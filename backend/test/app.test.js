const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'snovasys-test-'));
process.env.DATABASE_PATH = path.join(dataDir, 'test.sqlite');
process.env.UPLOAD_DIR = path.join(dataDir, 'uploads');
process.env.CLIENT_ORIGIN = 'http://localhost:5173';
process.env.MAX_UPLOAD_BYTES = '1024';

const db = require('../src/db');
const app = require('../src/app');
let server;
let baseUrl;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}/api`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function request(route, { token, ...options } = {}) {
  const headers = new Headers(options.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return fetch(`${baseUrl}${route}`, { ...options, headers });
}

async function register(email, name) {
  const response = await request('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password: 'a-secure-passphrase' }),
  });
  assert.equal(response.status, 201);
  return response.json();
}

async function login(email, password = 'a-secure-passphrase') {
  const response = await request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return { response, body: await response.json() };
}

async function uploadDocument(token, name, contents, type) {
  const form = new FormData();
  form.append('file', new Blob([contents], { type }), name);
  return request('/documents', { method: 'POST', token, body: form });
}

test('authentication, role authorization, document ownership, and session revocation', async () => {
  const health = await request('/health');
  assert.deepEqual(await health.json(), { status: 'ok' });

  const missingRegistrationData = await request('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(missingRegistrationData.status, 400);
  const malformedJson = await request('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{',
  });
  assert.equal(malformedJson.status, 400);
  assert.equal(malformedJson.headers.get('x-content-type-options'), 'nosniff');
  assert.equal((await request('/documents')).status, 401);

  const rejectedLogin = await login('missing@example.com');
  assert.equal(rejectedLogin.response.status, 401);

  const owner = await register('owner@example.com', 'Owner User');
  const other = await register('other@example.com', 'Other User');
  assert.deepEqual(owner.user.roles, ['user']);

  assert.equal((await request('/admin/users', { token: owner.token })).status, 403);
  assert.equal((await request('/admin/audit-logs', { token: owner.token })).status, 403);
  assert.equal((await request('/admin/audit-logs/1', { method: 'DELETE', token: owner.token })).status, 403);
  assert.equal((await request(`/admin/users/${owner.user.id}/role`, {
    method: 'PUT',
    token: owner.token,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'admin' }),
  })).status, 403);

  const invalidType = await uploadDocument(owner.token, 'fake.pdf', 'not a pdf file', 'application/pdf');
  assert.equal(invalidType.status, 415);
  const unsupportedType = await uploadDocument(owner.token, 'payload.exe', 'not allowed', 'application/x-msdownload');
  assert.equal(unsupportedType.status, 415);
  const oversized = await uploadDocument(owner.token, 'large.txt', 'x'.repeat(1025), 'text/plain');
  assert.equal(oversized.status, 413);
  const forbiddenUpload = await uploadDocument(null, 'notes.txt', 'private document', 'text/plain');
  assert.equal(forbiddenUpload.status, 401);

  const uploaded = await uploadDocument(owner.token, 'notes.txt', 'private document', 'text/plain');
  assert.equal(uploaded.status, 201);
  const { document } = await uploaded.json();
  assert.equal(document.original_name, 'notes.txt');

  const ownList = await request('/documents', { token: owner.token });
  assert.equal((await ownList.json()).documents.length, 1);
  const ownDownload = await request(`/documents/${document.id}/download`, { token: owner.token });
  assert.equal(ownDownload.status, 200);
  assert.equal(await ownDownload.text(), 'private document');
  const otherList = await request('/documents', { token: other.token });
  assert.equal((await otherList.json()).documents.length, 0);

  assert.equal((await request(`/documents/${document.id}/download`)).status, 401);
  const deniedDownload = await request(`/documents/${document.id}/download`, { token: other.token });
  assert.equal(deniedDownload.status, 403);
  const deniedDelete = await request(`/documents/${document.id}`, { method: 'DELETE', token: other.token });
  assert.equal(deniedDelete.status, 403);
  assert.equal((await request('/documents/not-a-uuid/download', { token: owner.token })).status, 400);
  assert.equal((await request('/documents/not-a-uuid', { method: 'DELETE', token: owner.token })).status, 400);

  const ownerDocument = db.prepare('SELECT storage_name FROM documents WHERE id = ?').get(document.id);
  assert.match(ownerDocument.storage_name, /^[0-9a-f-]{36}$/i);
  db.prepare('UPDATE documents SET storage_name = ? WHERE id = ?').run('../../outside.txt', document.id);
  assert.equal((await request(`/documents/${document.id}/download`, { token: owner.token })).status, 404);
  assert.equal((await request(`/documents/${document.id}`, { method: 'DELETE', token: owner.token })).status, 404);
  db.prepare('UPDATE documents SET storage_name = ? WHERE id = ?').run(ownerDocument.storage_name, document.id);
  const auditCountBeforeTamper = db.prepare('SELECT COUNT(*) AS count FROM audit_logs').get().count;
  assert.throws(() => db.prepare('UPDATE audit_logs SET action = ? WHERE id = 1').run('tampered'), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM audit_logs WHERE id = 1').run(), /append-only/);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM audit_logs').get().count, auditCountBeforeTamper);

  const managerId = db.prepare('SELECT id FROM users WHERE email = ?').get('other@example.com').id;
  db.prepare(`
    INSERT INTO user_roles (user_id, role_id)
    SELECT ?, id FROM roles WHERE name = 'manager'
  `).run(managerId);
  db.prepare(`
    DELETE FROM user_roles WHERE user_id = ?
      AND role_id = (SELECT id FROM roles WHERE name = 'user')
  `).run(managerId);
  const { response: managerLoginResponse, body: manager } = await login('other@example.com');
  assert.equal(managerLoginResponse.status, 200);
  const managerList = await request('/documents', { token: manager.token });
  assert.equal(managerList.status, 200);
  assert.equal((await managerList.json()).documents[0].owner_name, 'Owner User');
  const managerDownload = await request(`/documents/${document.id}/download`, { token: manager.token });
  assert.equal(managerDownload.status, 200);
  assert.equal(await managerDownload.text(), 'private document');
  const managerDelete = await request(`/documents/${document.id}`, { method: 'DELETE', token: manager.token });
  assert.equal(managerDelete.status, 204);
  const userOwnedResponse = await uploadDocument(owner.token, '..\\..\\user-owned.txt', 'owner-only cleanup test', 'text/plain');
  assert.equal(userOwnedResponse.status, 201);
  const { document: userOwnedDocument } = await userOwnedResponse.json();
  assert.equal(userOwnedDocument.original_name, 'user-owned.txt');
  assert.equal((await request(`/documents/${userOwnedDocument.id}`, { method: 'DELETE', token: owner.token })).status, 204);
  const adminDocumentResponse = await uploadDocument(owner.token, 'admin.txt', 'admin-only cleanup test', 'text/plain');
  assert.equal(adminDocumentResponse.status, 201);
  const { document: adminDocument } = await adminDocumentResponse.json();

  const ownerId = db.prepare('SELECT id FROM users WHERE email = ?').get('owner@example.com').id;
  db.prepare(`
    INSERT INTO user_roles (user_id, role_id)
    SELECT ?, id FROM roles WHERE name = 'admin'
  `).run(ownerId);
  db.prepare(`
    DELETE FROM user_roles WHERE user_id = ?
      AND role_id = (SELECT id FROM roles WHERE name = 'user')
  `).run(ownerId);
  const logout = await request('/auth/logout', { method: 'POST', token: owner.token });
  assert.equal(logout.status, 204);
  const revoked = await request('/auth/me', { token: owner.token });
  assert.equal(revoked.status, 401);

  const { body: admin } = await login('owner@example.com');
  assert.ok(admin.user.permissions.includes('audit.read_any'));
  assert.equal((await request('/admin/users', { token: admin.token })).status, 200);

  const auditResponse = await request('/admin/audit-logs?limit=100', { token: admin.token });
  assert.equal(auditResponse.status, 200);
  const { logs } = await auditResponse.json();
  const actions = logs.map((entry) => entry.action);
  for (const action of ['auth.register', 'auth.login', 'auth.login_failed', 'auth.logout', 'document.upload', 'document.download']) {
    assert.ok(actions.includes(action), `audit log should contain ${action}`);
  }
  assert.equal((await request('/admin/audit-logs?limit=101', { token: admin.token })).status, 400);
  assert.equal((await request('/admin/users/not-a-uuid/role', {
    method: 'PUT',
    token: admin.token,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'admin' }),
  })).status, 400);
  assert.equal((await request(`/admin/users/${managerId}/role`, {
    method: 'PUT',
    token: admin.token,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'root' }),
  })).status, 400);
  assert.equal((await request('/admin/audit-logs/1', { method: 'PUT', token: admin.token, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'tampered' }) })).status, 405);
  assert.equal((await request('/admin/audit-logs/1', { method: 'DELETE', token: admin.token })).status, 405);

  const roleChange = await request(`/admin/users/${managerId}/role`, {
    method: 'PUT',
    token: admin.token,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'user' }),
  });
  assert.equal(roleChange.status, 200);
  assert.deepEqual((await roleChange.json()).user.roles, ['user']);
  assert.equal((await request(`/admin/users/${ownerId}/role`, {
    method: 'PUT',
    token: admin.token,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'user' }),
  })).status, 409);

  const adminDelete = await request(`/documents/${adminDocument.id}`, { method: 'DELETE', token: admin.token });
  assert.equal(adminDelete.status, 204);
  assert.ok(db.prepare('SELECT 1 FROM audit_logs WHERE action = ?').get('document.delete'));
  assert.ok(db.prepare('SELECT 1 FROM audit_logs WHERE action = ?').get('admin.user_role_changed'));

  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.equal((await login('unknown@example.com')).response.status, 401);
  }
  assert.equal((await login('unknown@example.com')).response.status, 429);

});
