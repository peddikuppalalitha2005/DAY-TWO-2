const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'snovasys-test-'));
process.env.DATABASE_PATH = path.join(dataDir, 'test.sqlite');
process.env.UPLOAD_DIR = path.join(dataDir, 'uploads');
process.env.CLIENT_ORIGIN = 'http://localhost:5173';

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
  const owner = await register('owner@example.com', 'Owner User');
  const other = await register('other@example.com', 'Other User');
  assert.deepEqual(owner.user.roles, ['user']);

  const form = new FormData();
  form.append('file', new Blob(['private document'], { type: 'text/plain' }), 'notes.txt');
  const uploaded = await request('/documents', { method: 'POST', token: owner.token, body: form });
  assert.equal(uploaded.status, 201);
  const { document } = await uploaded.json();

  const ownList = await request('/documents', { token: owner.token });
  assert.equal((await ownList.json()).documents.length, 1);
  const otherList = await request('/documents', { token: other.token });
  assert.equal((await otherList.json()).documents.length, 0);

  const deniedDownload = await request(`/documents/${document.id}/download`, { token: other.token });
  assert.equal(deniedDownload.status, 403);
  const deniedDelete = await request(`/documents/${document.id}`, { method: 'DELETE', token: other.token });
  assert.equal(deniedDelete.status, 403);

  const managerId = db.prepare('SELECT id FROM users WHERE email = ?').get('other@example.com').id;
  db.prepare(`
    INSERT INTO user_roles (user_id, role_id)
    SELECT ?, id FROM roles WHERE name = 'manager'
  `).run(managerId);
  db.prepare(`
    DELETE FROM user_roles WHERE user_id = ?
      AND role_id = (SELECT id FROM roles WHERE name = 'user')
  `).run(managerId);
  const managerLogin = await request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'other@example.com', password: 'a-secure-passphrase' }),
  });
  const manager = await managerLogin.json();
  const managerList = await request('/documents', { token: manager.token });
  assert.equal(managerList.status, 200);
  assert.equal((await managerList.json()).documents[0].owner_name, 'Owner User');
  const managerDownload = await request(`/documents/${document.id}/download`, { token: manager.token });
  assert.equal(managerDownload.status, 200);
  assert.equal(await managerDownload.text(), 'private document');
  const managerDelete = await request(`/documents/${document.id}`, { method: 'DELETE', token: manager.token });
  assert.equal(managerDelete.status, 204);

  const logout = await request('/auth/logout', { method: 'POST', token: owner.token });
  assert.equal(logout.status, 204);
  const revoked = await request('/auth/me', { token: owner.token });
  assert.equal(revoked.status, 401);
});
