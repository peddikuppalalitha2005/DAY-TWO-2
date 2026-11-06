const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const db = require('./db');
const config = require('./config');
const {
  authenticate,
  audit,
  createSession,
  getUser,
  hashPassword,
  hashToken,
  requireAnyPermission,
  verifyPassword
} = require('./auth');

fs.mkdirSync(config.uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, callback) => callback(null, config.uploadDir),
  filename: (_req, _file, callback) => callback(null, crypto.randomUUID())
});
const upload = multer({
  storage,
  limits: { fileSize: config.maxUploadBytes, files: 1 }
});

const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: config.clientOrigin }));
app.use(express.json({ limit: '1mb' }));

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (name.length < 1 || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      || email.length > 254 || password.length < 8 || password.length > 72
      || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Provide a name, valid email, and password (8–72 characters, 72-byte maximum).' });
    }
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    db.transaction(() => {
      db.prepare('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)')
        .run(userId, name, email, passwordHash);
      db.prepare(`
        INSERT INTO user_roles (user_id, role_id)
        SELECT ?, id FROM roles WHERE name = 'user'
      `).run(userId);
    })();
    const token = createSession(userId);
    audit(userId, 'auth.register', 'user', userId);
    return res.status(201).json({ token, user: getUser(userId) });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    return next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const row = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    if (!row || !(await verifyPassword(password, row.password_hash))) {
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }
    const token = createSession(row.id);
    audit(row.id, 'auth.login', 'user', row.id);
    return res.json({ token, user: getUser(row.id) });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  db.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ?')
    .run(new Date().toISOString(), req.sessionTokenHash);
  audit(req.user.id, 'auth.logout', 'user', req.user.id);
  res.status(204).end();
});

app.get('/api/auth/me', authenticate, (req, res) => res.json({ user: req.user }));

app.get('/api/dashboard', authenticate, (req, res) => {
  const canReadAll = req.user.permissions.includes('documents.read_any');
  const documentCount = canReadAll
    ? db.prepare('SELECT COUNT(*) AS count FROM documents').get().count
    : db.prepare('SELECT COUNT(*) AS count FROM documents WHERE owner_id = ?').get(req.user.id).count;
  const userCount = req.user.permissions.includes('users.read_any')
    ? db.prepare('SELECT COUNT(*) AS count FROM users').get().count
    : null;
  res.json({ documentCount, userCount });
});

app.get('/api/documents', authenticate, requireAnyPermission('documents.read_own', 'documents.read_any'), (req, res) => {
  const canReadAll = req.user.permissions.includes('documents.read_any');
  const documents = canReadAll
    ? db.prepare(`
      SELECT documents.id, documents.owner_id, documents.original_name, documents.mime_type,
             documents.size_bytes, documents.created_at, users.name AS owner_name
      FROM documents JOIN users ON users.id = documents.owner_id
      ORDER BY documents.created_at DESC
    `).all()
    : db.prepare(`
      SELECT id, owner_id, original_name, mime_type, size_bytes, created_at, NULL AS owner_name
      FROM documents WHERE owner_id = ? ORDER BY created_at DESC
    `).all(req.user.id);
  res.json({ documents });
});

app.post('/api/documents', authenticate, requireAnyPermission('documents.upload'), (req, res, next) => {
  upload.single('file')(req, res, (error) => {
    if (error) {
      if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: `File exceeds the ${config.maxUploadBytes}-byte upload limit.` });
      }
      if (error instanceof multer.MulterError) return res.status(400).json({ error: error.message });
      return next(error);
    }
    if (!req.file) return res.status(400).json({ error: 'Choose a file to upload.' });

    const id = crypto.randomUUID();
    try {
      db.prepare(`
        INSERT INTO documents (id, owner_id, storage_name, original_name, mime_type, size_bytes)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(id, req.user.id, req.file.filename, path.basename(req.file.originalname), req.file.mimetype, req.file.size);
      audit(req.user.id, 'document.upload', 'document', id);
      const document = db.prepare(`
        SELECT id, owner_id, original_name, mime_type, size_bytes, created_at, NULL AS owner_name
        FROM documents WHERE id = ?
      `).get(id);
      return res.status(201).json({ document });
    } catch (error) {
      fs.unlink(req.file.path, (unlinkError) => {
        if (unlinkError) console.error('Unable to remove a failed document upload:', unlinkError);
      });
      return next(error);
    }
  });
});

function findAccessibleDocument(req, res) {
  const document = db.prepare(`
    SELECT id, owner_id, storage_name, original_name, mime_type, size_bytes, created_at
    FROM documents WHERE id = ?
  `).get(req.params.id);
  if (!document) {
    res.status(404).json({ error: 'Document not found.' });
    return null;
  }
  if (document.owner_id !== req.user.id && !req.user.permissions.includes('documents.read_any')) {
    res.status(403).json({ error: 'You do not have access to this document.' });
    return null;
  }
  return document;
}

app.get('/api/documents/:id/download', authenticate, requireAnyPermission('documents.read_own', 'documents.read_any'), (req, res, next) => {
  const document = findAccessibleDocument(req, res);
  if (!document) return;
  const filePath = path.join(config.uploadDir, document.storage_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Stored document file is missing.' });
  audit(req.user.id, 'document.download', 'document', document.id);
  res.download(filePath, document.original_name, (error) => {
    if (error && !res.headersSent) next(error);
  });
});

app.delete('/api/documents/:id', authenticate, requireAnyPermission('documents.delete_own', 'documents.delete_any'), (req, res, next) => {
  const document = findAccessibleDocument(req, res);
  if (!document) return;
  const canDeleteAny = req.user.permissions.includes('documents.delete_any');
  if (document.owner_id !== req.user.id && !canDeleteAny) {
    return res.status(403).json({ error: 'You do not have access to delete this document.' });
  }

  const filePath = path.join(config.uploadDir, document.storage_name);
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    db.prepare('DELETE FROM documents WHERE id = ?').run(document.id);
    audit(req.user.id, 'document.delete', 'document', document.id);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(config.frontendDist));
  app.get('*path', (_req, res) => res.sendFile(path.join(config.frontendDist, 'index.html')));
}

app.use((error, _req, res, _next) => {
  if (res.headersSent) return;
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Request body must contain valid JSON.' });
  }
  if (error.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body is too large.' });
  }
  console.error(error);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

module.exports = app;
