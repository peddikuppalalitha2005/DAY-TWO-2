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

const allowedFileTypes = {
  '.pdf': { mimeType: 'application/pdf', matches: (file) => file.subarray(0, 5).toString('ascii') === '%PDF-' },
  '.txt': {
    mimeType: 'text/plain',
    matches: (file) => !file.includes(0) && Buffer.from(file.toString('utf8'), 'utf8').equals(file)
  },
  '.png': { mimeType: 'image/png', matches: (file) => file.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
  '.jpg': { mimeType: 'image/jpeg', matches: (file) => file.length >= 3 && file[0] === 255 && file[1] === 216 && file[2] === 255 },
  '.jpeg': { mimeType: 'image/jpeg', matches: (file) => file.length >= 3 && file[0] === 255 && file[1] === 216 && file[2] === 255 }
};

const storage = multer.diskStorage({
  destination: (_req, _file, callback) => callback(null, config.uploadDir),
  filename: (_req, _file, callback) => callback(null, crypto.randomUUID())
});
const upload = multer({
  storage,
  limits: { fileSize: config.maxUploadBytes, files: 1 }
});
const failedLoginAttempts = new Map();
const loginWindowMs = 15 * 60 * 1000;
const maxLoginAttempts = 10;

function rateLimitLogin(req, res, next) {
  const key = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const current = failedLoginAttempts.get(key);
  if (current && current.expiresAt <= now) failedLoginAttempts.delete(key);
  const attempts = failedLoginAttempts.get(key);
  if (attempts && attempts.count >= maxLoginAttempts) {
    return res.status(429).json({ error: 'Too many unsuccessful sign-in attempts. Try again later.' });
  }

  res.once('finish', () => {
    if (res.statusCode === 401) {
      const previous = failedLoginAttempts.get(key);
      const entry = previous && previous.expiresAt > now
        ? previous
        : { count: 0, expiresAt: now + loginWindowMs };
      entry.count += 1;
      failedLoginAttempts.set(key, entry);
    } else if (res.statusCode < 400) {
      failedLoginAttempts.delete(key);
    }

    if (failedLoginAttempts.size > 10000) {
      for (const [address, entry] of failedLoginAttempts) {
        if (entry.expiresAt <= Date.now()) failedLoginAttempts.delete(address);
      }
    }
  });
  next();
}

const app = express();
app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });
  next();
});
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

app.post('/api/auth/login', rateLimitLogin, async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (email.length > 254 || Buffer.byteLength(password, 'utf8') > 72) {
      audit(null, 'auth.login_failed', 'user');
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }
    const row = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    if (!row || !(await verifyPassword(password, row.password_hash))) {
      audit(row?.id || null, 'auth.login_failed', 'user', row?.id || null);
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

app.get('/api/admin/users', authenticate, requireAnyPermission('users.read_any'), (_req, res) => {
  const users = db.prepare(`
    SELECT users.id, users.name, users.email, users.created_at,
           GROUP_CONCAT(roles.name, ',') AS roles
    FROM users
    LEFT JOIN user_roles ON user_roles.user_id = users.id
    LEFT JOIN roles ON roles.id = user_roles.role_id
    GROUP BY users.id
    ORDER BY users.created_at DESC
  `).all().map((user) => ({ ...user, roles: user.roles ? user.roles.split(',') : [] }));
  res.json({ users });
});

app.put('/api/admin/users/:id/role', authenticate, requireAnyPermission('users.manage_roles'), (req, res, next) => {
  if (!cryptoValidateId(req.params.id)) return res.status(400).json({ error: 'User ID must be a UUID.' });
  const role = req.body && typeof req.body.role === 'string' ? req.body.role : '';
  if (!['admin', 'manager', 'user'].includes(role)) {
    return res.status(400).json({ error: 'Role must be admin, manager, or user.' });
  }
  if (!db.prepare('SELECT 1 FROM users WHERE id = ?').get(req.params.id)) {
    return res.status(404).json({ error: 'User not found.' });
  }

  try {
    db.transaction(() => {
      const currentRoles = db.prepare(`
        SELECT roles.name FROM roles
        JOIN user_roles ON user_roles.role_id = roles.id
        WHERE user_roles.user_id = ?
      `).all(req.params.id).map((row) => row.name);
      if (currentRoles.includes('admin') && role !== 'admin'
        && db.prepare(`
          SELECT COUNT(*) AS count FROM user_roles
          JOIN roles ON roles.id = user_roles.role_id
          WHERE roles.name = 'admin'
        `).get().count <= 1) {
        const error = new Error('The last administrator cannot be demoted.');
        error.status = 409;
        throw error;
      }

      db.prepare('DELETE FROM user_roles WHERE user_id = ?').run(req.params.id);
      db.prepare(`
        INSERT INTO user_roles (user_id, role_id)
        SELECT ?, id FROM roles WHERE name = ?
      `).run(req.params.id, role);
      audit(req.user.id, 'admin.user_role_changed', 'user', req.params.id, { role });
    })();
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    return next(error);
  }
  return res.json({ user: getUser(req.params.id) });
});

app.get('/api/admin/audit-logs', authenticate, requireAnyPermission('audit.read_any'), (req, res) => {
  const limit = req.query.limit === undefined ? 50 : Number(req.query.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    return res.status(400).json({ error: 'Limit must be an integer between 1 and 100.' });
  }
  const logs = db.prepare(`
    SELECT audit_logs.id, audit_logs.user_id, users.email AS user_email,
           audit_logs.action, audit_logs.entity_type, audit_logs.entity_id,
           audit_logs.details, audit_logs.created_at
    FROM audit_logs LEFT JOIN users ON users.id = audit_logs.user_id
    ORDER BY audit_logs.id DESC LIMIT ?
  `).all(limit);
  return res.json({ logs });
});

app.put('/api/admin/audit-logs/:id', authenticate, requireAnyPermission('audit.read_any'), (_req, res) => {
  res.status(405).json({ error: 'Audit logs are append-only.' });
});
app.delete('/api/admin/audit-logs/:id', authenticate, requireAnyPermission('audit.read_any'), (_req, res) => {
  res.status(405).json({ error: 'Audit logs are append-only.' });
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
  upload.single('file')(req, res, async (error) => {
    if (error) {
      if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: `File exceeds the ${config.maxUploadBytes}-byte upload limit.` });
      }
      if (error instanceof multer.MulterError) return res.status(400).json({ error: error.message });
      return next(error);
    }
    if (!req.file) return res.status(400).json({ error: 'Choose a file to upload.' });

    const extension = path.extname(req.file.originalname).toLowerCase();
    const fileType = allowedFileTypes[extension];
    try {
      const actualType = fileType && await fs.promises.readFile(req.file.path);
      if (!fileType || req.file.mimetype.split(';', 1)[0].toLowerCase() !== fileType.mimeType
        || !fileType.matches(actualType)) {
        await fs.promises.unlink(req.file.path);
        return res.status(415).json({ error: 'Unsupported file type. Upload a valid PDF, TXT, PNG, or JPEG file.' });
      }
    } catch (validationError) {
      if (req.file && fs.existsSync(req.file.path)) {
        try {
          await fs.promises.unlink(req.file.path);
        } catch (cleanupError) {
          return next(cleanupError);
        }
      }
      return next(validationError);
    }

    const id = crypto.randomUUID();
    const originalName = Array.from(path.posix.basename(req.file.originalname.replace(/\\/g, '/'))
      .replace(/[\u0000-\u001f\u007f]/g, '').trim()).slice(0, 255).join('');
    try {
      db.transaction(() => {
        db.prepare(`
          INSERT INTO documents (id, owner_id, storage_name, original_name, mime_type, size_bytes)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(id, req.user.id, req.file.filename, originalName || 'document', fileType.mimeType, req.file.size);
        audit(req.user.id, 'document.upload', 'document', id);
      })();
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

function cryptoValidateId(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function findDocument(req, res) {
  if (!cryptoValidateId(req.params.id)) {
    res.status(400).json({ error: 'Document ID must be a UUID.' });
    return null;
  }
  const document = db.prepare(`
    SELECT id, owner_id, storage_name, original_name, mime_type, size_bytes, created_at
    FROM documents WHERE id = ?
  `).get(req.params.id);
  if (!document) {
    res.status(404).json({ error: 'Document not found.' });
    return null;
  }
  return document;
}

app.get('/api/documents/:id/download', authenticate, requireAnyPermission('documents.read_own', 'documents.read_any'), async (req, res, next) => {
  const document = findDocument(req, res);
  if (!document) return;
  if (document.owner_id !== req.user.id && !req.user.permissions.includes('documents.read_any')) {
    return res.status(403).json({ error: 'You do not have access to this document.' });
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(document.storage_name)) {
    return res.status(404).json({ error: 'Stored document is unavailable.' });
  }
  const uploadRoot = path.resolve(config.uploadDir);
  const filePath = path.resolve(uploadRoot, document.storage_name);
  if (path.dirname(filePath) !== uploadRoot) return res.status(404).json({ error: 'Stored document is unavailable.' });
  let fileInfo;
  try {
    fileInfo = await fs.promises.lstat(filePath);
  } catch (error) {
    if (error.code === 'ENOENT') return res.status(404).json({ error: 'Stored document file is missing.' });
    return next(error);
  }
  if (!fileInfo.isFile()) return res.status(404).json({ error: 'Stored document is unavailable.' });
  audit(req.user.id, 'document.download', 'document', document.id);
  res.download(filePath, document.original_name, (error) => {
    if (error && !res.headersSent) next(error);
  });
});

app.delete('/api/documents/:id', authenticate, requireAnyPermission('documents.delete_own', 'documents.delete_any'), async (req, res, next) => {
  const document = findDocument(req, res);
  if (!document) return;
  const canDeleteAny = req.user.permissions.includes('documents.delete_any');
  if (document.owner_id !== req.user.id && !canDeleteAny) {
    return res.status(403).json({ error: 'You do not have access to delete this document.' });
  }

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(document.storage_name)) {
    return res.status(404).json({ error: 'Stored document is unavailable.' });
  }
  const uploadRoot = path.resolve(config.uploadDir);
  const filePath = path.resolve(uploadRoot, document.storage_name);
  if (path.dirname(filePath) !== uploadRoot) {
    return res.status(404).json({ error: 'Stored document is unavailable.' });
  }
  try {
    const fileInfo = await fs.promises.lstat(filePath).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (fileInfo && !fileInfo.isFile()) {
      return res.status(404).json({ error: 'Stored document is unavailable.' });
    }
    if (fileInfo) await fs.promises.unlink(filePath);
    db.transaction(() => {
      db.prepare('DELETE FROM documents WHERE id = ?').run(document.id);
      audit(req.user.id, 'document.delete', 'document', document.id);
    })();
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
  if (error.status === 413) {
    return res.status(413).json({ error: 'Request body is too large.' });
  }
  console.error(error);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

module.exports = app;
