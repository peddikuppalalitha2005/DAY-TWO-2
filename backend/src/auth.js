const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const db = require('./db');

const SESSION_DURATION_MS = 12 * 60 * 60 * 1000;

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function getUser(userId) {
  const user = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(userId);
  if (!user) return null;

  const roles = db.prepare(`
    SELECT roles.name
    FROM roles JOIN user_roles ON user_roles.role_id = roles.id
    WHERE user_roles.user_id = ?
  `).all(userId).map((row) => row.name);
  const permissions = db.prepare(`
    SELECT DISTINCT permissions.name
    FROM permissions
    JOIN role_permissions ON role_permissions.permission_id = permissions.id
    JOIN user_roles ON user_roles.role_id = role_permissions.role_id
    WHERE user_roles.user_id = ?
  `).all(userId).map((row) => row.name);

  return { ...user, roles, permissions };
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
  db.prepare(`
    INSERT INTO auth_sessions (id, user_id, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(crypto.randomUUID(), userId, hashToken(token), expiresAt);
  return token;
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function verifyPassword(password, passwordHash) {
  return bcrypt.compare(password, passwordHash);
}

function authenticate(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]+)$/);
  if (!match) return res.status(401).json({ error: 'Authentication required.' });

  const session = db.prepare(`
    SELECT user_id FROM auth_sessions
    WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
  `).get(hashToken(match[1]), new Date().toISOString());
  if (!session) return res.status(401).json({ error: 'Session is invalid or expired.' });

  const user = getUser(session.user_id);
  if (!user) return res.status(401).json({ error: 'Account no longer exists.' });
  req.user = user;
  req.sessionTokenHash = hashToken(match[1]);
  next();
}

function requireAnyPermission(...permissions) {
  return (req, res, next) => {
    if (!permissions.some((permission) => req.user.permissions.includes(permission))) {
      return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    }
    next();
  };
}

function audit(userId, action, entityType = null, entityId = null, details = null) {
  db.prepare(`
    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId || null, action, entityType, entityId, details ? JSON.stringify(details) : null);
}

module.exports = {
  authenticate,
  audit,
  createSession,
  getUser,
  hashPassword,
  requireAnyPermission,
  verifyPassword,
  hashToken
};
