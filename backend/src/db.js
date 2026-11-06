const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const config = require('./config');

fs.mkdirSync(path.dirname(config.databasePath), { recursive: true });

const db = new Database(config.databasePath);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

const migrationsDir = path.resolve(__dirname, '../migrations');
db.exec(`
  CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

for (const name of fs.readdirSync(migrationsDir).filter((file) => file.endsWith('.sql')).sort()) {
  const applied = db.prepare('SELECT 1 FROM schema_migrations WHERE name = ?').get(name);
  if (!applied) {
    const sql = fs.readFileSync(path.join(migrationsDir, name), 'utf8');
    db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(name);
    })();
  }
}

const permissionNames = [
  'documents.upload',
  'documents.read_own',
  'documents.read_any',
  'documents.delete_own',
  'documents.delete_any',
  'users.read_any'
];

const seedAuthorization = db.transaction(() => {
  const addRole = db.prepare('INSERT OR IGNORE INTO roles (name) VALUES (?)');
  for (const role of ['admin', 'manager', 'user']) addRole.run(role);

  const addPermission = db.prepare('INSERT OR IGNORE INTO permissions (name) VALUES (?)');
  for (const permission of permissionNames) addPermission.run(permission);

  const grant = db.prepare(`
    INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
    SELECT roles.id, permissions.id
    FROM roles, permissions
    WHERE roles.name = ? AND permissions.name = ?
  `);
  const grants = {
    admin: permissionNames,
    manager: ['documents.upload', 'documents.read_any', 'documents.delete_any'],
    user: ['documents.upload', 'documents.read_own', 'documents.delete_own']
  };
  for (const [role, permissions] of Object.entries(grants)) {
    for (const permission of permissions) grant.run(role, permission);
  }
});

seedAuthorization();

module.exports = db;
