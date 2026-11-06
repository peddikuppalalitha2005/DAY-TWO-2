const crypto = require('node:crypto');
const db = require('../src/db');
const { hashPassword } = require('../src/auth');

async function seedDemoUsers() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Demo accounts cannot be seeded in production.');
  }

  const accounts = [
    { role: 'admin', name: 'Demo Admin', email: process.env.DEMO_ADMIN_EMAIL, password: process.env.DEMO_ADMIN_PASSWORD },
    { role: 'manager', name: 'Demo Manager', email: process.env.DEMO_MANAGER_EMAIL, password: process.env.DEMO_MANAGER_PASSWORD },
    { role: 'user', name: 'Demo User', email: process.env.DEMO_USER_EMAIL, password: process.env.DEMO_USER_PASSWORD }
  ];

  for (const account of accounts) {
    const prefix = `DEMO_${account.role.toUpperCase()}`;
    if (!account.email || !account.password || Buffer.byteLength(account.password, 'utf8') < 12
      || Buffer.byteLength(account.password, 'utf8') > 72
      || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(account.email)) {
      throw new Error(`Set a valid ${prefix}_EMAIL and a 12–72 byte ${prefix}_PASSWORD.`);
    }
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(account.email)) {
      throw new Error(`Demo account ${account.email} already exists. The seed script will not change existing accounts.`);
    }
  }

  const prepared = await Promise.all(accounts.map(async (account) => ({
    ...account,
    id: crypto.randomUUID(),
    passwordHash: await hashPassword(account.password)
  })));

  db.transaction(() => {
    for (const account of prepared) {
      db.prepare('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)')
        .run(account.id, account.name, account.email, account.passwordHash);
      db.prepare(`
        INSERT INTO user_roles (user_id, role_id)
        SELECT ?, id FROM roles WHERE name = ?
      `).run(account.id, account.role);
    }
  })();

  console.log('Demo accounts created:');
  for (const account of prepared) console.log(`- ${account.role}: ${account.email}`);
  console.log('Passwords were read from environment variables and are not printed.');
}

seedDemoUsers()
  .catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  })
  .finally(() => db.close());
