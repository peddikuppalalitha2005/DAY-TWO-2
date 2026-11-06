# Snovasys

A role-aware document management starter with a React frontend, Express API, SQLite database, and persistent local document storage.

## Requirements

- Node.js 24+
- npm 10+
- Docker (optional, for the container deployment)

## Local development

1. Copy `.env.example` to `.env` and adjust values if needed.
2. Install dependencies with `npm install`.
3. Start the API and frontend with `npm run dev`.
4. Open <http://localhost:5173>. The API listens on <http://localhost:4000>.

The database and uploaded files are created on first run. SQL migrations run automatically; public registration creates regular-user accounts only. To create the first administrator, register an account and promote it directly in SQLite:

```sql
INSERT INTO user_roles (user_id, role_id)
SELECT 'USER_ID', id FROM roles WHERE name = 'admin';
DELETE FROM user_roles
WHERE user_id = 'USER_ID'
  AND role_id = (SELECT id FROM roles WHERE name = 'user');
```

Find the account ID with `SELECT id, email FROM users;`. Do this only through a trusted, direct database connection.

## Features

- Registration, login, logout, bcrypt password hashing, and revocable 12-hour bearer sessions.
- Admin, manager, and regular-user roles with permissions enforced by the API.
- Document upload, listing, download, and deletion. Regular users can access their own documents; managers and admins can access all documents.
- Audit events for authentication and document activity.
- A dashboard tailored to the signed-in user's role.

## Deployment

Build and run the single-container deployment with `docker compose up --build -d`, then open <http://localhost:4000>. SQLite data and uploads persist in the `app-data` Docker volume. Configure `CLIENT_ORIGIN` to the public origin when deploying behind a domain or reverse proxy, and use HTTPS in production.

The frontend is served by the API in production. For a separate frontend/API deployment, set `VITE_API_URL` at frontend build time and set the API's `CLIENT_ORIGIN` to the frontend origin.

## API overview

- `POST /api/auth/register`, `/api/auth/login`, `/api/auth/logout`
- `GET /api/auth/me`, `/api/dashboard`
- `GET /api/documents`, `POST /api/documents`
- `GET /api/documents/:id/download`, `DELETE /api/documents/:id`

All document and dashboard routes require `Authorization: Bearer <token>`. Uploads are limited to 20 MiB by default; configure `MAX_UPLOAD_BYTES` to change the limit.

## GitHub

The application is ready to initialize and publish as a public repository. Create an empty public repository in your GitHub account, then add it as the `origin` remote and push this workspace.
