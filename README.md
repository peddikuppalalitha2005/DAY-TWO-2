# Snovasys

A role-aware document management application built with React, Express, SQLite, and local persistent file storage.

## Requirements and local setup

- Node.js 24+ and npm 10+
- Git for source control
- Docker only if using the container deployment

```powershell
Copy-Item .env.example .env
npm install
npm run dev
```

Open <http://localhost:5173>. The API listens on <http://localhost:4000>; check `GET /api/health`.
The SQLite database and uploads are created under `data/` on first run. SQL migrations are applied automatically.

## Roles, demo accounts, and test credentials

Public registration always creates a regular `user`. It never accepts a requested role. For local demos only, set six distinct environment variables in `.env`, then run `npm run seed:demo -w backend`. The script creates one admin, manager, and regular user, hashes their passwords, prints account email addresses but not passwords, refuses to overwrite accounts, and refuses to run with `NODE_ENV=production`. Set passwords to unique values of at least 12 characters; do not use demo credentials in production.

The automated integration test creates its own accounts and isolated temporary SQLite database. Example test-only credentials are generated in `backend/test/app.test.js`; those accounts do not exist in the application database.

## Security behavior

- bcrypt password hashes; random 256-bit bearer tokens stored as SHA-256 hashes; revocable 12-hour sessions.
- Backend authorization on every document list, upload, download, and delete operation. Users can access their own files; managers and admins can access all documents.
- Strict upload allowlist: PDF-header, UTF-8 plain text, PNG-signature, and JPEG-signature files; the declared MIME type, file extension, and basic signature/content check must agree. This is file-type screening, not malware scanning or full document parsing. Size is capped by `MAX_UPLOAD_BYTES` (20 MiB by default).
- Server-generated UUID storage names, sanitized download names, UUID validation, upload-directory containment checks, and symlink rejection for document operations.
- Append-only audit records for registration, successful/failed login, logout, upload, download, deletion, and admin role changes. Admins can read audit history; the API does not expose a mutation route, and SQLite triggers reject update/delete operations.
- Admin-only user listing and role assignment; the last administrator cannot be demoted.
- Login attempts are limited to 10 unsuccessful attempts per connecting peer IP in a 15-minute window (behind a reverse proxy, this may be the proxy IP).
- See [THREATS.md](./THREATS.md) for assumptions, mitigations, and limitations.

## Tests

```powershell
npm test
npm run build
```

Backend integration tests exercise registration/login/logout, invalid input, upload type and size rejection, admin/manager/user authorization, cross-user document isolation, download and deletion, audit log immutability, and login throttling.

## API and database

See [API.md](./API.md) for routes, authorization, request shapes, and responses. The initial SQLite schema is in `backend/migrations/001_initial.sql`; migration `002_immutable_audit_logs.sql` adds append-only audit triggers. The backend applies pending migrations at startup.

## Deployment

### Render

The root `render.yaml` defines a Docker web service, `/api/health` health check, and a 1 GiB persistent disk mounted at `/app/data` for SQLite and uploads. The persistent disk requires a paid Render web-service plan. To deploy, push the repository to GitHub, sign in at <https://dashboard.render.com>, choose **New → Blueprint**, connect `peddikuppalalitha2005/DAY-TWO-2`, select the `main` branch, review the service and disk plan/cost in the Blueprint preview, and choose **Deploy Blueprint**. After deploy, confirm the `snovasys-day-two.onrender.com` URL is available and that `/api/health` returns `{"status":"ok"}`. The service runs the backend and serves the production frontend from the same origin. Do not run the demo seeder in production or expose the SQLite file.

### Docker Compose

Alternatively, build and run with `docker compose up --build -d`, then open <http://localhost:4000>. Persistent SQLite data and uploads use the `app-data` Docker volume. Configure `CLIENT_ORIGIN` for your deployed frontend origin. Put the app behind HTTPS in production.

For a separate frontend/API deployment, set `VITE_API_URL` at frontend build time and `CLIENT_ORIGIN` on the API. SQLite/local disk storage is intended for a single-instance deployment; use private object storage and a server database for horizontally scaled deployments.

## Submission materials

- [API.md](./API.md) — API documentation
- [THREATS.md](./THREATS.md) — threat model and residual risks
- [PROMPTS.md](./PROMPTS.md) — summarized project prompt log
- [FINAL_SUBMISSION.md](./FINAL_SUBMISSION.md) — project write-up and checklist
- [DEMO.md](./DEMO.md) — timed five-minute demo recording script

The demo script is not a recorded video. Record the walkthrough separately in your preferred screen recorder.
