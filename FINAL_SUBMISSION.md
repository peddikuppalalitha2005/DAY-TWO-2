# Final project write-up

## Project

Snovasys is a role-aware document workspace with a React/TypeScript frontend, Express API, SQLite migrations, and persistent file storage. Admin, manager, and regular-user dashboards reflect server-issued roles and permissions.

## Delivered

- Account registration/login/logout, bcrypt password hashing, hashed and revocable 12-hour sessions.
- Role/permission tables and server-side authorization for document operations.
- Document upload, listing, download, and deletion with owner/all-document permission checks.
- PDF/TXT/PNG/JPEG allowlist, size cap, signature/content checks, generated storage UUIDs, path containment, and sanitized display names.
- Append-only audit records and SQLite triggers, admin-only audit reading, admin user/role endpoints, and last-admin protection.
- Backend integration tests, API documentation, threat model, prompt summary, demo account seed script, and five-minute recording plan.

## Local verification

Run `npm test` and `npm run build`. The backend tests use temporary test data and cover the required security cases. Create non-production demonstration accounts only by setting the `DEMO_*` environment values and running `npm run seed:demo -w backend`.

## Deployment

The Docker Compose configuration builds one app container and persists its data volume. Set the public `CLIENT_ORIGIN`, terminate HTTPS at the hosting platform/reverse proxy, and back up the persistent volume. The local-disk/SQLite design is intended for one instance.

## Submission checklist

- [x] Source repository and `day-1` branch
- [x] Database migrations and role/permission setup
- [x] Backend security controls and cross-user tests
- [x] Audit logging and append-only enforcement
- [x] `README.md`, `API.md`, `THREATS.md`, and `PROMPTS.md`
- [x] Demo account seed script and non-production credential instructions
- [x] Five-minute demo recording script in `DEMO.md`
- [ ] Record and attach the actual five-minute demo video
- [ ] Deploy the container to the final hosting account and verify its public URL

The video and public deployment must be completed in the submitter's recording/hosting accounts; this repository contains instructions, not a fabricated recording or deployment claim.
