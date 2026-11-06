# API reference

Base URL: `/api`. JSON request bodies use `Content-Type: application/json`. Authenticated requests use `Authorization: Bearer <session-token>`. Tokens expire after 12 hours and are revoked by logout. Uploaded files use `multipart/form-data` with a single field named `file`.

## Authentication

| Method | Route | Access | Request | Success |
|---|---|---|---|---|
| `GET` | `/health` | Public | — | `200 {"status":"ok"}` |
| `POST` | `/auth/register` | Public | `{"name":"Alex","email":"alex@example.com","password":"..."}` | `201 {"token":"…","user":{…}}` |
| `POST` | `/auth/login` | Public, throttled | `{"email":"alex@example.com","password":"..."}` | `200 {"token":"…","user":{…}}` |
| `POST` | `/auth/logout` | Authenticated | — | `204` |
| `GET` | `/auth/me` | Authenticated | — | `200 {"user":{…}}` |
| `GET` | `/dashboard` | Authenticated | — | `200 {"documentCount":0,"userCount":null}` |

Registration requires a trimmed name (1–100 characters), valid email (at most 254 characters), and password of 8–72 UTF-8 bytes. Registration never assigns an elevated role. Login failures return a generic `401`; more than 10 failed attempts from one connecting peer IP in 15 minutes returns `429`. Behind a reverse proxy, the peer IP may be the proxy address.

## Documents

| Method | Route | Access | Request | Success |
|---|---|---|---|---|
| `GET` | `/documents` | `documents.read_own` or `documents.read_any` | — | `200 {"documents":[…]}` |
| `POST` | `/documents` | `documents.upload` | Multipart field `file` | `201 {"document":{…}}` |
| `GET` | `/documents/:id/download` | Read permission and owner or `documents.read_any` | UUID in path | File download |
| `DELETE` | `/documents/:id` | `documents.delete_own` or `documents.delete_any`, and owner or delete-any permission | UUID in path | `204` |

Allowed uploads are PDF (header checked), UTF-8 plain text, PNG (signature checked), and JPEG (start marker checked). Extension, declared MIME type, and basic content signature/encoding are checked; files are not fully parsed or malware-scanned. The configured byte limit defaults to 20 MiB. A malformed document UUID returns `400`; a missing document returns `404`; another user's document returns `403`.

## Administration

All routes below require the corresponding admin permission; regular users and managers are denied.

| Method | Route | Permission | Request / response |
|---|---|---|---|
| `GET` | `/admin/users` | `users.read_any` | `200 {"users":[…]}`; password hashes are never returned. |
| `PUT` | `/admin/users/:id/role` | `users.manage_roles` | `{"role":"admin\|manager\|user"}`; returns the safe public user. |
| `GET` | `/admin/audit-logs?limit=50` | `audit.read_any` | `200 {"logs":[…]}`; limit must be 1–100. |
| `PUT` / `DELETE` | `/admin/audit-logs/:id` | `audit.read_any` | Always `405`; audit records are append-only. |

The final administrator cannot be demoted (`409`). Successful role changes are themselves audited.

## Error shape

API errors use `{"error":"description"}`. Common status codes are `400` invalid input, `401` missing/invalid session, `403` forbidden, `404` missing resource, `405` immutable audit record, `409` duplicate account or last-admin protection, `413` body/file too large, `415` unsupported or mismatched file type, and `429` login throttling.

## Data model

SQLite migrations create `users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `documents`, `audit_logs`, and `auth_sessions`. Foreign keys are enabled. Migration status is tracked in `schema_migrations`; the backend applies sorted pending `.sql` migrations on startup.
