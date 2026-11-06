# Threat model and security notes

## Scope and assets

The application protects account credentials, bearer sessions, document contents and metadata, role assignments, and audit history. The security boundary is the Express API: the React UI is not trusted to enforce access control.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Broken object-level authorization (IDOR/BOLA) | Each document operation checks its permission and verifies ownership or the explicit `*_any` permission on the server. IDs must be UUIDs; modifying a URL does not grant access. |
| Unauthorized upload, download, list, or delete | Each document route requires a bearer session and a relevant permission. Managers/admins receive only the documented all-document grants. |
| Malicious or oversized upload | Multer caps bytes and file count before storage. Only PDF, UTF-8 text, PNG, and JPEG are accepted; extension, declared MIME, and basic content signature/encoding must agree. Rejected temporary files are removed. |
| Path traversal / unsafe filenames | Storage names are generated UUIDs, never taken from the client filename. Download/delete check UUID format, resolved parent directory, and regular-file status; symlinks are rejected. Display/download names are reduced to a basename and control characters are removed. |
| Invalid input and injection | Request JSON, names, email, password length, role values, UUIDs, and audit limits are validated. SQL values use prepared statements. |
| Credential/session exposure | bcrypt hashes are stored, raw tokens are returned only at login/registration, only token hashes are persisted, sessions expire/revoke, password hashes are omitted from API responses, and security headers are set. No passwords or tokens are written to audit records. |
| Password guessing | Failed logins return a generic message and are throttled to 10 unsuccessful attempts per connecting peer IP per 15 minutes. Behind a reverse proxy, the peer IP may identify the proxy rather than an individual client. |
| Audit tampering through the application | Audit routes are read-only; only admins can read them. SQLite triggers reject `UPDATE` and `DELETE`. Login, document, and role-management events are recorded. |
| Privilege escalation | Public registration assigns only `user`; only admins can change roles; role names are allowlisted; the last admin cannot be demoted. |
| Browser framing/content sniffing | API responses set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive Permissions Policy. |

## Assumptions and residual risks

- The deployment host, its filesystem, Node.js runtime, secrets, and administrator accounts are trusted. A host/database administrator can bypass application authorization and alter or replace the SQLite file/triggers; SQLite triggers are not cryptographic or remote tamper evidence.
- HTTPS must be provided by the deployment platform or reverse proxy. Do not send bearer tokens over plain public HTTP.
- The upload allowlist and signature checks are not antivirus or content-disarm scanning. Do not serve uploaded files inline; retain backups and consider malware scanning for higher-risk deployments.
- Login throttling is in-memory and per process/peer IP; it resets on restart and is not shared across instances. Configure a trusted proxy-aware shared rate limiter at the gateway for proxied or distributed deployments.
- Local SQLite and disk uploads suit a single application instance. Multiple instances need shared durable storage and a database designed for concurrency.
- No email verification, password reset, MFA, account lockout workflow, or external SIEM integration is included.
- A compromised admin session can change roles and access all documents. Protect admin credentials and use HTTPS.

## Verification

Run `npm test` for backend integration tests. They exercise cross-user access denial, unauthenticated access, malformed IDs, unsupported/mismatched and oversized files, regular-user restrictions on admin endpoints, role-management guardrails, login throttling, and append-only audit enforcement.
