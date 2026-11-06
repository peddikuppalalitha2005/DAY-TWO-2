# Five-minute demo recording script

This is a timed recording plan; it is not itself a video.

## Before recording

1. Start locally with `npm run dev`, or use the deployed HTTPS URL.
2. For a local-only demo, set three distinct demo emails and passwords in `.env`, then run `npm run seed:demo -w backend`.
3. Keep the admin, manager, and regular-user credentials ready in a password manager; do not show passwords in the recording.
4. Have one small plain-text or PDF sample file ready. Do not use real or sensitive documents. Upload checks recognize basic file signatures; they do not scan for malware or fully parse documents.

## Timeline (5:00)

- **0:00–0:35 — Introduction:** name the app and explain the admin/manager/user roles.
- **0:35–1:15 — Sign-in and dashboard:** sign in as the regular user; show the role and document count.
- **1:15–2:10 — Document lifecycle:** upload a sample, show the list, download it, then delete it.
- **2:10–3:00 — User isolation:** sign in as a second regular user and show that the first user's file is not listed and direct access is denied.
- **3:00–3:45 — Upload validation:** demonstrate that a disallowed extension/type and a file over the configured limit are rejected.
- **3:45–4:35 — Admin controls and audit:** sign in as admin, show user/role administration and audit history; explain audit records are append-only and that the last admin cannot be demoted.
- **4:35–5:00 — Close:** mention the automated test command, threat model, and deployment target/limitations.

Do not display bearer tokens, passwords, `.env`, SQLite files, or sensitive document contents. If recording against a local test database, disclose that it is a local demo rather than a public deployment.
