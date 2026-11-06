# Project prompt log

This is a concise summary of the project requirements that guided the implementation, not a verbatim transcript.

## Day 1 — application foundation

Build a React frontend and Express backend for a document workspace. Add SQLite schema/migrations, bcrypt registration/login, revocable sessions, admin/manager/user roles, server-enforced document ownership, upload/list/download/delete, role-specific dashboards, and Docker deployment preparation.

## Day 2 — security and submission

Harden the backend against IDOR/BOLA, unsafe upload types/sizes, path traversal, invalid input, and unauthorized document operations. Make audit events append-only and admin-readable, add backend integration coverage for authentication, roles, uploads/downloads, and cross-user isolation, and document the API, threat model, setup, demo seed accounts, deployment, and final demonstration.

## Security constraints reflected in the code

- Treat frontend visibility as presentation only; enforce authorization in the API.
- Never assign privileged roles during public registration.
- Store server-generated file identifiers rather than client paths.
- Do not commit credentials, real test passwords, local databases, or uploaded files.
- State deployment limitations honestly; a demo script is not a recorded demo video.
