# Talkz Cloud — Render deployment

Talkz Cloud is a real server-backed chat MVP with:
- User registration and sign-in (passwords hashed with bcrypt)
- PostgreSQL persistence for users, servers, channels, memberships, and messages
- Session-based authentication with HTTP-only cookies
- Real-time channel message updates through Socket.IO
- Membership checks on server/channel/message routes
- Rate limits on authentication and message sending
- Render Blueprint configuration for a web service and PostgreSQL database

## Deploy to Render

1. Create a GitHub repository and upload the contents of this folder to its root.
2. In Render, choose **New + → Blueprint** and connect that repository.
3. Render reads `render.yaml` and proposes the `talkz-cloud` web service plus `talkz-db` PostgreSQL database. Review the plan and deploy.
4. Wait for the web service to finish deploying. Open its `onrender.com` URL.
5. Create an account in Talkz and test with two separate browsers/accounts.

The Blueprint generates `SESSION_SECRET` and wires the database connection string into the service. Do not put secrets in GitHub or browser code.

## Local development

Requires Node.js 20+ and PostgreSQL.

1. Create a database named `talkz`.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` and a long random `SESSION_SECRET`.
3. Install dependencies with `npm install`.
4. Run `npm start`, then visit `http://localhost:3000`.

The app creates its required tables on startup. `connect-pg-simple` also creates its session table.

## Current scope / important limitations

This is a first cloud MVP, not a complete Discord replacement:
- Real-time messages work in text channels for connected users.
- Account recovery/email verification, invitations, public server discovery, roles UI, DMs, uploads, moderation tools, and voice/video are not implemented yet.
- The `join` endpoint is a basic starter and currently has no invite-code requirement; do not advertise it as a secure public discovery feature. Add signed invite codes and abuse controls before opening communities broadly.
- Free Render services/databases can have limits or sleep/expiry policies that change over time. Check the current Render dashboard/pricing before relying on a free deployment.
- Before production use, add email verification/password reset, CSRF protection appropriate to the chosen auth model, stronger server-join/invite flows, moderation/reporting, backups, monitoring, and a security review.
- PostgreSQL SSL uses `rejectUnauthorized: false` in production for compatibility with hosted database certificates. For stricter deployments, configure certificate verification according to your database provider.

## Project files

- `server.js` — Express API, PostgreSQL schema setup, sessions, Socket.IO
- `public/index.html` — Talkz login and app layout
- `public/style.css` — Talkz UI styling
- `public/app.js` — client application
- `render.yaml` — Render Blueprint
