# Server README

Minimal Node/Express scaffold to test Stripe Checkout locally and serve the static site from the same origin.

Setup

1. Copy `.env.example` to `.env` and fill in your Stripe test keys:

```
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
PORT=4242
```

2. Install dependencies and start the server:

```bash
cd server
npm install
npm start
```

3. Open `http://localhost:4242` to view the site. Donation buttons will call the local server to create a Checkout session.

Notes
- Do NOT commit real secret keys. Use test keys only while developing.
- This is a minimal example for local testing only; do not use as-is in production.

Membership
- The server includes a simple membership API for prototyping (file-based storage in `server/data/`).
- Endpoints:
  - `POST /api/register` { name, email, password } -> { token, user }
  - `POST /api/login` { email, password } -> { token, user }
  - `GET /api/me` -> authenticated user
  - `GET /api/events` -> member-only events (calendar)
  - `GET /api/posts` -> list discussion posts
  - `POST /api/posts` { content } -> create post
  - `POST /api/posts/:id/flag` { reason? } -> flag a post for moderation
  - `POST /api/mod/posts/:id/clear-flag` -> admin-only clear flag
  - `GET /api/mod/posts` -> admin-only list flagged posts
  - `DELETE /api/mod/posts/:id` -> admin-only delete post
  - `POST /api/assign-admin` { email, secret } -> dev helper to grant admin role (requires `ADMIN_SECRET` env var)
- Configure `JWT_SECRET` in your `.env` for production-like tokens. For local testing a default is used.
- Start the server (`npm start`) and use the membership UI on the `Member Area` page to register and sign in.

Admin (dev) setup:
- Set `ADMIN_SECRET` in `.env` and call `POST /api/assign-admin` with `{ "email": "test@example.com", "secret": "your-secret" }` to promote a user to admin for testing moderation features.

Security notes:
- This is a prototype with file-based storage; **do not use in production**.
- Environment: set a secure `JWT_SECRET` in your `.env` to avoid predictable tokens.
- Consider moving to a real database, enabling HTTPS, adding email verification, and adding moderation & audit logging for posts.
- Basic protections added: `helmet` (security headers), request body size limits, input validation, and rate limiting on auth and posts endpoints.
-For testing:
    test@example.com
    pass123