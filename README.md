# marani.github.io

Added membership prototype: registration, login, member calendar (events), and discussion board backed by a simple file-based server API for quick testing. Also includes moderation features (flagging and admin moderation panel).

Run the server:

```bash
cd server
npm install
npm start
```

Open http://localhost:4242 and visit **Member Area** to register and access member features. For moderation testing, set `ADMIN_SECRET` in `server/.env` and call POST `/api/assign-admin` with `{ "email": "user@example.com", "secret": "..." }` to promote a user to admin.