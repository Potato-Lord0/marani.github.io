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
