const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4242;

const DATA_DIR = path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_secure_secret';

// Helpers for simple file-based data store
async function readJson(filename) {
  const p = path.join(DATA_DIR, filename);
  try {
    const raw = await fs.promises.readFile(p, 'utf8');
    return JSON.parse(raw || 'null') || [];
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

async function writeJson(filename, data) {
  const p = path.join(DATA_DIR, filename);
  await fs.promises.writeFile(p, JSON.stringify(data, null, 2), 'utf8');
}

// If you want to test Stripe locally, set STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY in .env
const stripeSecret = process.env.STRIPE_SECRET_KEY || 'sk_test_replace_me';
const stripePublishable = process.env.STRIPE_PUBLISHABLE_KEY || 'pk_test_replace_me';

const stripe = require('stripe')(stripeSecret);

app.use(express.static(path.join(__dirname, '..')));
app.use(express.json());

app.get('/config', (req, res) => {
  res.json({ publicKey: stripePublishable });
});

app.post('/create-checkout-session', async (req, res) => {
  const { amount } = req.body; // expected in cents
  if (!amount || isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: 'Marani Donation' },
            unit_amount: parseInt(amount, 10)
          },
          quantity: 1
        }
      ],
      success_url: `${req.protocol}://${req.get('host')}/?success=true`,
      cancel_url: `${req.protocol}://${req.get('host')}/?canceled=true`
    });

    res.json({ id: session.id });
  } catch (err) {
    console.error('Stripe session error', err);
    res.status(500).json({ error: 'Internal error creating session' });
  }
});

// Simple authentication helpers
function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
}

async function authenticateToken(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Registration endpoint
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  const users = await readJson('users.json');
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) return res.status(409).json({ error: 'Email already in use' });

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: `user-${Date.now()}`, name, email, password: hashed };
  users.push(user);
  await writeJson('users.json', users);

  const token = createToken(user);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const users = await readJson('users.json');
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = createToken(user);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get('/api/me', authenticateToken, async (req, res) => {
  const users = await readJson('users.json');
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email });
});

// Events (calendar) - members only
app.get('/api/events', authenticateToken, async (req, res) => {
  const events = await readJson('events.json');
  res.json(events);
});

// Discussion board
app.get('/api/posts', authenticateToken, async (req, res) => {
  const posts = await readJson('posts.json');
  res.json(posts);
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  const { content } = req.body || {};
  if (!content) return res.status(400).json({ error: 'Missing content' });

  const posts = await readJson('posts.json');
  const post = {
    id: `post-${Date.now()}`,
    author: req.user.name || req.user.email,
    authorId: req.user.id,
    content,
    createdAt: Date.now()
  };
  posts.unshift(post);
  await writeJson('posts.json', posts);
  res.json(post);
});

// Delete a post (only author can delete)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const posts = await readJson('posts.json');
  const idx = posts.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Post not found' });
  const post = posts[idx];
  if (post.authorId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  posts.splice(idx, 1);
  await writeJson('posts.json', posts);
  res.json({ deleted: id });
});

// Keep the existing app.listen behavior
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
