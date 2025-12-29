const express = require('express');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4242;

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

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
