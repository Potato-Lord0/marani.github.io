// Client-side donation helpers.
// This script expects a backend server to serve the site and provide two endpoints:
//  - GET /config -> { publicKey }
//  - POST /create-checkout-session { amount } -> { id: sessionId }
// See server/ for a minimal Node/Express scaffold.

let stripe = null;

async function initStripe() {
  try {
    const res = await fetch('/config');
    const cfg = await res.json();
    stripe = Stripe(cfg.publicKey || 'pk_test_replace_me');
    console.log('Stripe initialized');
  } catch (err) {
    console.error('Failed to initialize Stripe:', err);
  }
}

async function donate(amount) {
  if (!stripe) {
    alert('Payments are not configured. Run the local server and set Stripe keys.');
    return;
  }

  // amount is expected in USD (dollars) here; convert to cents for Checkout
  const cents = Math.round(Number(amount) * 100);
  if (!Number.isFinite(cents) || cents <= 0) {
    alert('Invalid amount');
    return;
  }

  try {
    const res = await fetch('/create-checkout-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: cents })
    });
    const data = await res.json();
    if (data.id) {
      const result = await stripe.redirectToCheckout({ sessionId: data.id });
      if (result.error) console.error(result.error.message);
    } else {
      console.error('No session id returned', data);
      alert('Payment setup failed. See console.');
    }
  } catch (err) {
    console.error('Error creating checkout session', err);
    alert('Payment request failed; check console for details.');
  }
}

function customDonate() {
  const value = prompt('Enter donation amount (USD):');
  if (value) donate(value);
}

// Prevent the contact form from submitting (no backend) and wire up Stripe on load
document.addEventListener('DOMContentLoaded', () => {
  initStripe();

  const form = document.querySelector('.contact-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      alert('This contact form is static. Provide a backend or third-party provider to handle submissions.');
    });
  }

  // Mobile nav toggle
  const navToggle = document.querySelector('.nav-toggle');
  const primaryNav = document.getElementById('primary-navigation');
  if (navToggle && primaryNav) {
    navToggle.addEventListener('click', () => {
      const expanded = navToggle.getAttribute('aria-expanded') === 'true';
      navToggle.setAttribute('aria-expanded', String(!expanded));
      primaryNav.classList.toggle('open');
    });
  }
});
