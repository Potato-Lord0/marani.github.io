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
function getAuthToken() {
  return localStorage.getItem('marani_token');
}

function setAuth(token, user) {
  localStorage.setItem('marani_token', token);
  localStorage.setItem('marani_user', JSON.stringify(user || {}));
}

function clearAuth() {
  localStorage.removeItem('marani_token');
  localStorage.removeItem('marani_user');
}

async function fetchWithAuth(url, opts = {}) {
  const headers = opts.headers || {};
  const token = getAuthToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return fetch(url, { ...opts, headers });
}

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

  // Membership UI wiring
  const showRegisterBtn = document.getElementById('show-register');
  const showLoginBtn = document.getElementById('show-login');
  const registerForm = document.getElementById('register-form');
  const loginForm = document.getElementById('login-form');
  const memberArea = document.getElementById('member-area');
  const memberWelcome = document.getElementById('member-welcome');
  const signOutBtn = document.getElementById('sign-out');
  const tabEvents = document.getElementById('tab-events');
  const tabDiscussion = document.getElementById('tab-discussion');
  const tabEventsContent = document.getElementById('tab-events-content');
  const tabDiscussionContent = document.getElementById('tab-discussion-content');
  const eventsList = document.getElementById('events-list');
  const postsList = document.getElementById('posts-list');
  const postForm = document.getElementById('post-form');

  function showRegister() {
    registerForm.style.display = '';
    loginForm.style.display = 'none';
  }
  function showLogin() {
    loginForm.style.display = '';
    registerForm.style.display = 'none';
  }

  showRegisterBtn && showRegisterBtn.addEventListener('click', showRegister);
  showLoginBtn && showLoginBtn.addEventListener('click', showLogin);

  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('reg-name').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const password = document.getElementById('reg-password').value;
      try {
        const res = await fetch('/api/register', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Registration failed');
        setAuth(data.token, data.user);
        initializeMemberArea();
      } catch (err) {
        alert('Registration failed: ' + err.message);
      }
    });
  }

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      try {
        const res = await fetch('/api/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Sign in failed');
        setAuth(data.token, data.user);
        initializeMemberArea();
      } catch (err) {
        alert('Sign in failed: ' + err.message);
      }
    });
  }

  signOutBtn && signOutBtn.addEventListener('click', (e) => {
    clearAuth();
    memberArea.style.display = 'none';
    document.getElementById('membership-cta').style.display = '';
    document.getElementById('auth-forms').style.display = '';
  });

  tabEvents && tabEvents.addEventListener('click', () => {
    tabEventsContent.style.display = '';
    tabDiscussionContent.style.display = 'none';
  });
  tabDiscussion && tabDiscussion.addEventListener('click', () => {
    tabDiscussionContent.style.display = '';
    tabEventsContent.style.display = 'none';
  });

  async function fetchEvents() {
    try {
      const res = await fetchWithAuth('/api/events');
      if (!res.ok) throw new Error('Failed to load events');
      const events = await res.json();
      eventsList.innerHTML = events.map(ev => `\n        <div class="event">\n          <strong>${ev.title}</strong> — <em>${ev.date}</em>\n          <div>${ev.description || ''}</div>\n        </div>`).join('');
    } catch (err) {
      eventsList.innerHTML = '<p>Unable to load events. Please sign in.</p>';
    }
  }

  async function fetchPosts() {
    try {
      const res = await fetchWithAuth('/api/posts');
      if (!res.ok) throw new Error('Failed to load posts');
      const posts = await res.json();
      // Render posts safely to avoid HTML injection
      postsList.innerHTML = '';
      const currentUser = JSON.parse(localStorage.getItem('marani_user') || '{}');
      posts.forEach(p => {
        const postEl = document.createElement('div');
        postEl.className = 'post';

        const meta = document.createElement('div');
        meta.className = 'meta';

        const avatar = document.createElement('div');
        avatar.className = 'avatar';
        const initials = (p.author || '').split(' ').map(s => s[0]).filter(Boolean).slice(0,2).join('').toUpperCase();
        avatar.textContent = initials || 'M';

        const author = document.createElement('span');
        author.className = 'author';
        author.textContent = p.author || 'Member';

        const time = document.createElement('span');
        time.className = 'time';
        time.textContent = new Date(p.createdAt).toLocaleString();

        meta.appendChild(avatar);
        meta.appendChild(author);
        meta.appendChild(document.createTextNode(' • '));
        meta.appendChild(time);

        // Actions container (e.g., delete)
        if (currentUser && currentUser.id && p.authorId === currentUser.id) {
          const actions = document.createElement('div');
          actions.className = 'actions';
          const del = document.createElement('button');
          del.className = 'delete-btn';
          del.textContent = 'Delete';
          del.addEventListener('click', async () => {
            if (!confirm('Delete this post? This cannot be undone.')) return;
            try {
              const d = await fetchWithAuth(`/api/posts/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
              const body = await d.json();
              if (!d.ok) throw new Error(body.error || 'Delete failed');
              // remove post element from DOM
              postEl.remove();
            } catch (err) {
              alert('Delete failed: ' + err.message);
            }
          });
          actions.appendChild(del);
          meta.appendChild(actions);
        }

        const content = document.createElement('div');
        content.className = 'content';
        content.textContent = p.content || '';

        postEl.appendChild(meta);
        postEl.appendChild(content);
        postsList.appendChild(postEl);
      });
    } catch (err) {
      postsList.innerHTML = '<p>Unable to load discussion. Please sign in.</p>';
    }
  }

  if (postForm) {
    postForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const content = document.getElementById('post-content').value.trim();
      if (!content) return;
      try {
        const res = await fetchWithAuth('/api/posts', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Post failed');
        document.getElementById('post-content').value = '';
        fetchPosts();
      } catch (err) {
        alert('Post failed: ' + err.message);
      }
    });
  }

  async function initializeMemberArea() {
    const token = getAuthToken();
    if (!token) return;
    try {
      const res = await fetchWithAuth('/api/me');
      if (!res.ok) throw new Error('Not authenticated');
      const me = await res.json();
      // keep a copy of user info in localStorage for client-side checks (used to show delete button)
      localStorage.setItem('marani_user', JSON.stringify(me));
      document.getElementById('membership-cta').style.display = 'none';
      document.getElementById('auth-forms').style.display = 'none';
      memberArea.style.display = '';
      memberWelcome.textContent = `Welcome, ${me.name || me.email}`;
      fetchEvents();
      fetchPosts();
    } catch (err) {
      clearAuth();
    }
  }

  // On load, check for stored token
  initializeMemberArea();

});
