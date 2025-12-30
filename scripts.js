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

// Safely parse JSON responses, fall back to text when content-type isn't JSON
async function parseJsonSafe(res) {
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (ct.includes('application/json')) {
    return res.json();
  }
  // If the server returned HTML or plain text, return the text for a clearer error message
  return res.text();
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

  // Show login form by default on members page
  if (window.location.pathname.endsWith('/members.html') && loginForm) showLogin();

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
        const data = await parseJsonSafe(res);
        if (!res.ok) {
          const msg = (data && typeof data === 'object') ? (data.error || JSON.stringify(data)) : String(data || 'Registration failed');
          throw new Error(msg);
        }
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
        const data = await parseJsonSafe(res);
        if (!res.ok) {
          const msg = (data && typeof data === 'object') ? (data.error || JSON.stringify(data)) : String(data || 'Sign in failed');
          throw new Error(msg);
        }
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

        // Flagged badge
        if (p.flagged) {
          const badge = document.createElement('span');
          badge.className = 'flagged-badge';
          badge.textContent = 'Flagged';
          meta.appendChild(badge);
        }

        // Actions container (delete by owner, flag by others)
        const actions = document.createElement('div');
        actions.className = 'actions';

        if (currentUser && currentUser.id && p.authorId === currentUser.id) {
          const del = document.createElement('button');
          del.className = 'delete-btn';
          del.textContent = 'Delete';
          del.addEventListener('click', async () => {
            if (!confirm('Delete this post? This cannot be undone.')) return;
            try {
              const d = await fetchWithAuth(`/api/posts/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
              const body = await parseJsonSafe(d).catch(() => null);
              if (!d.ok) {
                const msg = (body && typeof body === 'object') ? (body.error || JSON.stringify(body)) : String(body || 'Delete failed');
                throw new Error(msg);
              }
              // remove post element from DOM
              postEl.remove();
            } catch (err) {
              alert('Delete failed: ' + err.message);
            }
          });
          actions.appendChild(del);
        } else if (currentUser && currentUser.id) {
          // allow flagging
          if (!p.flagged) {
            const flagBtn = document.createElement('button');
            flagBtn.className = 'delete-btn';
            flagBtn.textContent = 'Flag';
            flagBtn.addEventListener('click', async () => {
              const reason = prompt('Reason for flagging (optional):');
              try {
                const d = await fetchWithAuth(`/api/posts/${encodeURIComponent(p.id)}/flag`, {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ reason })
                });
                const body = await parseJsonSafe(d).catch(() => null);
                if (!d.ok) {
                  const msg = (body && typeof body === 'object') ? (body.error || JSON.stringify(body)) : String(body || 'Flag failed');
                  throw new Error(msg);
                }
                fetchPosts();
                // if admin panel visible, refresh it
                if (typeof window.fetchFlaggedPosts === 'function') window.fetchFlaggedPosts();
                alert('Post flagged for review.');
              } catch (err) {
                alert('Flag failed: ' + err.message);
              }
            });
            actions.appendChild(flagBtn);
          } else {
            // show small note if already flagged
            const flaggedNote = document.createElement('span');
            flaggedNote.className = 'flagged-note';
            flaggedNote.textContent = 'Flagged';
            actions.appendChild(flaggedNote);
          }
        }

        // append actions if any
        if (actions.children.length) meta.appendChild(actions);

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
    const postContent = document.getElementById('post-content');
    const postSubmit = document.getElementById('post-submit');
    const charCount = document.getElementById('char-count');

    async function fetchFlaggedPosts() {
      try {
        const res = await fetchWithAuth('/api/mod/posts');
        if (!res.ok) throw new Error('Failed to load flagged posts');
        const posts = await res.json();
        const flaggedList = document.getElementById('flagged-posts-list');
        if (!flaggedList) return;
        flaggedList.innerHTML = '';
        posts.forEach(p => {
          const el = document.createElement('div');
          el.className = 'post';

          const meta = document.createElement('div');
          meta.className = 'meta';
          const avatar = document.createElement('div'); avatar.className = 'avatar';
          avatar.textContent = (p.author||'').split(' ').map(s=>s[0]).slice(0,2).join('').toUpperCase() || 'M';
          const author = document.createElement('span'); author.className = 'author'; author.textContent = p.author;
          const time = document.createElement('span'); time.className = 'time'; time.textContent = new Date(p.createdAt).toLocaleString();
          meta.appendChild(avatar); meta.appendChild(author); meta.appendChild(document.createTextNode(' • ')); meta.appendChild(time);

          const reason = document.createElement('div'); reason.className = 'flag-reason'; reason.textContent = p.flagReason ? `Reason: ${p.flagReason}` : 'No reason provided.';

          const actions = document.createElement('div'); actions.className = 'actions';
          const clearBtn = document.createElement('button'); clearBtn.className = 'delete-btn'; clearBtn.textContent = 'Clear Flag';
          clearBtn.addEventListener('click', async () => {
            if (!confirm('Clear flag for this post?')) return;
            try {
              const r = await fetchWithAuth(`/api/mod/posts/${encodeURIComponent(p.id)}/clear-flag`, { method: 'POST' });
              const b = await parseJsonSafe(r).catch(() => null);
              if (!r.ok) {
                const msg = (b && typeof b === 'object') ? (b.error || JSON.stringify(b)) : String(b || 'Clear failed');
                throw new Error(msg);
              }
              fetchFlaggedPosts(); fetchPosts();
            } catch (err) { alert('Clear failed: '+err.message); }
          });
          const delBtn = document.createElement('button'); delBtn.className = 'delete-btn'; delBtn.textContent = 'Delete';
          delBtn.addEventListener('click', async () => {
            if (!confirm('Delete this post permanently?')) return;
            try {
              const r = await fetchWithAuth(`/api/mod/posts/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
              const b = await parseJsonSafe(r).catch(() => null);
              if (!r.ok) {
                const msg = (b && typeof b === 'object') ? (b.error || JSON.stringify(b)) : String(b || 'Delete failed');
                throw new Error(msg);
              }
              fetchFlaggedPosts(); fetchPosts();
            } catch (err) { alert('Delete failed: '+err.message); }
          });
          actions.appendChild(clearBtn); actions.appendChild(delBtn);

          const content = document.createElement('div'); content.className = 'content'; content.textContent = p.content || '';

          el.appendChild(meta); el.appendChild(reason); el.appendChild(content); el.appendChild(actions);
          flaggedList.appendChild(el);
        });
      } catch (err) {
        // ignore, admin panel will show empty
      }
    }

    // Expose fetchFlaggedPosts to window for use elsewhere (e.g., after flagging)
    window.fetchFlaggedPosts = typeof fetchFlaggedPosts === 'function' ? fetchFlaggedPosts : null;

    function updateCharCount() {
      const len = postContent.value.length;
      charCount.textContent = `${len} / ${postContent.getAttribute('maxlength') || 1000}`;
      postSubmit.disabled = len === 0 || len > Number(postContent.getAttribute('maxlength'));
    }

    postContent && postContent.addEventListener('input', updateCharCount);
    updateCharCount();

    postForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const content = postContent.value.trim();
      if (!content) return;
      if (content.length > 2000) { alert('Post is too long'); return; }
      try {
        postSubmit.disabled = true;
        const res = await fetchWithAuth('/api/posts', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        const data = await parseJsonSafe(res);
        if (!res.ok) {
          const msg = (data && typeof data === 'object') ? (data.error || JSON.stringify(data)) : String(data || 'Post failed');
          throw new Error(msg);
        }
        postContent.value = '';
        updateCharCount();
        fetchPosts();
      } catch (err) {
        alert('Post failed: ' + err.message);
      } finally {
        postSubmit.disabled = false;
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
      // moderation tab visibility for admins
      const tabModerationEl = document.getElementById('tab-moderation');
      const tabModerationContent = document.getElementById('tab-moderation-content');
      const flaggedPostsList = document.getElementById('flagged-posts-list');
      if (tabModerationEl) {
        if (me.isAdmin) {
          tabModerationEl.style.display = '';
          tabModerationEl.addEventListener('click', () => {
            tabModerationContent.style.display = '';
            tabDiscussionContent.style.display = 'none';
            tabEventsContent.style.display = 'none';
            fetchFlaggedPosts();
          });
        } else {
          tabModerationEl.style.display = 'none';
        }
      }

      fetchEvents();
      fetchPosts();
    } catch (err) {
      clearAuth();
    }
  }

  // On load, check for stored token
  initializeMemberArea();

});
