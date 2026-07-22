let me = null;

async function init() {
  const who = await fetch('/api/whoami').then((r) => r.json());
  if (!who.user) {
    window.location.href = 'login.html';
    return;
  }
  me = who.user;
  document.getElementById('whoami').textContent = `Signed in as ${me.username}${me.is_admin ? ' (admin)' : ''}`;
  loadUserPhotos(me.id, true);
}

function renderGrid(photos) {
  const grid = document.getElementById('grid');
  // VULN: stored XSS — title/description are inserted with innerHTML, no escaping.
  grid.innerHTML = photos
    .map(
      (p) => `
    <div class="tile" data-id="${p.id}" data-owner="${p.owner_id}">
      <img src="/uploads/${p.filename}" alt="">
      <div class="owner-badge">user #${p.owner_id}</div>
      <button class="delete-btn" onclick="deletePhoto(event, ${p.id})">&times;</button>
      <div class="caption">${p.title}</div>
    </div>
  `
    )
    .join('');

  [...grid.querySelectorAll('.tile')].forEach((tile, i) => {
    tile.addEventListener('click', (e) => {
      if (e.target.classList.contains('delete-btn')) return;
      openLightbox(photos[i]);
    });
  });
}

async function loadUserPhotos(userId, isMe) {
  document.getElementById('page-title').textContent = isMe ? 'Photos' : `Photos of user #${userId}`;
  // VULN: IDOR — the server only checks that a session exists, not that it
  // owns userId. Any logged-in user can pass any id here.
  const res = await fetch(`/api/users/${userId}/photos`);
  const photos = await res.json();
  renderGrid(Array.isArray(photos) ? photos : []);
}

document.getElementById('lookup-btn').addEventListener('click', () => {
  const id = prompt('View photos for user ID:');
  if (id) loadUserPhotos(id, false);
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = 'login.html';
});

document.getElementById('upload-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const res = await fetch('/api/photos', { method: 'POST', body: form });
  if (res.ok) {
    e.target.reset();
    loadUserPhotos(me.id, true);
  }
});

let searchTimer;
document.getElementById('search-input').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  const q = e.target.value;
  searchTimer = setTimeout(() => runSearch(q), 300);
});

async function runSearch(q) {
  const notice = document.getElementById('search-notice');
  if (!q) {
    notice.innerHTML = '';
    loadUserPhotos(me.id, true);
    return;
  }
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
  const data = await res.json();
  // VULN: reflected XSS — data.term is the raw query string, rendered unescaped.
  notice.innerHTML = `<div class="notice info">Results for: ${data.term}</div>`;
  document.getElementById('page-title').textContent = 'Search';
  renderGrid(data.results || []);
}

async function deletePhoto(e, id) {
  e.stopPropagation();
  // VULN: CSRF — plain POST, no anti-CSRF token, session cookie sent automatically.
  await fetch(`/api/photos/${id}/delete`, { method: 'POST' });
  loadUserPhotos(me.id, true);
}

function openLightbox(photo) {
  document.getElementById('lightbox-img').src = `/uploads/${photo.filename}`;
  // VULN: stored XSS in the lightbox description too.
  document.getElementById('lightbox-meta').innerHTML = `
    <h2>${photo.title}</h2>
    <p>${photo.description || ''}</p>
    <button class="btn secondary" onclick="shareLink(${photo.id})">Get share link</button>
    <div id="share-output" style="margin-top:8px;font-size:12px;word-break:break-all"></div>
  `;
  document.getElementById('lightbox').classList.add('open');
}

async function shareLink(id) {
  const res = await fetch(`/api/photos/${id}/share`, { method: 'POST' });
  const data = await res.json();
  document.getElementById('share-output').textContent = `${window.location.origin}${data.url}`;
}

document.getElementById('lightbox-close').addEventListener('click', () => {
  document.getElementById('lightbox').classList.remove('open');
});

init();
