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
  grid.innerHTML = ''; 

  photos.forEach(p => {
    const tile = document.createElement('div');
    tile.className = 'tile';
    tile.dataset.id = p.id;
    tile.dataset.owner = p.owner_id;

    const img = document.createElement('img');
    img.src = `/uploads/${p.filename}`;

    const caption = document.createElement('div');
    caption.className = 'caption';
    caption.textContent = p.title; 

    const badge = document.createElement('div');
    badge.className = 'owner-badge';
    badge.textContent = `user #${p.owner_id}`;

    tile.appendChild(img);
    tile.appendChild(badge);
    tile.appendChild(caption);
    grid.appendChild(tile);
  });

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
  //notice.innerHTML = `<div class="notice info">Results for: ${data.term}</div>`;
  divNotice = document.createElement('div');
  divNotice.className = 'notice info';
  divNotice.textContent = `Results for: ${data.term}`;
  notice.appendChild(divNotice);
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

  const meta = document.getElementById('lightbox-meta');
  meta.innerHTML = ''; // safe - no user data here

  const titleEl = document.createElement('h2');
  titleEl.textContent = photo.title;

  const descEl = document.createElement('p');
  descEl.textContent = photo.description || '';

  const shareBtn = document.createElement('button');
  shareBtn.className = 'btn secondary';
  shareBtn.textContent = 'Get share link';
  shareBtn.addEventListener('click', () => shareLink(photo.id));

  const shareOutput = document.createElement('div');
  shareOutput.id = 'share-output';
  shareOutput.style.cssText = 'margin-top:8px;font-size:12px;word-break:break-all';

  meta.appendChild(titleEl);
  meta.appendChild(descEl);
  meta.appendChild(shareBtn);
  meta.appendChild(shareOutput);

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
