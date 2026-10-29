const CACHE = 'book-v14';
const SHELL = ['./', 'index.html', 'writer.js', 'vendor/noble-secp256k1.js', 'manifest.json', 'icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL))); self.skipWaiting(); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET') return;
  // 字体：先用缓存
  if (u.host.endsWith('fonts.gstatic.com') || u.host.endsWith('fonts.googleapis.com')) {
    e.respondWith(caches.open(CACHE).then(async c => (await c.match(e.request)) ||
      fetch(e.request).then(r => { c.put(e.request, r.clone()); return r; })));
    return;
  }
  // 页面：先联网，断网时用缓存
  if (u.origin === location.origin) {
    e.respondWith(fetch(e.request, { cache: 'no-cache' }).then(r => { caches.open(CACHE).then(c => c.put(e.request, r.clone())); return r; })
      .catch(() => caches.match(e.request).then(r => r || caches.match('index.html'))));
  }
});
