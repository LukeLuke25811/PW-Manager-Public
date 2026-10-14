// Caches the app's own files so it opens offline. The vault itself is never
// fetched over the network, so nothing secret passes through here.
const CACHE = "pwm-web-v1";
const FILES = [
  "./", "index.html", "app.js", "vault.js", "style.css", "manifest.webmanifest",
  "icon.svg", "icon-180.png", "icon-512.png", "vendor/argon2.umd.min.js",
];

self.addEventListener("install", (ev) => {
  ev.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (ev) => {
  ev.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// Network first so updates arrive right away; the cache is the offline fallback.
self.addEventListener("fetch", (ev) => {
  if (ev.request.method !== "GET" || new URL(ev.request.url).origin !== self.location.origin) return;
  ev.respondWith(fetch(ev.request)
    .then((res) => {
      if (res.ok) {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(ev.request, copy));
      }
      return res;
    })
    .catch(() => caches.match(ev.request, { ignoreSearch: true })));
});
