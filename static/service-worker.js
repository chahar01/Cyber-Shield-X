const CACHE_NAME = "cyber-shield-x-v1";
const APP_SHELL = [
    "/login",
    "/signup",
    "/forgot",
    "/static/manifest.json",
    "/static/pwa.js",
    "/static/pwa/icon-192.png",
    "/static/pwa/icon-512.png",
    "/static/pwa/icon.svg",
    "/static/pwa/maskable-icon.svg"
];

self.addEventListener("install", function (event) {
    event.waitUntil(
        caches.open(CACHE_NAME).then(function (cache) {
            return cache.addAll(APP_SHELL);
        }).catch(function () {
            return undefined;
        })
    );
    self.skipWaiting();
});

self.addEventListener("activate", function (event) {
    event.waitUntil(
        caches.keys().then(function (cacheNames) {
            return Promise.all(
                cacheNames
                    .filter(function (cacheName) {
                        return cacheName !== CACHE_NAME;
                    })
                    .map(function (cacheName) {
                        return caches.delete(cacheName);
                    })
            );
        })
    );
    self.clients.claim();
});

self.addEventListener("fetch", function (event) {
    const request = event.request;

    if (request.method !== "GET") {
        return;
    }

    const url = new URL(request.url);
    if (url.origin !== self.location.origin || url.pathname.startsWith("/download_")) {
        return;
    }

    const isCacheablePage = ["/login", "/signup", "/forgot"].includes(url.pathname);
    const isStaticAsset = url.pathname.startsWith("/static/");

    event.respondWith(
        fetch(request).then(function (response) {
            if (response.ok && response.type === "basic" && (isCacheablePage || isStaticAsset)) {
                const responseCopy = response.clone();
                caches.open(CACHE_NAME).then(function (cache) {
                    cache.put(request, responseCopy);
                });
            }
            return response;
        }).catch(function () {
            return caches.match(request).then(function (cached) {
                return cached || caches.match("/login");
            });
        })
    );
});
