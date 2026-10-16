const C="sellchometz-v5";const SHELL=["icons/icon-192.png","icons/icon-512.png","manifest.webmanifest"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(SHELL)));self.skipWaiting()});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{const u=new URL(e.request.url);if(e.request.method!=="GET"||u.origin!==location.origin)return; // API never cached
 const fresh=e.request.mode==="navigate"||/\.(html|js|webmanifest)$/.test(u.pathname)||u.pathname.endsWith("/");
 e.respondWith(fetch(e.request,fresh?{cache:"no-store"}:{}).then(r=>{if(r.ok){const cp=r.clone();caches.open(C).then(c=>c.put(e.request,cp))}return r}).catch(()=>caches.match(e.request).then(m=>m||caches.match("./"))))});
