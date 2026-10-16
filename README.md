# SellChometz
Mechiras Chometz web app (PWA). Static frontend (GitHub Pages) + Cloudflare Worker API with D1 database.
No congregant data is stored in this repository. Set `config.js` → `API_BASE` to the Worker URL.
Backend: see `worker/` (secrets ADMIN_PASSWORD and SESSION_SECRET via `wrangler secret put`).
