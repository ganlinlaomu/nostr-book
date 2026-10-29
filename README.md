# nostr-book

read nostr post like reading a book

把 Nostr 时间线排成一本可以翻页的书来读。纯静态 PWA，无需构建：

- `index.html` — 应用本体
- `manifest.json` / `icon-512.png` — PWA 安装信息
- `sw.js` — Service Worker，离线缓存

本地预览：`python3 -m http.server`，然后打开 http://localhost:8000 。
可直接部署到 GitHub Pages / Cloudflare Pages 等任何静态托管。
