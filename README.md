# nostr-book

驿书 — read nostr posts like reading a book

把 Nostr 关注动态排成一本可以翻页的书来读。纯静态 PWA，无需构建：

- `index.html` — 应用本体
- `manifest.json` / `icon-512.png` — PWA 安装信息
- `sw.js` — Service Worker，离线缓存

本地预览：`python3 -m http.server`，然后打开 http://localhost:8000 。
可直接部署到 GitHub Pages / Cloudflare Pages 等任何静态托管。

新增：收录关注账号的普通动态、NIP-10 回复与 NIP-22 评论。评论正文须至少含 20 个汉字（不计算引用段落、URL、标点、数字和英文字母）。旧版书库首次升级会尝试补查最近 7 天的评论。
