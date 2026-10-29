# nostr-book

驿书 — read nostr posts like reading a book

把 Nostr 关注动态排成一本可以翻页的书来读。纯静态 PWA，无需构建：

- `index.html` — 应用本体
- `manifest.json` / `icon-512.png` — PWA 安装信息
- `sw.js` — Service Worker，离线缓存

本地预览：`python3 -m http.server`，然后打开 http://localhost:8000 。
可直接部署到 GitHub Pages / Cloudflare Pages 等任何静态托管。

新增：收录关注账号的普通动态、NIP-10 回复与 NIP-22 评论。评论正文须至少含 20 个汉字（不计算引用段落、URL、标点、数字和英文字母）。旧版书库首次升级会尝试补查最近 7 天的评论。

## 随笔（本地优先试用版）

阅读不需要私钥。点击顶部工具栏「写」，草稿自动存入本机 IndexedDB，关闭后仍能继续编辑。点击「发表」时，可以首次导入当前阅读账号的 nsec / 64 位十六进制私钥，并设置至少 12 字符的加密密码。私钥由 WebCrypto PBKDF2-SHA256（310,000 次）和 AES-256-GCM 加密，仅存储密文；每次发表输入密码后在本机解密、NIP-01 kind 1 签名，签名后清理密钥内存，然后向 NIP-65 写入 Relay 和默认 Relay 发送并等待 OK 回执。没有成功回执时保留草稿，不直接报告发表成功。

**安全边界**：这是试用实现，不是经过独立安全审计的密钥钱包。Schnorr 签名仅在导入/发表时动态加载固定版本的 `@noble/secp256k1@3.1.0`，由 jsDelivr CDN 提供；签名逻辑在客户端运行，但加载该第三方 JavaScript 需要信任 CDN，离线时首次使用签名功能不可用。强烈建议首次测试使用专门的测试身份，而非重要的主账号私钥。密码丢失只能重新导入私钥。不要在共享设备导入私钥。清理网站数据或卸载 PWA 可能删除草稿及本地加密密钥。加密不能防御被篡改的同源 JavaScript、受感染设备或 XSS。纯离线时可以写作和阅读已缓存书籍；真正发布需要网络。
