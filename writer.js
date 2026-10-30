/* 驿书写作模块 — 单独维护，不干预书页渲染。
 * 私钥只存在于一次操作的内存中；持久化的只有 PBKDF2/AES-GCM 密文。
 * 签名算法来自固定版本的 noble-secp256k1；仅在密钥设置或发表时加载。
 */
const $ = id => document.getElementById(id);
const overlay = $('writerOverlay');
const editor = $('writerText');
const status = $('writerStatus');
const setup = $('writerSetup');
const unlock = $('writerUnlock');
const importButton = $('writerImport');
const publishButton = $('writerPublish');
const closeButton = $('writerClose');
const saveHint = $('writerSaved');
const secretInput = $('writerSecret');
const newPassInput = $('writerNewPass');
const confirmPassInput = $('writerNewPassConfirm');
const unlockPassInput = $('writerUnlockPass');
let activePk = null;
let replyCtx = null;      // 回复模式：被回复内容的 id / 作者 / kind；null 表示写随笔
let draftKey = null;      // 随笔草稿按 npub 存；每条回复各自一份草稿
let saveTimer = null;
let opBusy = false;
let draftGeneration = 0;
const encoder = new TextEncoder();
const KDF_ITERATIONS = 310000;
const MAX_CONTENT = 12000;
const NOBLE_SOURCE = './vendor/noble-secp256k1.js';
let schnorrPromise;
function showStatus(text, error = false){
  status.textContent = text;
  status.classList.toggle('error', error);
}
function showPanel(panel){
  setup.hidden = panel !== 'setup';
  unlock.hidden = panel !== 'unlock';
}
const b2h = bytes => Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
function h2b(hex){
  if (typeof hex !== 'string' || !/^[a-f0-9]{64}$/i.test(hex)) throw Error('私钥格式不正确');
  return Uint8Array.from(hex.match(/../g), b => parseInt(b, 16));
}
const ABC = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function nsecBytes(value){
  const input = String(value || '').trim();
  if (/^[0-9a-f]{64}$/i.test(input)) return h2b(input);
  const text = input.replace(/^nostr:/i, '');
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) throw Error('nsec 不能混用大小写');
  const s = text.toLowerCase();
  if (!s.startsWith('nsec1')) throw Error('请输入 nsec 私钥或 64 位十六进制私钥');
  const values = [...s.slice(5)].map(ch => ABC.indexOf(ch));
  if (values.length < 7 || values.some(i => i < 0)) throw Error('nsec 格式不正确');
  // Bech32 checksum for Nostr NIP-19.
  let chk = 1;
  const step=v=>{const top=chk>>>25;chk=((chk&0x1ffffff)<<5)^v;for(let i=0;i<5;i++)if((top>>>i)&1)chk^=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3][i];};
  for(const ch of 'nsec')step(ch.charCodeAt(0)>>>5);
  step(0);
  for(const ch of 'nsec')step(ch.charCodeAt(0)&31);
  for (const v of values)step(v);
  if (chk !== 1) throw Error('nsec 校验失败，请检查是否输错');
  let acc=0, bits=0;
  const out=[];
  for(const v of values.slice(0,-6)){
    acc=(acc<<5)|v;bits+=5;
    while(bits>=8){bits-=8;out.push((acc>>>bits)&255);}
    acc &= (1<<bits)-1;
  }
  if (bits >= 5 || (acc & ((1<<bits)-1))) throw Error('nsec 编码不正确');
  if (out.length !== 32) throw Error('nsec 长度不正确');
  return new Uint8Array(out);
}
async function schnorr(){
  if (!schnorrPromise) schnorrPromise = import(NOBLE_SOURCE).then(mod => {
    if (!mod.schnorr?.signAsync || !mod.schnorr?.verifyAsync || !mod.schnorr?.getPublicKey)
      throw Error('签名库接口不可用');
    return mod.schnorr;
  }).catch(err => { schnorrPromise = null; throw err; });
  return schnorrPromise;
}
function vaultKey(pk){return 'book.writer.vault.v1.' + pk;}
function getVault(pk){
  try{
    const obj=JSON.parse(localStorage.getItem(vaultKey(pk)));
    if(obj?.v===1 && obj.pk===pk && obj.iter===KDF_ITERATIONS && /^[a-f0-9]{32}$/.test(obj.salt) &&
       /^[a-f0-9]{24}$/.test(obj.iv) && /^[a-f0-9]+$/.test(obj.data)) return obj;
  }catch(e){}
  return null;
}
async function passKey(password,salt){
  const passwordBytes=encoder.encode(password);
  try{
    const input=await crypto.subtle.importKey('raw',passwordBytes,'PBKDF2',false,['deriveKey']);
    return await crypto.subtle.deriveKey(
      {name:'PBKDF2',salt,iterations:KDF_ITERATIONS,hash:'SHA-256'},input,
      {name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }finally{passwordBytes.fill(0);}
}
async function encryptSecret(secret,password,pk){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await passKey(password,salt);
  const data=new Uint8Array(await crypto.subtle.encrypt(
    {name:'AES-GCM',iv,additionalData:encoder.encode('nostr-book:v1:'+pk)},key,secret));
  return {v:1,pk,iter:KDF_ITERATIONS,salt:b2h(salt),iv:b2h(iv),data:b2h(data)};
}
async function decryptSecret(vault,password){
  const salt=Uint8Array.from(vault.salt.match(/../g),x=>parseInt(x,16));
  const key=await passKey(password,salt);
  const data=Uint8Array.from(vault.data.match(/../g),x=>parseInt(x,16));
  try{
    return new Uint8Array(await crypto.subtle.decrypt(
      {name:'AES-GCM',iv:Uint8Array.from(vault.iv.match(/../g),x=>parseInt(x,16)),
       additionalData:encoder.encode('nostr-book:v1:'+vault.pk)},key,data));
  }catch(e){ throw Error('密码错误或本地密钥数据损坏'); }
}
// IndexedDB 草稿按 npub 隔离。遇到不支持 IndexedDB 时明确提示，不以明文私钥回退。
function dbOpen(){
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open('nostr-book-writer',1);
    req.onupgradeneeded=()=>{if(!req.result.objectStoreNames.contains('drafts'))req.result.createObjectStore('drafts',{keyPath:'pk'});};
    req.onerror=()=>reject(req.error || Error('IndexedDB 不可用'));
    req.onsuccess=()=>resolve(req.result);
  });
}
async function draftIO(pk,text){
  const db=await dbOpen();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction('drafts',text===undefined?'readonly':'readwrite');
    const store=tx.objectStore('drafts');
    const req=text===undefined ? store.get(pk) : store.put({pk,text,updatedAt:Date.now()});
    req.onerror=()=>reject(req.error || Error('草稿保存失败'));
    tx.oncomplete=()=>{resolve(text===undefined ? (req.result?.text || '') : true);db.close();};
    tx.onerror=()=>{db.close();reject(tx.error || Error('草稿数据库错误'));};
  });
}
async function flushDraft(){
  clearTimeout(saveTimer);saveTimer=null;
  if (!activePk) return;
  const pk=activePk, key=draftKey||pk, text=editor.value;
  try{await draftIO(key,text);if(pk===activePk)saveHint.textContent='已保存';return true;}
  catch(e){if(pk===activePk){saveHint.textContent='保存失败';showStatus('本地存储不可用，请先复制文字备份',true);}return false;}
}
const HAN_MIN = 20;
function updateReplyHint(){
  const hint=$('writerHint');
  if(!replyCtx){hint.hidden=true;return;}
  const n=(editor.value.match(/\p{Script=Han}/gu)||[]).length;
  hint.hidden=n>=HAN_MIN;
  hint.textContent='不足二十个汉字的回复会正常发出，但不会收进书里';
}
function scheduleDraft(){
  updateReplyHint();
  saveHint.textContent='保存中…';
  clearTimeout(saveTimer);
  saveTimer=setTimeout(flushDraft,600);
}
function safeRelay(raw){
  try{
    const url=new URL(raw);
    const host=url.hostname.toLowerCase();
    if(url.protocol!=='wss:'||url.username||url.password||!host||
       host==='localhost'||host.endsWith('.local')||/^(127\.|10\.|192\.168\.|169\.254\.)/.test(host)||
       /^172\.(1[6-9]|2\d|3[01])\./.test(host))return null;
    return url.href.replace(/\/$/,'');
  }catch(e){return null;}
}
function writeRelays(pk){
  let hints={}, customized=[];
  try{hints=JSON.parse(localStorage.getItem('book.relayHints.v1'))||{};}catch(e){}
  try{customized=JSON.parse(localStorage.getItem('book.relays'))||[];}catch(e){}
  if(!Array.isArray(customized)) customized=[];
  const defaults=['wss://relay.damus.io','wss://nos.lol','wss://relay.primal.net'];
  return [...new Set([...(Array.isArray(hints[pk])?hints[pk]:[]),...customized,...defaults]
     .map(safeRelay).filter(Boolean))].slice(0,7);
}
function sendRelay(url,event,timeout=12000){
  return new Promise(resolve=>{
    let socket,timer,done=false;
    function finish(ok,reason){
      if(done)return;done=true;clearTimeout(timer);
      try{socket?.close();}catch(e){}
      resolve({url,ok,reason});
    }
    timer=setTimeout(()=>finish(false,'Relay 超时'),timeout);
    try{
      socket=new WebSocket(url);
      socket.onopen=()=>{try{socket.send(JSON.stringify(['EVENT',event]));}catch(e){finish(false,'发送失败');}};
      socket.onmessage=msg=>{
        try{
          const d=JSON.parse(msg.data);
          if(d[0]==='OK' && d[1]===event.id)finish(d[2]===true,String(d[3]||''));
        }catch(e){}
      };
      socket.onerror=()=>finish(false,'无法连接');
      socket.onclose=()=>finish(false,'连接关闭，未收到确认');
    }catch(e){finish(false,'无法建立连接');}
  });
}
function currentReader(){
  const pk=window.bookWriterReader?.();
  return typeof pk==='string' && /^[0-9a-f]{64}$/.test(pk) ? pk : null;
}
function setBusy(value){
  opBusy=value;
  for(const b of [publishButton,importButton,$('writerSaveKey'),$('writerSend'),closeButton])
    b.disabled=value;
}
function updateKeyBadge(){
  importButton.textContent=getVault(activePk)?'私钥':'设置私钥';
}
async function openWriter(ctx=null){
  if(opBusy)return;
  const pk=currentReader();
  if(!pk){showStatus('只读示例不支持发表');return;}
  replyCtx=ctx && /^[0-9a-f]{64}$/.test(ctx.id||'') && /^[0-9a-f]{64}$/.test(ctx.pk||'') ? ctx : null;
  draftKey=replyCtx ? pk+'#reply:'+replyCtx.id : pk;
  $('writerQuote').hidden=!replyCtx;
  if(replyCtx){$('writerQuoteWho').textContent='回 '+(replyCtx.name||'')+'：';$('writerQuoteText').textContent='「'+(replyCtx.text||'')+'」';}
  editor.placeholder=replyCtx?'写下你的回复……':'写点什么……';
  activePk=pk;draftGeneration++;
  editor.value='';showPanel(null);status.textContent='';
  updateKeyBadge();
  overlay.hidden=false;
  $('writerPublished').hidden=true;
  $('writerTitle').textContent=replyCtx?'回复':'随笔';
  updateReplyHint();
  const generation=draftGeneration, key=draftKey;
  try{
    const draft=await draftIO(key);
    if(generation===draftGeneration && pk===activePk){editor.value=draft;updateReplyHint();}
    if(generation===draftGeneration){saveHint.textContent='已保存';editor.focus();}
  }catch(e){showStatus('本地草稿不可用，请先确认浏览器存储权限',true);}
}
function closeWriter(){
  if(opBusy)return;
  draftGeneration++;
  flushDraft();
  overlay.hidden=true;
  showPanel(null);
  secretInput.value='';newPassInput.value='';confirmPassInput.value='';unlockPassInput.value='';
  activePk=null;replyCtx=null;draftKey=null;
  $('writerQuote').hidden=true;$('writerHint').hidden=true;
  window.dispatchEvent(new Event('resize'));
}
async function importKey(){
  if(opBusy)return;
  if(!activePk)return;
  const password=newPassInput.value,confirm=confirmPassInput.value,pk=activePk;
  if(password.length<12){showStatus('请设置至少 12 个字符的加密密码',true);return;}
  if(password!==confirm){showStatus('两次密码不一致',true);return;}
  let sk;
  setBusy(true);
  try{
    if(!crypto?.subtle || !crypto?.getRandomValues)throw Error('当前环境不支持安全加密');
    sk=nsecBytes(secretInput.value);
    const lib=await schnorr();
    const derived=b2h(lib.getPublicKey(sk));
    if(derived!==pk)throw Error('私钥与当前阅读账号不匹配，请先切换到该账号的 npub');
    const vault=await encryptSecret(sk,password,pk);
    localStorage.setItem(vaultKey(pk),JSON.stringify(vault));
    showPanel(null);updateKeyBadge();
    showStatus('私钥已加密保存');
  }catch(e){showStatus(e.message||'私钥设置失败',true);}
  finally{
    sk?.fill(0);
    secretInput.value='';newPassInput.value='';confirmPassInput.value='';
    setBusy(false);
  }
}
async function publish(){
  if(opBusy||!activePk)return;
  const content=editor.value.trim();
  if(!content){showStatus('请先写点什么',true);editor.focus();return;}
  if(content.length>MAX_CONTENT){showStatus('正文过长，请保持在 12000 字符以内',true);return;}
  if(!await flushDraft())return;
  if(!getVault(activePk)){showPanel('setup');showStatus('');secretInput.focus();return;}
  if(!navigator.onLine){showStatus('当前离线，草稿已保存；联网后可发表',true);return;}
  showPanel('unlock');showStatus('');unlockPassInput.focus();
}
async function signAndSend(){
  if(opBusy||!activePk)return;
  const pk=activePk, content=editor.value.trim(),password=unlockPassInput.value;
  if(!password){showStatus('请输入本地解锁密码',true);return;}
  if(!content){showStatus('正文为空',true);return;}
  if(content.length>MAX_CONTENT){showStatus('正文过长',true);return;}
  let sk;
  setBusy(true);
  unlockPassInput.value='';
  try{
    if(!await flushDraft())throw Error('草稿未能保存，请检查本机存储空间');
    const vault=getVault(pk);
    if(!vault)throw Error('签名密钥未设置');
    sk=await decryptSecret(vault,password);
    const lib=await schnorr();
    const actualPk=b2h(lib.getPublicKey(sk));
    if(actualPk!==pk)throw Error('密钥与当前阅读账号不匹配');
    const ctx=replyCtx, key=draftKey||pk;
    const event={kind:1,created_at:Math.floor(Date.now()/1000),tags:[['client','驿书']],content,pubkey:pk};
    if(ctx){
      // 只回这一条，不接整串：普通客户端里就是对这条内容的直接回复
      const hint=(ctx.relays||[]).map(safeRelay).find(Boolean)||'';
      if(ctx.kind===1111 && Array.isArray(ctx.root) && ctx.root.length){
        event.kind=1111;     // NIP-22：根作用域照抄，小写标签指向被回复的这条评论
        event.tags=[...ctx.root.map(t=>t.map(String)),['e',ctx.id,hint,ctx.pk],['k','1111'],(hint?['p',ctx.pk,hint]:['p',ctx.pk]),['client','驿书']];
      }else{
        event.tags=[['e',ctx.id,hint,'root',ctx.pk],(hint?['p',ctx.pk,hint]:['p',ctx.pk]),['client','驿书']];   // NIP-10
      }
    }
    const canonical=JSON.stringify([0,event.pubkey,event.created_at,event.kind,event.tags,event.content]);
    event.id=b2h(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(canonical))));
    const digest=h2b(event.id);
    event.sig=b2h(await lib.signAsync(digest,sk));
    if(!await lib.verifyAsync(Uint8Array.from(event.sig.match(/../g),x=>parseInt(x,16)),digest,Uint8Array.from(pk.match(/../g),x=>parseInt(x,16))))
      throw Error('本地签名校验失败，未发送');
    sk.fill(0);sk=null;
    showPanel(null);showStatus('正在发表…');
    const urls=[...new Set([...writeRelays(pk),...((ctx?.relays)||[]).map(safeRelay).filter(Boolean)])].slice(0,9);
    if(!urls.length)throw Error('没有可用的写入 Relay');
    const result=await Promise.all(urls.map(url=>sendRelay(url,event)));
    if(pk!==activePk)return;
    const ok=result.filter(r=>r.ok).length;
    if(!ok)throw Error('未收到 Relay 接受确认；草稿保留。若网络不稳定，请先检查是否已发布，避免重复发帖');
    // The event has been accepted; display it immediately without waiting for relay echo.
    window.dispatchEvent(new CustomEvent('nostr-book:published', {detail:event}));
    await draftIO(key,'');
    editor.value='';saveHint.textContent='草稿已清空';
    showStatus('发表成功 · '+ok+' 个 Relay 已接收');
    $('writerPublished').hidden=false;
  }catch(e){if(pk===activePk)showStatus(e.message||'发表失败，草稿已保留',true);}
  finally{sk?.fill(0);setBusy(false);}
}
$('writePost').addEventListener('click',()=>openWriter());
window.addEventListener('nostr-book:reply',e=>openWriter(e.detail));
closeButton.addEventListener('click',closeWriter);
editor.addEventListener('input',scheduleDraft);
importButton.addEventListener('click',()=>{showPanel('setup');showStatus('');secretInput.focus();});
$('writerSaveKey').addEventListener('click',importKey);
publishButton.addEventListener('click',publish);
$('writerSend').addEventListener('click',signAndSend);
$('writerPublished').addEventListener('click',()=>{ $('writerPublished').hidden=true;closeWriter(); });
overlay.addEventListener('keydown',e=>{
  if(e.key==='Escape'&&!opBusy){e.preventDefault();closeWriter();}
  if((e.key==='Enter')&&(e.target===unlockPassInput)){e.preventDefault();signAndSend();}
});
