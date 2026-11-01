// 데모 암호화 빌드.
//   DEMO_PASSWORD='...' node build_demos.mjs
//
// private/demos_list.json (원본 경로·표시 제목·분류, 올리지 않음) 을 읽어
//   demos/enc/<id>.bin      — 곡마다 AES-GCM 으로 잠근 mp3 (앞 12바이트가 IV)
//   demos/manifest.json     — 제목 목록 자체도 잠가 둔다 (비번 없이는 곡 이름도 안 보인다)
// 를 만든다. 브라우저(demo.html)는 같은 WebCrypto 로 비번 → 키를 만들어 푼다.
//
// 비밀번호는 어디에도 저장하지 않는다. 같은 비번으로 다시 돌리면 바뀐 곡만 다시 잠근다
// (private/cache.json). 비번을 바꾸면 전부 다시 잠근다.
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import tty from 'node:tty';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const LIST = path.join(HERE, 'private/demos_list.json');
const CACHE = path.join(HERE, 'private/cache.json');
const ENC = path.join(HERE, 'demos/enc');
const MANIFEST = path.join(HERE, 'demos/manifest.json');
const ITER = 600000;

// 비번은 명령줄에 적지 않는다 — 쉘이 ! $ # ( 공백 을 먼저 먹어 node 까지 가지도 못한다.
// 환경변수가 있으면 그대로 쓰고(자동화용), 없으면 터미널에 직접 물어본다. 화면에도 히스토리에도 안 남는다.
function askHidden (prompt) {
  return new Promise ((res, rej) => {
    let fd;
    try { fd = fs.openSync ('/dev/tty', 'r'); }
    catch { return rej (new Error ('터미널이 아니다 — DEMO_PASSWORD 로 넘겨라')); }
    const input = new tty.ReadStream (fd);
    process.stderr.write (prompt);
    input.setRawMode (true);
    let buf = '';
    const done = v => { input.setRawMode (false); input.destroy (); process.stderr.write ('\n'); res (v); };
    input.on ('data', d => {
      for (const ch of d.toString ('utf8')) {
        if (ch === '\r' || ch === '\n') return done (buf);
        if (ch === '\u0003') { input.setRawMode (false); input.destroy (); process.exit (130); }
        if (ch === '\u007f' || ch === '\b') { buf = buf.slice (0, -1); continue; }
        buf += ch;
      }
    });
  });
}

let pw = process.env.DEMO_PASSWORD;
if (!pw) pw = await askHidden ('데모 비밀번호: ');
if (!pw) { console.error ('비밀번호가 없다'); process.exit(1); }

const b64 = u8 => Buffer.from(u8).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

async function deriveKey(salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// 비번이 그대로면 예전 소금을 다시 써야 캐시가 산다 → 예전 매니페스트가 이 비번으로 풀리는지 본다
let salt = null, key = null, cache = {};
if (fs.existsSync(MANIFEST) && fs.existsSync(CACHE)) {
  const m = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const k = await deriveKey(unb64(m.salt));
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(m.iv) }, k, unb64(m.ct));
    salt = unb64(m.salt); key = k; cache = JSON.parse(fs.readFileSync(CACHE, 'utf8'));
  } catch { console.log('비밀번호가 바뀌었다 → 전부 다시 잠근다'); }
}
// 예전 비번과 다르면 전곡이 이 비번으로 다시 잠긴다 — 오타면 사이트가 통째로 안 열린다. 한 번 더 받는다.
if (!key && !process.env.DEMO_PASSWORD) {
  if (await askHidden ('예전 비번과 다르다. 새 비번으로 전부 다시 잠근다 — 한 번 더: ') !== pw) {
    console.error ('두 번 입력이 다르다 — 아무것도 바꾸지 않았다'); process.exit (1);
  }
}
if (!key) { salt = crypto.getRandomValues(new Uint8Array(16)); key = await deriveKey(salt); cache = {}; }

fs.mkdirSync(ENC, { recursive: true });
const list = JSON.parse(fs.readFileSync(LIST, 'utf8'));
const items = [], used = new Set(), newCache = {};
let redone = 0;

for (const e of list) {
  const src = e.src.replace(/^~/, os.homedir());
  const st = fs.statSync(src);
  const sig = `${st.size}:${st.mtimeMs}`;
  let c = cache[src];
  if (!c || c.sig !== sig || !fs.existsSync(path.join(ENC, c.id + '.bin'))) {
    // 영숫자만: GitHub Pages(Jekyll)는 _ 로 시작하는 파일을 빼고 올린다 (Look at You Like That 이 404 났던 이유)
    const id = Buffer.from(crypto.getRandomValues(new Uint8Array(9))).toString('hex');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, fs.readFileSync(src)));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
    fs.writeFileSync(path.join(ENC, id + '.bin'), out);
    c = { id, sig }; redone++;
  }
  newCache[src] = c; used.add(c.id + '.bin');
  items.push({ id: c.id, cat: e.cat, title: e.title, note: e.note || '', t: st.mtimeMs });
}

// 최종 수정이 최신인 곡이 위로 (분류 안에서). 시각 자체는 매니페스트에 안 남긴다
items.sort((a, b) => b.t - a.t);
for (const i of items) delete i.t;

// 연락처(전화번호)도 같이 잠근다 — 원본은 private/contact.json (올리지 않음)
const CONTACT = path.join(HERE, 'private/contact.json');
const contact = fs.existsSync(CONTACT) ? JSON.parse(fs.readFileSync(CONTACT, 'utf8')) : {};

// 목록에서 빠진 곡의 잠긴 파일은 지운다
for (const f of fs.readdirSync(ENC)) if (!used.has(f)) fs.unlinkSync(path.join(ENC, f));

const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key,
  new TextEncoder().encode(JSON.stringify({ items, contact }))));
fs.writeFileSync(MANIFEST, JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
fs.writeFileSync(CACHE, JSON.stringify(newCache, null, 1));

const n = c => items.filter(i => i.cat === c).length;
console.log(`트랙 ${n('track')} · 풀 ${n('full')} · R&B ${n('rnb')} 곡 — 새로 잠근 것 ${redone}`);
