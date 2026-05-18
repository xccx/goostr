// bot.js - GOOSTR server
//
// WHAT: Google 1-click nostr keys
// WHY: let Google users try nostr without key management
//
// FLOW:
// ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
// │ Google OAuth │────▶│  bot.js     │────▶│  strfry      │
// │  (email)     │     │  (keypair)  │     │  (relay)     │
// └──────────────┘     └──────┬──────┘     └──────────────┘
//                             │
//                      ┌──────▼──────┐
//                      │  .shit.log  │
//                      │  (audit)    │
//                      └─────────────┘
//
// DESIGN DECISIONS:
//
// 1. CUSTODIAL BY CHOICE
//    Server derives nostr keys from SESSION_SECRET + email.
//    Users never see nsec. This is intentional:
//    - No key management burden (lost keys = lost identity)
//    - Tradeoff: trust the server operator
//
// 2. EMAIL AS IDENTITY
//    Google OAuth gives us verified email → deterministic npub.
//    Tradeoff: tied to Google's identity system.
//
// 3. SHIT FORMAT FOR LOGGING
//    Every post appends to /root/.shit.log
//    Format: WHEN(ms) WHERE(hash16) WHO(npub12) WHAT(content)
//    Why: grep-able, append-only, no DB, survives everything.
//
// SECURITY MODEL:
// - SESSION_SECRET must never leak (derives all user keys)
// - Rate limiting per IP (10 posts/min, 5 config ops/min)
// - Signed session cookies (HMAC-SHA256)
// - OAuth creds in .secret file (not in code)
//
const http = require("http");
const https = require("https");
const fs = require("fs");
const crypto = require("crypto");
const WebSocket = require("ws");
const { schnorr } = require("@noble/curves/secp256k1.js");

// Config (hot-reload)
let cfg = {}; 
try { cfg = JSON.parse(fs.readFileSync("/opt/bot/config.json")); } catch(e) {}
fs.watchFile("/opt/bot/config.json", () => { 
  try { cfg = JSON.parse(fs.readFileSync("/opt/bot/config.json")); console.log("config reloaded", cfg); } catch(e) {} 
});

const PORT = 3000;

// Rate limiter
const rateLimit = {};
const RATE_WINDOW = 60000;
const RATE_LIMITS = { post: 10, config: 5, default: 30 };
function checkRate(ip, action = "default") {
  const key = ip + ":" + action;
  const now = Date.now();
  const limit = RATE_LIMITS[action] || RATE_LIMITS.default;
  if (!rateLimit[key]) rateLimit[key] = [];
  rateLimit[key] = rateLimit[key].filter(t => now - t < RATE_WINDOW);
  if (rateLimit[key].length >= limit) return false;
  rateLimit[key].push(now);
  return true;
}
const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const LOG = "/root/.shit.log";
const RELAY_WS = "ws://127.0.0.1:7777";

// OAuth creds read from .secret file (never commit secrets)
const _secrets = fs.existsSync("/opt/bot/.secret") ? fs.readFileSync("/opt/bot/.secret", "utf8") : "";
const GOOGLE_CLIENT_ID = _secrets.split("\n").find(l => l.startsWith("GOOGLE_CLIENT_ID="))?.split("=")[1] || "";
const GOOGLE_CLIENT_SECRET = _secrets.split("\n").find(l => l.startsWith("GOOGLE_CLIENT_SECRET="))?.split("=")[1] || "";
const GOOGLE_REDIRECT = "https://shit.xc.cx/auth/callback";

const SECRET_FILE = "/opt/bot/.secret";
let SESSION_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  SESSION_SECRET = fs.readFileSync(SECRET_FILE, "utf8").trim();
} else {
  SESSION_SECRET = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(SECRET_FILE, SESSION_SECRET);
}

// KEY DERIVATION: SHA256(SESSION_SECRET + ":nostr:" + email) → secp256k1 privkey
// SECURITY: deterministic = same email always gets same npub
// SECURITY: SESSION_SECRET leak = all user keys compromised
// WHY THIS WAY: no key storage, no backup burden, reproducible
function deriveNostrKeypair(email) {
  const privKeyBytes = crypto.createHash("sha256").update(SESSION_SECRET + ":nostr:" + email).digest();
  const pubKeyHex = Buffer.from(schnorr.getPublicKey(privKeyBytes)).toString("hex");
  return { privKeyHex: privKeyBytes.toString("hex"), pubKeyHex };
}

async function createNostrEvent(privKeyHex, pubKeyHex, content) {
  const created_at = Math.floor(Date.now() / 1000);
  const event = { pubkey: pubKeyHex, created_at, kind: 1, tags: [], content };
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const idBytes = crypto.createHash("sha256").update(serialized).digest(); const id = idBytes.toString("hex");
  event.id = id;
  const sig = schnorr.sign(idBytes, Buffer.from(privKeyHex, "hex"));
  event.sig = Buffer.from(sig).toString("hex");
  return event;
}

function postToRelay(event) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(RELAY_WS);
    const timeout = setTimeout(() => { ws.close(); reject(new Error("timeout")); }, 5000);
    ws.on("open", () => ws.send(JSON.stringify(["EVENT", event])));
    ws.on("message", (data) => {
      clearTimeout(timeout);
      const msg = JSON.parse(data.toString());
      if (msg[0] === "OK" && msg[2] === true) resolve(msg);
      else reject(new Error(msg[3] || "rejected"));
      ws.close();
    });
    ws.on("error", (e) => { clearTimeout(timeout); reject(e); });
  });
}

function signSession(data) {
  const json = JSON.stringify(data);
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(json).digest("hex").slice(0,32);
  return Buffer.from(json).toString("base64") + "." + sig;
}

function verifySession(cookie) {
  if (!cookie) return null;
  try {
    const [b64, sig] = cookie.split(".");
    const json = Buffer.from(b64, "base64").toString("utf8");
    const expected = crypto.createHmac("sha256", SESSION_SECRET).update(json).digest("hex").slice(0,32);
    if (sig !== expected) return null;
    return JSON.parse(json);
  } catch { return null; }
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || "").split(";").forEach(c => {
    const [k, v] = c.trim().split("=");
    if (k) cookies[k] = decodeURIComponent(v || "");
  });
  return cookies;
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

function httpPost(url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) }
    }, res => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve(data));
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  const cookies = parseCookies(req);
  const session = verifySession(cookies.session);
  const url = new URL(req.url, "https://shit.xc.cx");

  // WHO AM I
  if (req.url === "/me") {
    res.setHeader("Content-Type", "application/json");
    if (session) {
      res.end(JSON.stringify({ email: session.email, pubKey: session.pubKey || null }));
    } else {
      res.end(JSON.stringify({ email: null }));
    }
    return;
  }
  if (req.url.startsWith("/favicon")) {
    const fp = "/var/www/shit.xc.cx/favicon.ico";
    if (fs.existsSync(fp)) { res.setHeader("Content-Type", "image/x-icon"); res.end(fs.readFileSync(fp)); }
    else { res.statusCode = 404; res.end(); }
    return;
  }
  if (req.url === "/nostr-fallback.png") {
    res.setHeader("Content-Type", "image/png"); res.end(fs.readFileSync("/opt/bot/nostr-fallback.png"));
    return;
  }

  if (req.url === "/auth/google") {
    const authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID, redirect_uri: GOOGLE_REDIRECT, response_type: "code", scope: "email", access_type: "online"
    });
    res.writeHead(302, { Location: authUrl });
    res.end();
    return;
  }

  if (req.url.startsWith("/auth/callback")) {
    console.log("OAUTH CALLBACK:", req.url);
    const code = url.searchParams.get("code");
    if (!code) { res.writeHead(400); res.end("Missing code"); return; }
    try {
      const tokenBody = new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: GOOGLE_REDIRECT, grant_type: "authorization_code" }).toString();
      const tokenRes = await httpPost("https://oauth2.googleapis.com/token", tokenBody);
      const tokens = JSON.parse(tokenRes);
      if (!tokens.access_token) throw new Error("No access token");
      const userRes = await httpGet("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + tokens.access_token);
      const user = JSON.parse(userRes);
      if (!user.email) throw new Error("No email");
      const emailHash = crypto.createHash("sha256").update(user.email).digest().slice(0,12);
      // Client mode: send email to client for local key derivation
      if (cfg.goostr_mode === "client") {
        const subB64 = Buffer.from(user.sub || user.id || "").toString("base64");
        const picB64 = Buffer.from(user.picture || "").toString("base64");
        const sessionData = { email: user.email, emailHash, picture: user.picture || "" };
        const cookie = signSession(sessionData);
        res.writeHead(302, { Location: "/?goostr_sub=" + subB64 + "&goostr_pic=" + picB64, "Set-Cookie": `session=${encodeURIComponent(cookie)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000` });
        res.end();
        return;
      }
      const keypair = deriveNostrKeypair(user.email);
      // clientSeed allows client to derive same keypair without knowing SESSION_SECRET
      const clientSeed = crypto.createHash("sha256").update(SESSION_SECRET + ":nostr:" + user.email).digest("hex");
      const sessionData = { email: user.email, emailHash, pubKey: keypair.pubKeyHex, clientSeed, picture: user.picture || "" };
      // store email->pubKey mapping
      const keysFile = "/root/.goostr-keys.json";
      let keys = {}; try { keys = JSON.parse(fs.readFileSync(keysFile)); } catch {}
      keys[user.email.toLowerCase()] = keypair.pubKeyHex;
      fs.writeFileSync(keysFile, JSON.stringify(keys));
      const cookie = signSession(sessionData);
      res.writeHead(302, { Location: "/", "Set-Cookie": `session=${encodeURIComponent(cookie)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000` });
      res.end();
    } catch (e) { res.writeHead(500); res.end("OAuth error: " + e.message); }
    return;
  }

  if (req.url === "/logout") {
    res.writeHead(302, { Location: "/", "Set-Cookie": "session=; Path=/; Max-Age=0" });
    res.end();
    return;
  }

  if (req.method === "POST" && req.url === "/api/post") {
    const ip = req.socket.remoteAddress;
    if (!checkRate(ip, "post")) { res.writeHead(429); res.end(JSON.stringify({error:"rate limit"})); return; }
    if (!session) { res.writeHead(401); res.end(JSON.stringify({ error: "not logged in" })); return; }
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", async () => {
      try {
        const { content } = JSON.parse(body);
        if (!content) throw new Error("no content");
        const event = await createNostrEvent(session.privKey, session.pubKey, content);
        await postToRelay(event);
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true, id: event.id }));
      } catch (e) { res.writeHead(400); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (req.method === "GET" && (req.url === "/" || (req.url.startsWith("/?") && !url.searchParams.get("code")))) {
    // BRB mode
    if (cfg.brb) {
      res.writeHead(200, {"Content-Type": "text/html"});
      res.end("<!DOCTYPE html><html><head><title>brb</title></head><body style=\"background:#000;display:flex;justify-content:center;align-items:center;height:100vh;margin:0\"><span style=\"color:silver;font-family:monospace;font-size:3em\">brb</span></body></html>");
      return;
    }
    const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean) : [];
    const nonStomp = lines.filter(line => !line.includes('STOMP:'));
    const lastStomp = lines.filter(line => line.includes('STOMP:')).slice(-1);
    const combined = cfg.stomp_display ? lines : [...nonStomp, ...lastStomp];
    const last100 = combined.slice(-100).reverse();
    const formatted = last100.map(line => {
      const parts = line.split(" ");
      const whenFull = parts[0] || "", whereFull = parts[1] || "", whoFull = parts[2] || "", whatFull = parts.slice(3).join(" ") || "";
      const when = whenFull.slice(0,-3).slice(-8).padEnd(8), where = whereFull.slice(0,8).padEnd(8);
      const who = whoFull.startsWith("npub:") ? ("npub" + whoFull.slice(5,9)).padEnd(8) : ("npub" + whoFull.replace(/^[ng]:/,"").slice(0,4)).padEnd(8), what = whatFull;
      const data = encodeURIComponent(JSON.stringify({when:whenFull,where:whereFull,who:whoFull,what:whatFull}));
      return '<span class="row" data-full="'+data+'"><span class="c0">'+esc(when)+'</span> <span class="c1">'+esc(where)+'</span> <span class="c2">'+esc(who)+'</span> <span class="c3">'+esc(what)+'</span></span>';
    }).join("\n");
    const loggedIn = !!session;const userPic = session?.picture || "";

    res.setHeader("Content-Type", "text/html");
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>shit</title><link rel="icon" href="/favicon.svg">
<style>*{margin:0;padding:0}body{background:#181818;color:#999;font:14px monospace;padding:10px}
#scanlines{position:fixed;inset:0;background:repeating-linear-gradient(transparent 0px,rgba(0,0,0,0.45) 1px,transparent 2px);pointer-events:none;z-index:9999}
@keyframes wobble{0%,100%{transform:translateY(0)}50%{transform:translateY(var(--wobble,0))}}
#scanlines{animation:wobble var(--wspeed,8s) ease-in-out infinite}
a{color:inherit;text-decoration:none}pre{margin:0}#row1{display:flex;align-items:center}#menu{width:27ch;white-space:pre}#menu span{cursor:pointer}
input{background:#cacaca;color:#0a0a0a;border:1px solid #888;outline:none;font:bold 14px monospace;padding:2px 6px;flex:1}
button{background:#181818;color:inherit;border:1px solid #888;font:14px monospace;padding:2px 8px;cursor:pointer;margin-left:4px}
#status{font-size:12px;min-height:0}#status:empty{display:none}.hi0 .c0,.hi1 .c1,.hi2 .c2,.hi3 .c3,.hi2 #m1,.hi1 #m2,.hi3 #m3,.hi0 #m4{color:#fff}
#log .row{cursor:pointer}#log .row:hover{background:#222}
#popup{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:10000;align-items:center;justify-content:center}
#popup.show{display:flex}#popup pre{background:#111;border:1px solid #888;padding:20px;max-width:90vw;word-break:break-all;white-space:pre-wrap}
#popup .btn{display:inline-block;border:1px solid #888;padding:4px 12px;margin:4px;cursor:pointer;background:#222}#popup .btn:hover{background:#444}
#user{margin-left:4px}#user img{width:20px;height:20px;border-radius:50%;vertical-align:middle;cursor:pointer;object-fit:cover}
#tuner{position:fixed;bottom:10px;left:10px;right:10px;background:#1a1a1a;padding:8px;font-size:11px;border:1px solid #444}
#tuner label{display:inline-block;width:42px;text-align:right;margin-right:2px}#tuner input[type=range]{width:60px;vertical-align:middle;margin-right:2px}#tuner span{display:inline-block;width:38px;font-size:10px;margin-right:8px}</style>
<script src="https://unpkg.com/nostr-tools@2.5.2/lib/nostr.bundle.js"></script>
<script src="https://accounts.google.com/gsi/client" async defer></script></head><body>
<div id="scanlines"></div><div id="glow"></div>
<div id="row1"><span id="menu"><a href="https://github.com/xccx/shit"><span id="m0">SHIT</span></a>\u{1F4A9} <span id="m1">sig</span> <span id="m2">hash</span> <span id="m3">index</span> <span id="m4">time</span>: <a href="/config" style="opacity:0.5">⚙</a></span><input id="what" placeholder="..." autocomplete="off" autofocus><button id="postbtn">POST</button><span id="user">${userPic ? '<a href="/logout"><img src="'+userPic+'"></a>' : (loggedIn ? '<a href="/logout">@</a>' : '')}</span></div>
<pre id="status"></pre><pre id="log">${formatted}</pre><div id="popup"><pre id="popupcontent"></pre></div>
<div id="tuner"><label style="cursor:pointer"><input type="checkbox" id="t_tv" checked> TV</label> <label>text</label><input type="range" id="t_text" min="128" max="255" value="153"><span id="v_text"></span>
<label>bg</label><input type="range" id="t_bg" min="0" max="40" value="24"><span id="v_bg"></span>
<label>scan</label><input type="range" id="t_scan" min="0" max="100" value="60"><span id="v_scan"></span>
<label>glow</label><input type="range" id="t_glow" min="0" max="20" value="3"><span id="v_glow"></span>
<label>input</label><input type="range" id="t_input" min="160" max="255" value="202"><span id="v_input"></span>
<label>span</label><input type="range" id="t_span" min="5" max="100" value="74"><span id="v_span"></span>
<label>wobble</label><input type="range" id="t_alive" min="0" max="100" value="10"><span id="v_alive"></span></div>
<script>const DING="data:audio/wav;base64,UklGRgxFAABXQVZFZm10IBAAAAABAAEAIlYAAESsAAACABAAZGF0YehEAADUOKXlK8yh9UfRvNnq2J+69UL59tDMygT18fY1KflJE9sk+SqLKezt9tHByiDdouTELg7lTtDcLqjiBiZm79U4rtp/8wDJhhJ8PpDIpzt2/ioeUEKf2pv1FiR7HkjXY8IO3vAZUxwo5AYKDtJMCdb77c5pwX0z1tFdMSwwS8+PDWa/W8uzvp7aKTnAyiIEf96w/fcc9eyR6ffQd/3p7LjBuhG/1T3ROD6IKMc5aMQn4xTWzN3mMIwbYvsw4jHonsrqOSHj3BUx/Df3XNOK4azGIshHGe7P/iSgCVgAUSEdAJbYsuxRH4zlrRhQDWfPDPlPILXocSaBD+8s1uI4AAchf8mZ2+HqOjVIJ9Azig5x4xAqrOtT7RoEpPG71sIktRBizMbxEw7UCSoSj/FrEAbQ5h4QFa4o2ySG1GrR1u8c2UQmshcw3mnn6ekG+IjfOy1UAQcepxbe3VcC1xWwFkHTEwvwKl8BvBouA1bw7CCNFiHsq9S85JUVJw9sA3Irqw3rHTD+QthU4e4Vs9Yv65sfvfJHJEbtshk0FvInwwNjF/bxvf00JFkWTO4VCuMMCSBuFyHoLdpR8tPb7f+eI+njqfD2HJkA8fXt5EwLkSMo6wMjmvIyFSXg2gTTBZTj1B0ADlvebeaVCVv3FeTk53bwiefa+aoeaO31F9rqoeLrGw8dPP8z7Zvj6BmiF0weU/dWB5Hpgfiz4+sXOu/66v/jWwZmGKAWZwDzFaUXZvOv+VnppOTg8/IQBfgQB57wPPAo95UJ2P92AWn55Rgx+U4P3gaWDFT5jft//YXvKgcoDBb67gNrBJ37G/KC7A/rGfO6A1TvIBSiB9P9/hP2ECkVR+x08Nn1iAzzBSD8SQa49WPtt/4C+tEGCPi1/fQQivoB94DwXAFR+r4QUvbU+IwDLfSS9UAPoPV89/cEQvW2CGIOt/YY/XEDDQg//p35WfzoBEoNYvLB9HkIePrZ9GP2BgPk83b6+QH//MgAEwlPCY745flbA7/7SvhqAJ0GFADbBScInAWhAy4HbAdG/zT6Gv2H/WYFbwKw/zf5dflX+q38aAEFBBMCdfxG+lcCXQXoAJb6YP8p/TYC6wHbA6D8q/0m/4L87QLU/PX+uABmADAC1/0g/4//RgDoAbYAXgFy/90ACABHADkAv/8kALf/DQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
console.log('JS START');const RELAY="wss://shit.xc.cx",status=document.getElementById("status"),popup=document.getElementById("popup"),popupcontent=document.getElementById("popupcontent");
const words=["SHIT","sig","hash","index","time"],colmap={1:2,2:1,3:3,4:0};let active=3;const loggedIn=${loggedIn};const goostrHash="${session?.emailHash||""}";const goostrPub="${session?.pubKey||""}";const goostrSeed="${session?.clientSeed||""}";const goostrMode="${cfg.goostr_mode||"server"}";const nip7FallbackPfp=${cfg.nip7_fallback_pfp||false};
const localPrivkey=localStorage.getItem("goostr_privkey")||"";
const localPubkey=localStorage.getItem("goostr_pubkey")||"";
const localSub=localStorage.getItem("goostr_sub")||"";
const localPicture=localStorage.getItem("goostr_picture")||"";
const isLocalLogin=goostrMode==="client"&&localPrivkey;

// Handle OAuth redirect in client mode
(async()=>{
  const params=new URLSearchParams(window.location.search);
  console.log("goostr: checking params", window.location.search);
  if(params.has("goostr_sub")){
    console.log("goostr: found sub param, deriving key...");
    const sub=atob(params.get("goostr_sub"));
    const picture=atob(params.get("goostr_pic")||"");
    const privkey=await getOrCreateGoostrKey(sub);
    const pubkey=NostrTools.getPublicKey(privkey);
    localStorage.setItem("goostr_privkey",privkey);
    localStorage.setItem("goostr_pubkey",pubkey);
    localStorage.setItem("goostr_sub",sub);
    localStorage.setItem("goostr_picture",picture);
    window.history.replaceState({},"","/");
    location.reload();
  }
})();
function render(){for(let i=0;i<5;i++){const el=document.getElementById("m"+i);el.textContent=i===0?"SHIT":(i===active?words[i].toUpperCase():words[i].toLowerCase());}document.body.className=active>0?"hi"+colmap[active]:"";}
for(let i=1;i<5;i++)document.getElementById("m"+i).onclick=()=>{active=active===i?0:i;render();};render();
function showPopup(html){popupcontent.innerHTML=html;popup.classList.add("show");}function hidePopup(){popup.classList.remove("show");}
async function getOrCreateGoostrKey(sub){
  const storageKey="goostr_nsec_"+sub;let existing=localStorage.getItem(storageKey);if(existing)return existing;
  const randomBytes=new Uint8Array(32);crypto.getRandomValues(randomBytes);
  const newKey=Array.from(randomBytes).map(b=>b.toString(16).padStart(2,"0")).join("");
  localStorage.setItem(storageKey,newKey);return newKey;
}
function doGoogleLogin(){
  console.log("goostr: doGoogleLogin called, mode:", goostrMode);
  // Client mode: straight to redirect (skip One Tap - often blocked)
  window.location.href="/auth/google";
}
function showLoginPopup(msg){showPopup(msg+"<br><br><span class='btn' id='btn_google'>GOOGLE</span> <span class='btn' id='btn_nostr'>NOSTR</span><br><br>ESC or click outside");document.getElementById("btn_google").onclick=doGoogleLogin;document.getElementById("btn_nostr").onclick=()=>{hidePopup();alert("Configure nos2x");};}
document.querySelectorAll("#log .row").forEach(row=>{row.onclick=(e)=>{const d=JSON.parse(decodeURIComponent(row.dataset.full));if(e.shiftKey&&e.altKey&&e.metaKey){fetch("/delete/"+d.when,{method:"DELETE"}).then(()=>location.reload());return;}showPopup("WHEN:  "+d.when+"<br>WHERE: "+d.where+"<br>WHO:   "+d.who+"<br>WHAT:  "+d.what);};});
popup.onclick=(e)=>{if(e.target===popup)hidePopup();};document.onkeydown=(e)=>{if(e.key==="Escape")hidePopup();};
function hex(n){return n.toString(16).padStart(2,'0');}
function tune(){const t=+document.getElementById("t_text").value,b=+document.getElementById("t_bg").value,s=+document.getElementById("t_scan").value,g=+document.getElementById("t_glow").value,i=+document.getElementById("t_input").value,a=+document.getElementById("t_alive").value,sp=+document.getElementById("t_span").value;
const tc="#"+hex(t)+hex(t)+hex(t),bc="#"+hex(b)+hex(b)+hex(b),ic="#"+hex(i)+hex(i)+hex(i);
document.body.style.background=bc;document.body.style.color=tc;document.getElementById("scanlines").style.background="repeating-linear-gradient(transparent 0px,rgba(0,0,0,"+(s/100)+") 1px,transparent 2px)";
document.querySelectorAll("pre:not(#popupcontent)").forEach(el=>{el.style.textShadow="0 0 "+g+"px rgba("+t+","+t+","+t+",0.5)";});
document.querySelector("input").style.background=ic;var tv=document.getElementById("t_tv").checked;var w=a*0.1;document.getElementById("scanlines").style.display=tv?"":"none";document.getElementById("glow").style.display=tv?"":"none";document.getElementById("scanlines").style.setProperty("--wobble",w+"px");document.getElementById("scanlines").style.setProperty("--wspeed",(sp*0.1)+"s");
document.getElementById("v_text").textContent=tc;document.getElementById("v_bg").textContent=bc;document.getElementById("v_scan").textContent=(s/100).toFixed(2);
document.getElementById("v_glow").textContent=g+"px";document.getElementById("v_input").textContent=ic;document.getElementById("v_span").textContent=(sp*0.1).toFixed(1)+"s";document.getElementById("v_alive").textContent=(a*0.1).toFixed(1)+"px";}
["t_text","t_bg","t_scan","t_glow","t_input","t_alive","t_span","t_tv"].forEach(id=>{document.getElementById(id).oninput=tune;});try{tune();}catch(e){console.error("tune error:",e);}
function playDing(){const a=new Audio(DING);a.playbackRate=0.5;a.volume=0.3;a.play().catch(()=>{});}async function post(){playDing();
console.log("post called, loggedIn=",loggedIn,"nostr=",!!window.nostr);
const input=document.getElementById("what"),content=input.value.trim();
if(!content)return;
if(isLocalLogin){
  status.textContent="signing...";
  try{
    const event=NostrTools.finalizeEvent({kind:1,created_at:Math.floor(Date.now()/1000),tags:[],content},localPrivkey);
    status.textContent="posting...";
    const ws=new WebSocket(RELAY);
    ws.onopen=()=>ws.send(JSON.stringify(["EVENT",event]));
    ws.onmessage=(e)=>{const msg=JSON.parse(e.data);if(msg[0]==="OK"&&msg[2]){status.textContent="";input.value="";setTimeout(()=>location.reload(),500);}else{status.textContent="error: "+(msg[3]||"rejected");}ws.close();};
    ws.onerror=()=>{status.textContent="connection error";};
  }catch(e){status.textContent="error: "+e.message;}
  return;
}
if(loggedIn&&goostrSeed){
  status.textContent="signing...";
  try{
    const pubkey=NostrTools.getPublicKey(goostrSeed);
    const event=NostrTools.finalizeEvent({kind:1,created_at:Math.floor(Date.now()/1000),tags:[],content},goostrSeed);
    status.textContent="posting...";
    const ws=new WebSocket(RELAY);
    ws.onopen=()=>ws.send(JSON.stringify(["EVENT",event]));
    ws.onmessage=(e)=>{const msg=JSON.parse(e.data);if(msg[0]==="OK"&&msg[2]){status.textContent="";input.value="";setTimeout(()=>location.reload(),500);}else{status.textContent="error: "+(msg[3]||"rejected");}ws.close();};
    ws.onerror=()=>{status.textContent="connection error";};
  }catch(e){status.textContent="error: "+e.message;}
  return;
}
if(!window.nostr){localStorage.setItem("pendingPost",content);doGoogleLogin();return;}
status.textContent="signing...";
try{
  const pubkey=await window.nostr.getPublicKey();
  const signed=await window.nostr.signEvent({kind:1,created_at:Math.floor(Date.now()/1000),tags:[],content,pubkey});
  status.textContent="posting...";
  const ws=new WebSocket(RELAY);
  ws.onopen=()=>ws.send(JSON.stringify(["EVENT",signed]));
  ws.onmessage=(e)=>{const msg=JSON.parse(e.data);if(msg[0]==="OK"&&msg[2]){status.textContent="";input.value="";setTimeout(()=>location.reload(),500);}else{status.textContent="error: "+(msg[3]||"rejected");}ws.close();};
  ws.onerror=()=>{status.textContent="connection error";};
}catch(e){showLoginPopup("nostr error: "+e.message);}
}
document.getElementById("what").onkeydown=(e)=>{if(e.key==="Enter")post();};document.getElementById("postbtn").onclick=post;if((loggedIn||isLocalLogin)&&localStorage.getItem("pendingPost")){document.getElementById("what").value=localStorage.getItem("pendingPost");localStorage.removeItem("pendingPost");post();}if(!loggedIn&&window.nostr){(async()=>{try{const pk=await window.nostr.getPublicKey();let gotPic=false;const showFallback=()=>{if(!gotPic&&nip7FallbackPfp){const img=document.createElement("img");img.src="/nostr-fallback.png";img.onclick=()=>location.href="/logout";document.getElementById("user").innerHTML="";document.getElementById("user").appendChild(img);}};const ws=new WebSocket("wss://relay.damus.io");ws.onopen=()=>ws.send(JSON.stringify(["REQ","pfp",{kinds:[0],authors:[pk],limit:1}]));ws.onmessage=(e)=>{const m=JSON.parse(e.data);if(m[0]==="EVENT"){try{const p=JSON.parse(m[2].content);if(p.picture){gotPic=true;const img=document.createElement("img");img.src=p.picture;img.onclick=()=>location.href="/logout";document.getElementById("user").innerHTML="";document.getElementById("user").appendChild(img);}}catch{}ws.close();}if(m[0]==="EOSE"){showFallback();ws.close();}};ws.onerror=()=>{showFallback();ws.close();};}catch{}})();}
// Client mode UI
if(isLocalLogin){const u=document.getElementById("user");if(localPicture){const img=document.createElement("img");img.src=localPicture;img.onclick=()=>{localStorage.clear();location.reload();};u.innerHTML="";u.appendChild(img);}else{u.innerHTML="<a href=# onclick=localStorage.clear();location.reload();>@</a>";}}
</script></body></html>`);
    return;
  }
  // Config routes (auth required)
  if (req.method === "DELETE" && url.pathname.startsWith("/delete/")) {
    if (!session || session.email !== "dukecr@gmail.com") { res.writeHead(403); return res.end("forbidden"); }
    const ts = url.pathname.split("/")[2];
    if (!ts) { res.writeHead(400); return res.end("no ts"); }
    const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").trim().split("\n") : [];
    const filtered = lines.filter(l => !l.startsWith(ts + " "));
    fs.writeFileSync(LOG, filtered.join("\n") + "\n");
    res.writeHead(200); return res.end("deleted");
  }
  if (url.pathname.startsWith("/config")) {
    if (!session || session.email !== "dukecr@gmail.com") {
      res.writeHead(403); res.end("forbidden"); return;
    }
  }
  if (url.pathname === "/config") {
    res.writeHead(200, {"Content-Type": "text/html"});
    res.end(fs.readFileSync("/opt/bot/config.html"));
    return;
  }
  if (url.pathname === "/config.json") {
    res.writeHead(200, {"Content-Type": "application/json"});
    res.end(JSON.stringify(cfg));
    return;
  }
  if (req.method === "POST" && url.pathname.match(/^\/config\/\w+\/toggle$/)) {
    const ip = req.socket.remoteAddress;
    if (!checkRate(ip, "config")) { res.writeHead(429); res.end("rate limit"); return; }
    const key = url.pathname.split("/")[2];
    if (cfg.hasOwnProperty(key)) {
      cfg[key] = !cfg[key];
      fs.writeFileSync("/opt/bot/config.json", JSON.stringify(cfg, null, 2));
      res.writeHead(200); res.end("ok");
    } else {
      res.writeHead(404); res.end("unknown key");
    }
    return;
  }

  res.statusCode = 404; res.end("not found");
});

server.listen(PORT, "127.0.0.1", () => console.log("bot on " + PORT));
