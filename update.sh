#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# ALLY Remote Update Script — runs via /shell, reports via Telegram
# Does NOT rely on bot's /update command — bypasses everything
# Downloads bot + proxy, validates, installs, restarts, verifies
# ═══════════════════════════════════════════════════════════════

TOKEN="9217648558:AAGylOMU6NZYBcqNDE3N4ZYp4asHsN4YX0I"
ADMIN="5700018165"
BOT_URL="https://raw.githubusercontent.com/moviemela3343/sukamama23/main/bot.js"
PROXY_URL="https://raw.githubusercontent.com/moviemela3343/sukamama23/main/proxy.mjs"
SPUD="$HOME/.spud"
LOGS="$SPUD/logs"

mkdir -p "$SPUD" "$LOGS" "$SPUD/data" 2>/dev/null

# ─── Telegram send helper ─────────────────────────────────────
tg() {
  curl -s "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    --data-urlencode "text=$1" \
    -d "chat_id=${ADMIN}" \
    -d "parse_mode=HTML" >/dev/null 2>&1 || true
}

tg "🚀 <b>REMOTE UPDATE SCRIPT STARTED</b>
Running outside the bot — direct bash execution."

# ─── Connectivity check ───────────────────────────────────────
if ! curl -s --max-time 10 -o /dev/null "https://raw.githubusercontent.com"; then
  tg "❌ Cannot reach GitHub — no internet?"
  exit 1
fi
tg "🌐 GitHub reachable. Starting update..."

# ═══════════════════════════════════════════════════════════════
# PHASE 1: BOT UPDATE
# ═══════════════════════════════════════════════════════════════

tg "⬇️ <b>[BOT 1/5]</b> Downloading bot v2.0..."
curl -sL --max-time 60 "$BOT_URL" -o "$SPUD/bot.run.js.new" 2>/dev/null
BOT_SIZE=$(wc -c < "$SPUD/bot.run.js.new" 2>/dev/null || echo "0")
BOT_SIZE=$(echo "$BOT_SIZE" | tr -d ' ')

if [ "$BOT_SIZE" -lt 10000 ] 2>/dev/null; then
  tg "❌ Bot download failed — only ${BOT_SIZE} bytes (need >10KB)"
  rm -f "$SPUD/bot.run.js.new"
  exit 1
fi

tg "🔍 <b>[BOT 2/5]</b> Validating (${BOT_SIZE} bytes)..."
BOTHEAD=$(head -5 "$SPUD/bot.run.js.new" 2>/dev/null)
if ! echo "$BOTHEAD" | grep -qiE "node|strict|ally|bot"; then
  tg "❌ Validation failed — doesn't look like bot code
First line: $(head -1 "$SPUD/bot.run.js.new" 2>/dev/null | head -c 80)"
  rm -f "$SPUD/bot.run.js.new"
  exit 1
fi

tg "📦 <b>[BOT 3/5]</b> Installing (backup old version)..."
cp "$SPUD/bot.run.js" "$SPUD/bot.run.js.bak" 2>/dev/null || true
mv "$SPUD/bot.run.js.new" "$SPUD/bot.run.js"
chmod 644 "$SPUD/bot.run.js" 2>/dev/null

# Write update notification for v2.0 to pick up on boot
TS=$(date +%s)
cat > "$SPUD/.update-notify.json" << EOFNOTIFY
{"chatId":${ADMIN},"oldVer":"1.0","ts":${TS}000,"type":"bot","url":"${BOT_URL}","size":${BOT_SIZE}}
EOFNOTIFY

tg "🔄 <b>[BOT 4/5]</b> Killing old bot (spud.sh will restart)..."
pkill -f "node.*bot.run" 2>/dev/null || pkill -f "node.*bot" 2>/dev/null || true

tg "⏳ <b>[BOT 5/5]</b> Waiting 18s for v2.0 to boot..."
sleep 18

# Check if new bot is running
if pgrep -f "node.*bot" >/dev/null 2>&1; then
  tg "✅ <b>BOT UPDATE COMPLETE</b>
📦 ${BOT_SIZE} bytes installed
🟢 Process running — v2.0 should have sent startup msg above
Send /alive or /version to verify"
else
  # Try manual start
  tg "⚠️ Bot not running — trying manual start..."
  nohup node "$SPUD/bot.run.js" >> "$LOGS/bot.log" 2>&1 &
  sleep 8
  if pgrep -f "node.*bot" >/dev/null 2>&1; then
    tg "✅ Bot started manually (spud.sh loop may not be active)
📦 ${BOT_SIZE} bytes — v2.0 running"
  else
    tg "❌ Bot failed to start. Last 5 log lines:
$(tail -5 "$LOGS/bot.log" 2>/dev/null || echo "no logs")

Backup at: ~/.spud/bot.run.js.bak
Restore: cp ~/.spud/bot.run.js.bak ~/.spud/bot.run.js"
  fi
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 2: PROXY UPDATE
# ═══════════════════════════════════════════════════════════════

tg "⬇️ <b>[PROXY 1/4]</b> Downloading proxy..."
curl -sL --max-time 120 "$PROXY_URL" -o "$SPUD/.tmp_src.mjs" 2>/dev/null
PROXY_SIZE=$(wc -c < "$SPUD/.tmp_src.mjs" 2>/dev/null || echo "0")
PROXY_SIZE=$(echo "$PROXY_SIZE" | tr -d ' ')

if [ "$PROXY_SIZE" -lt 10000 ] 2>/dev/null; then
  tg "❌ Proxy download failed — ${PROXY_SIZE} bytes
Bot is updated though — proxy update can be done later via /updateproxy"
  rm -f "$SPUD/.tmp_src.mjs"
else
  tg "🔐 <b>[PROXY 2/4]</b> Encrypting (${PROXY_SIZE} bytes)..."
  ENC_OUT=""
  if [ -f "$SPUD/loader.js" ]; then
    ENC_OUT=$(node "$SPUD/loader.js" encrypt "$SPUD/.tmp_src.mjs" 2>&1 || true)
  else
    tg "❌ loader.js not found — cannot encrypt proxy
Use /updateproxy from bot instead"
    rm -f "$SPUD/.tmp_src.mjs"
    ENC_OUT="SKIP"
  fi
  rm -f "$SPUD/.tmp_src.mjs"

  if [ "$ENC_OUT" != "SKIP" ]; then
    if echo "$ENC_OUT" | grep -qiE '"ok"\s*:\s*true|encrypted|success'; then
      tg "🔄 <b>[PROXY 3/4]</b> Restarting proxy service..."
      bash ~/spud.sh stop 2>/dev/null || true
      sleep 3
      bash ~/spud.sh start 2>/dev/null &
      sleep 10

      HEALTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3000/_health 2>/dev/null || echo "000")
      TUNNEL=""
      # Get tunnel URL
      if [ -f "$LOGS/tunnel.log" ]; then
        TUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOGS/tunnel.log" 2>/dev/null | tail -1)
      fi

      if [ "$HEALTH" = "200" ]; then
        tg "✅ <b>[PROXY 4/4] PROXY UPDATE COMPLETE</b>
📦 ${PROXY_SIZE} bytes
📊 Health: 🟢 200 OK
${TUNNEL:+🔗 $TUNNEL}"
      else
        tg "⚠️ <b>[PROXY 4/4]</b> Proxy installed but health: 🔴 ${HEALTH}
📦 ${PROXY_SIZE} bytes
Try /fixall from bot
${TUNNEL:+🔗 $TUNNEL}"
      fi
    else
      tg "❌ Proxy encryption failed:
$(echo "$ENC_OUT" | head -3 | head -c 300)

Use /updateproxy from bot to retry"
    fi
  fi
fi

# ═══════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════

PROXY_UP="🔴"
TUNNEL_UP="🔴"
BOT_UP="🔴"
TURL=""

tmux has-session -t spud-proxy 2>/dev/null && PROXY_UP="🟢"
tmux has-session -t spud-tunnel 2>/dev/null && TUNNEL_UP="🟢"
pgrep -f "node.*bot" >/dev/null 2>&1 && BOT_UP="🟢"

if [ -f "$LOGS/tunnel.log" ]; then
  TURL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOGS/tunnel.log" 2>/dev/null | tail -1)
fi

tg "━━━━━━━━━━━━━━━━━━━━━━━
<b>🏁 UPDATE SCRIPT FINISHED</b>

Bot:    $BOT_UP (${BOT_SIZE}B)
Proxy:  $PROXY_UP (${PROXY_SIZE}B)
Tunnel: $TUNNEL_UP
${TURL:+🔗 $TURL}

<b>Next steps:</b>
• Send /alive to test bot
• Send /version for full info
• Send /selftest for system check
• Send /health for proxy+tunnel check
━━━━━━━━━━━━━━━━━━━━━━━"

rm -f /tmp/u.sh 2>/dev/null
exit 0
