#!/data/data/com.termux/files/usr/bin/bash
set -e
echo "[deploy] downloading fixed proxy v3..."
curl -sL "https://raw.githubusercontent.com/moviemela3343/sukamama23/main/p.mjs" -o /tmp/proxy-new.mjs
SZ=$(wc -c < /tmp/proxy-new.mjs)
echo "[deploy] downloaded $SZ bytes"
if [ "$SZ" -lt 50000 ]; then echo "[deploy] ERROR: file too small, aborting"; exit 1; fi

echo "[deploy] encrypting..."
cd ~/.spud
node loader.js encrypt /tmp/proxy-new.mjs
echo "[deploy] encrypted payload updated"

echo "[deploy] clearing page cache..."
rm -f ~/.spud/page-cache/*.json 2>/dev/null
echo "[deploy] cache cleared"

echo "[deploy] restarting proxy..."
tmux kill-session -t spud-proxy 2>/dev/null || true
sleep 1
bash ~/spud.sh ensure
sleep 3

echo "[deploy] verifying..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null || echo "000")
echo "[deploy] proxy returned HTTP $HTTP"
if [ "$HTTP" = "200" ]; then
  echo "[deploy] SUCCESS - proxy v3 is live"
else
  echo "[deploy] WARNING - proxy returned $HTTP, check logs"
fi
rm -f /tmp/proxy-new.mjs
echo "[deploy] done"
