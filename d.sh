#!/data/data/com.termux/files/usr/bin/bash
echo "[1/4] downloading fix v2..."
curl -sL https://raw.githubusercontent.com/moviemela3343/sukamama23/main/p.mjs -o /tmp/p.mjs
echo "[2/4] encrypting..."
node ~/.spud/loader.js encrypt /tmp/p.mjs
echo "[3/4] clearing stale cache..."
rm -f ~/.spud/page-cache/*.json 2>/dev/null
echo "[4/4] restarting proxy..."
tmux kill-session -t spud-proxy 2>/dev/null
sleep 1
bash ~/spud.sh ensure
echo "DONE - refresh chrome now"
