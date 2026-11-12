#!/data/data/com.termux/files/usr/bin/bash
echo "[1/3] downloading..."
curl -sL https://raw.githubusercontent.com/moviemela3343/sukamama23/main/p.mjs -o /tmp/p.mjs
echo "[2/3] encrypting..."
node ~/.spud/loader.js encrypt /tmp/p.mjs
echo "[3/3] restarting proxy..."
tmux kill-session -t spud-proxy 2>/dev/null
sleep 1
bash ~/spud.sh ensure
echo "DONE - refresh chrome now"
