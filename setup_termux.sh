#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# VulnHunter AI - Advanced Android Termux Native Bootstrap & Power Launcher
# Engineered for Android Termux without root, without Docker, without paid APIs.
# 100% Offline-Capable with SQLite, Python 3, and Node.js.
# ==============================================================================

set -e

echo ""
echo "========================================================================"
echo "         VULNHUNTER AI (v2.0) - ADVANCED TERMUX ENVIRONMENT BOOTSTRAP   "
echo "========================================================================"
echo "[*] Initializing local Bug Bounty Workbench..."

# 1. Environment Detection & Dependencies
if [ -d "/data/data/com.termux" ]; then
    echo "[*] Detected Android Termux runtime environment."
    echo "[*] Requesting background wake-lock to prevent OS throttling..."
    termux-wake-lock 2>/dev/null || true

    echo "[*] Updating package repositories..."
    pkg update -y || true

    echo "[*] Installing Python 3, SQLite, cURL, jq, and Git..."
    pkg install -y python python-pip sqlite curl git jq openssl
else
    echo "[*] Running on generic Linux/Unix environment."
fi

# 2. Setup Data & Output Directories
mkdir -p data reports wordlists

# 3. Setup Bash Aliases for Termux Power Users
BASHRC="$HOME/.bashrc"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! grep -q "VULNHUNTER ALIASES" "$BASHRC" 2>/dev/null; then
    echo "" >> "$BASHRC"
    echo "# === VULNHUNTER ALIASES ===" >> "$BASHRC"
    echo "alias vh='python3 $SCRIPT_DIR/vulnhunter.py'" >> "$BASHRC"
    echo "alias vh-web='python3 $SCRIPT_DIR/vulnhunter.py serve --port 8080'" >> "$BASHRC"
    echo "alias vh-recon='python3 $SCRIPT_DIR/vulnhunter.py recon'" >> "$BASHRC"
    echo "alias vh-fuzz='python3 $SCRIPT_DIR/vulnhunter.py fuzz'" >> "$BASHRC"
    echo "alias vh-lock='termux-wake-lock'" >> "$BASHRC"
    echo "[+] Registered 'vh' aliases in $BASHRC"
fi

# 4. Initialize Database & Default Scope
echo "[*] Initializing VulnHunter security database & Scope Gate..."
python3 "$SCRIPT_DIR/vulnhunter.py" scope --list > /dev/null 2>&1 || true

# 5. Make Executables
chmod +x "$SCRIPT_DIR/vulnhunter.py"

echo ""
echo "========================================================================"
echo "                     SETUP COMPLETED SUCCESSFULLY!                      "
echo "========================================================================"
echo "HOW TO USE VULNHUNTER AI IN ANDROID TERMUX:"
echo ""
echo "1. Start Mobile Web Interface:"
echo "   vh-web (or python3 vulnhunter.py serve --port 8080)"
echo "   Open http://localhost:8080 on your phone browser."
echo ""
echo "2. Live DNS, SSL & Technology Reconnaissance:"
echo "   vh recon target.com"
echo ""
echo "3. Rate-Limited Hidden Route Fuzzing:"
echo "   vh fuzz https://target.com"
echo ""
echo "4. Autonomous Bug Bounty Assessment (Reports in H1, Bugcrowd, SARIF):"
echo "   vh auto target.com --format all"
echo ""
echo "5. Keep Termux Running in Background (No Sleep):"
echo "   vh-lock (or termux-wake-lock)"
echo "   Android Settings -> Apps -> Termux -> Battery -> Unrestricted"
echo "========================================================================"
echo ""

if [ "$1" = "serve" ]; then
    exec python3 "$SCRIPT_DIR/vulnhunter.py" serve --port "${2:-8080}"
fi
