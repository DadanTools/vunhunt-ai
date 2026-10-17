#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# VulnHunter AI - One-Command Termux Bootstrap & Launcher
# Tested for Android Termux without root, without Docker, without paid APIs.
# ==============================================================================

set -e

echo ""
echo "=========================================================="
echo "           VULNHUNTER AI - TERMUX BOOTSTRAP               "
echo "=========================================================="
echo "[*] Initializing local Bug Bounty Workbench..."

# Check environment
if [ -d "/data/data/com.termux" ]; then
    echo "[*] Detected Android Termux runtime environment."
    echo "[*] Updating package repositories..."
    pkg update -y || true
    echo "[*] Installing Python 3, SQLite, and cURL..."
    pkg install -y python python-pip sqlite curl git
else
    echo "[*] Running on generic Linux/Unix environment."
fi

# Create data directory
mkdir -p data

# Initialize SQLite database and default authorized local scope
echo "[*] Initializing VulnHunter security database..."
python3 vulnhunter.py scope --list > /dev/null 2>&1 || true

echo ""
echo "[+] Setup completed successfully!"
echo "=========================================================="
echo "HOW TO USE VULNHUNTER AI IN TERMUX:"
echo "1. Start local web server:"
echo "   python3 vulnhunter.py serve --port 8080"
echo "   Then open http://localhost:8080 in your mobile browser."
echo ""
echo "2. Add authorized target to Scope Gate:"
echo "   python3 vulnhunter.py scope --add bugbounty-target.com"
echo ""
echo "3. Run safe exposure scan:"
echo "   python3 vulnhunter.py scan --target http://bugbounty-target.com"
echo ""
echo "4. Export assessment report:"
echo "   python3 vulnhunter.py report"
echo "=========================================================="
echo ""

# Make executable
chmod +x vulnhunter.py

# Launch CLI menu or server if requested
if [ "$1" = "serve" ]; then
    exec python3 vulnhunter.py serve --port "${2:-8080}"
fi
