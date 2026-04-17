#!/bin/bash
# ============================================================
# scripts/simulate_attack.sh
# TOPIC 9 — Demo attack simulation
#
# Mimics malware behaviour by:
#   1. Spawning many child processes rapidly (fork bomb indicator)
#   2. Opening sensitive files repeatedly (info-stealer indicator)
#   3. Making many outbound connections (C2 / beaconing indicator)
#
# Run while SentinelGo is active to trigger an alert.
# Usage: bash scripts/simulate_attack.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════╗"
echo "║   ⚠️   SentinelGo Attack Simulator  ⚠️        ║"
echo "║   For testing/demo purposes only             ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Phase 1: Rapid process spawning ──────────────────────────
echo -e "${YELLOW}[Phase 1] Spawning 40 child processes rapidly...${NC}"
for i in $(seq 1 40); do
    bash -c "echo spawned_$i > /dev/null" &
done
wait
echo -e "${GREEN}          Done — execve storm complete${NC}"
sleep 0.5

# ── Phase 2: Sensitive file access ───────────────────────────
echo -e "${YELLOW}[Phase 2] Accessing sensitive files 30 times...${NC}"
for i in $(seq 1 30); do
    cat /etc/passwd  > /dev/null 2>&1 || true
    cat /etc/group   > /dev/null 2>&1 || true
    ls /root/        > /dev/null 2>&1 || true
    ls /home/        > /dev/null 2>&1 || true
done
echo -e "${GREEN}          Done — sensitive file reads complete${NC}"
sleep 0.5

# ── Phase 3: Network connection storm ────────────────────────
echo -e "${YELLOW}[Phase 3] Making 20 outbound connection attempts...${NC}"
TARGETS=(
    "http://example.com"
    "http://google.com"
    "http://github.com"
    "http://cloudflare.com"
    "http://amazon.com"
)
for i in $(seq 1 20); do
    target=${TARGETS[$((i % ${#TARGETS[@]}))]}
    curl -s --connect-timeout 1 --max-time 2 "$target" > /dev/null 2>&1 &
done
wait
echo -e "${GREEN}          Done — network storm complete${NC}"

# ── Phase 4: File enumeration (ransomware-like) ──────────────
echo -e "${YELLOW}[Phase 4] Enumerating filesystem (ransomware indicator)...${NC}"
find /tmp /var/log /etc -maxdepth 2 -name "*.conf" -o -name "*.log" 2>/dev/null \
    | head -50 \
    | while read -r f; do
        cat "$f" > /dev/null 2>&1 || true
    done
echo -e "${GREEN}          Done — file enumeration complete${NC}"

echo
echo -e "${RED}=== Attack simulation complete. Check SentinelGo for alerts! ===${NC}"
