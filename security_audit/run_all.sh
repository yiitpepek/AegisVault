#!/usr/bin/env bash
# AegisVault guvenlik PoC paketi - tum kanitlari sirayla calistirir
set -u
cd "$(dirname "$0")/.."
mkdir -p /tmp/opencode/aegis_poc
LOG=/tmp/opencode/aegis_poc/all_poc_output.log
: > "$LOG"
for poc in security_audit/PoC_*.py; do
    echo "########## $poc ##########" | tee -a "$LOG"
    if python3 "$poc" 2>&1 | tee -a "$LOG"; then
        echo "[OK] $poc" | tee -a "$LOG"
    else
        echo "[HATA] $poc" | tee -a "$LOG"
    fi
    echo | tee -a "$LOG"
done
echo "Tum PoC ciktilari: $LOG"
