#!/usr/bin/env bash
# Scénario T1046 — scan de ports (reconnaissance).
# Usage : ./portscan.sh <TARGET>
set -euo pipefail
TARGET="${1:-192.168.1.10}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap manquant : sudo apt install nmap" >&2
  exit 1
fi

echo "[*] Scan SYN des 1000 premiers ports de ${TARGET} (déclenche custom.rules SID 1000001)"
sudo nmap -sS -T4 -p 1-1000 "${TARGET}"

echo "[*] Scan de services sur quelques ports courants"
sudo nmap -sV -p 22,80,443,3306,8080 "${TARGET}" || true

echo "[+] Terminé. Détection attendue : Suricata 'MINISOC SCAN' (T1046)."
