#!/bin/bash
# ============================================================
# Mini-SOC — active-response Wazuh : blocage d'IP via nftables.
# Reçoit l'IP via stdin (format JSON Wazuh AR) ou en argument.
# Sécurité : whitelist intégrée + journalisation systématique.
#
# Installé dans /var/ossec/active-response/bin/ et appelé par le manager
# (voir <active-response> dans wazuh_manager.conf).
# Prérequis hôte : nftables + une table/`set` "minisoc_blackhole".
# ============================================================
set -u

LOG="/var/ossec/logs/active-responses.log"
TABLE="inet minisoc"
SET="blackhole"

# Ne jamais bloquer ces IP (gateway, loopback, DNS internes...).
WHITELIST=("127.0.0.1" "::1")

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') minisoc-block-ip: $*" >>"$LOG"; }

# ── Lecture de l'entrée Wazuh (JSON sur stdin en 4.x) ───────────────────────
read -r INPUT
COMMAND=$(echo "$INPUT" | sed -n 's/.*"command":"\([^"]*\)".*/\1/p')
SRCIP=$(echo "$INPUT"   | sed -n 's/.*"srcip":"\([^"]*\)".*/\1/p')

# Fallback : ancien format positionnel (arguments).
[ -z "${COMMAND:-}" ] && COMMAND="${1:-add}"
[ -z "${SRCIP:-}" ]   && SRCIP="${3:-}"

if [ -z "$SRCIP" ]; then
  log "ERREUR: aucune IP source fournie"
  exit 1
fi

for w in "${WHITELIST[@]}"; do
  if [ "$SRCIP" = "$w" ]; then
    log "REFUS: $SRCIP est en whitelist"
    exit 0
  fi
done

ensure_set() {
  nft list table $TABLE >/dev/null 2>&1 || nft add table $TABLE
  nft list set $TABLE $SET >/dev/null 2>&1 || \
    nft add set $TABLE $SET "{ type ipv4_addr; flags timeout; }"
  nft list chain $TABLE input >/dev/null 2>&1 || {
    nft add chain $TABLE input "{ type filter hook input priority 0; }"
    nft add rule  $TABLE input ip saddr @$SET drop
  }
}

case "$COMMAND" in
  add)
    ensure_set
    # Timeout 1h : déblocage automatique (cohérent avec <timeout> Wazuh).
    nft add element $TABLE $SET "{ $SRCIP timeout 3600s }" && \
      log "BLOQUE $SRCIP (nftables, 3600s)" || \
      log "ERREUR ajout $SRCIP"
    ;;
  delete)
    nft delete element $TABLE $SET "{ $SRCIP }" 2>/dev/null && \
      log "DEBLOQUE $SRCIP" || \
      log "INFO: $SRCIP absent du set"
    ;;
  *)
    log "ERREUR: commande inconnue '$COMMAND'"
    exit 1
    ;;
esac

exit 0
