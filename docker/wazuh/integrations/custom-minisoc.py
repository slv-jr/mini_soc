#!/usr/bin/env python3
# ============================================================
# Mini-SOC — intégration Wazuh -> webhook Flask du Mini-SOC.
# Wazuh appelle ce script pour chaque alerte correspondant au niveau configuré
# dans <integration> (ossec.conf) et lui passe le fichier d'alerte en argv[1].
#
# Installer dans /var/ossec/integrations/custom-minisoc (chmod 750, owner root:wazuh)
# avec un wrapper shell custom-minisoc -> python3 custom-minisoc.py.
# ============================================================
import json
import os
import sys

try:
    import requests
except ImportError:
    requests = None


def main() -> int:
    if len(sys.argv) < 4:
        return 1
    alert_file = sys.argv[1]
    hook_url = sys.argv[3]  # défini par <hook_url> dans ossec.conf

    with open(alert_file, encoding="utf-8") as f:
        alert = json.load(f)

    # Token d'API partagé (exigé par les endpoints POST du dashboard Mini-SOC).
    # Fourni via l'environnement du conteneur manager (MINISOC_API_TOKEN).
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("MINISOC_API_TOKEN", "")
    if token:
        headers["X-API-Token"] = token

    if requests is None:
        # Fallback urllib si requests indisponible dans l'env Wazuh.
        import urllib.request
        data = json.dumps(alert).encode()
        req = urllib.request.Request(hook_url, data=data, headers=headers)
        urllib.request.urlopen(req, timeout=5)
        return 0

    requests.post(hook_url, json=alert, headers=headers, timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
