# Démos & scénarios

Scénarios d'attaque rejouables pour démontrer la chaîne de détection complète.
Détail des détections attendues : [../scenarios/EXPECTED_DETECTIONS.md](../scenarios/EXPECTED_DETECTIONS.md).

## Préparation

```bash
cd scenarios
make check        # vérifie nmap / hydra / sqlmap
make lab-up       # démarre DVWA + Juice Shop (cibles d'entraînement)
```

Rappel monitoring : pour que Suricata/Zeek voient le trafic, lancer les attaques
depuis une **2e machine du LAN** vers l'IP de l'hôte Mini-SOC (`TARGET=<ip-hote>`).

## Les 5 scénarios

```bash
make demo-portscan   TARGET=192.168.1.10   # T1046 - reconnaissance
make demo-bruteforce TARGET=192.168.1.10   # T1110 - credential access
make demo-sqli       TARGET=192.168.1.10   # T1190 - exploitation web
make demo-beacon     TARGET=192.168.1.10   # T1071 - C2 beaconing
make demo-all        TARGET=192.168.1.10   # chaîne complète -> incident corrélé
```

## Déroulé d'une démo d'entretien (~15 min)

1. Montrer le dashboard Mini-SOC vide (état nominal).
2. Lancer `make demo-portscan` → alerte T1046 apparaît en temps réel (SSE).
3. Lancer `make demo-bruteforce` → alerte T1110, puis **incident corrélé**
   (recon → brute force) avec sa chaîne MITRE.
4. Montrer l'enrichissement de l'IP source (GeoIP / réputation).
5. Bloquer l'IP depuis le dashboard → vérifier `nft list set inet minisoc blackhole`.
6. Montrer Grafana (« Threat Landscape ») et le dashboard Wazuh (vue SIEM).

## Captures à intégrer au portfolio

Voir la liste en fin de [../scenarios/EXPECTED_DETECTIONS.md](../scenarios/EXPECTED_DETECTIONS.md).
