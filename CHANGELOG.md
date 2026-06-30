# Changelog

Toutes les évolutions notables du projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [2.0.0] — Migration Raspberry Pi → PC Ubuntu (refonte hybride pro)

Refonte majeure : le projet passe d'un prototype « tout-maison » sur Raspberry Pi
à une stack SOC hybride alignée sur les outils de l'industrie, déployée sur un PC
x86 sous Ubuntu. Le code Python est conservé comme couche de corrélation et de
SOAR (orchestration des réponses), au-dessus de capteurs et d'un SIEM standards.

### Contexte de la migration

La v1 capturait les paquets avec Scapy, parsait le syslog à la main et
implémentait ses propres règles (brute force, scan de ports, Z-score). C'était
pédagogique mais limité : peu de protocoles, faux positifs, pas de threat intel,
pas de mapping MITRE. Sur un PC Ubuntu (plus de RAM/CPU que le Pi), on délègue la
détection bas niveau à des outils éprouvés et on garde la vraie valeur ajoutée :
la corrélation multi-source et la réponse automatisée.

### Ajouté

- **Capteurs réseau standards** : Suricata (IDS/IPS + ruleset ET Open) et Zeek
  (analyse protocolaire conn/dns/http/ssl/files) à la place de la capture Scapy.
- **HIDS + SIEM** : stack Wazuh (manager + indexer + dashboard) pour les logs hôte,
  le FIM et l'agrégation.
- **Ingestion** : Vector normalise les sorties Suricata/Zeek/Wazuh vers le schéma
  `NetworkEvent` existant avant publication sur Redis.
- **MITRE ATT&CK** : `detection/mitre.py` mappe les signatures Suricata/Wazuh vers
  des techniques (T-IDs), affichées dans les alertes et le dashboard.
- **Threat intel** : `detection/enricher.py` enrichit les IP (GeoIP MaxMind offline,
  AbuseIPDB, AlienVault OTX optionnel) avec cache Redis.
- **SOAR** : `alerting/responder.py` (active-response Wazuh + fallback nftables) et
  notifications multi-canal (Slack, Telegram, webhook générique).
- **Lab d'attaque** : réseau Docker isolé (DVWA, Juice Shop) et scénarios rejouables
  (`scenarios/`) pour démonstrations reproductibles.
- **Infra as code** : déploiement Ansible idempotent à la place du script bash.
- **Qualité** : tests pytest, CI GitHub Actions, pre-commit (ruff/black/yamllint).

### Modifié

- `detection/correlator.py` : corrélation orientée chaînes MITRE multi-étapes
  (reconnaissance → accès initial → exécution → mouvement latéral / C2).
- `dashboard/topology.py` : tags MITRE, badges de sévérité, actions manuelles
  (bloquer / quarantaine / whitelist).
- `docker-compose.yml` : stack complète (capteurs + SIEM + ingestion + viz + lab).
- Renommage « Pi-SOC » → « Mini-SOC » (l'architecture reste compatible Pi 4 8 Go).

### Supprimé

- `collector/packet_capture.py` (remplacé par Suricata + Zeek).
- `collector/syslog_server.py` (remplacé par Wazuh + Vector).
- `detection/rules_engine.py` (les règles brute force / scan / flood sont
  désormais portées par Suricata ; la corrélation cross-source est dans
  `correlator.py`).
- `alerting/remediation.py` (iptables) remplacé par `alerting/responder.py`
  (nftables + active-response Wazuh).
- `install.sh` (remplacé par le playbook Ansible).
- `pi-soc.service` (renommé `minisoc.service`).
- `detection/anomaly.py` : archivé dans `examples/anomaly_zscore.py` (désactivé
  par défaut, conservé comme exemple pédagogique de détection statistique).

### Note d'architecture

Vector écrit directement les événements normalisés dans la file Redis `pisoc:raw`
consommée par le moteur Python : il joue le rôle qu'aurait eu un `eve_consumer`,
qui devient donc inutile (une indirection en moins).

## [1.0.0] — Version Raspberry Pi initiale

- Capture paquets Scapy, serveur syslog UDP, sondes ICMP/HTTP.
- Règles maison (brute force SSH, scan de ports, ARP spoof, ICMP/DNS flood).
- Détection d'anomalie par Z-score.
- Stockage Redis + InfluxDB + SQLite, dashboard Flask, Grafana.
- Déploiement via `install.sh` + service systemd.
