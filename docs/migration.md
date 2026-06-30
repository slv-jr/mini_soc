# Migration Raspberry Pi → PC Ubuntu

Ce document raconte la migration et les choix techniques, utile pour expliquer le
projet (entretien, soutenance).

## Point de départ (v1, Raspberry Pi)

Prototype « tout-maison » : capture Scapy, serveur syslog UDP, règles Python
(brute force, scan, ARP spoof, flood), détection d'anomalie Z-score, Redis +
InfluxDB + SQLite, dashboard Flask, Grafana. Pédagogique, mais limité (peu de
protocoles, faux positifs, pas de threat intel, pas de mapping MITRE) et contraint
par les ressources du Pi.

## Pourquoi migrer vers un PC Ubuntu

- Plus de RAM/CPU → possibilité de faire tourner une vraie stack SIEM (Wazuh +
  OpenSearch) et des capteurs performants (Suricata multi-thread, Zeek).
- Architecture x86 → images Docker officielles partout, pas de contrainte ARM.
- Objectif : un projet **valorisable** (aligné sur les outils du marché) ET
  **réellement utile** sur un réseau domestique.

## Ce qui a changé

| v1 (Pi) | v2 (Ubuntu) | Raison |
|---|---|---|
| Capture Scapy | Suricata + Zeek | Détection éprouvée, ruleset ET Open, 50+ protocoles |
| Serveur syslog maison | Wazuh + Vector | Parsing et corrélation standard |
| Règles Python (brute/scan) | Signatures Suricata | Moins de faux positifs, maintenu par la communauté |
| Z-score maison | Archivé (exemple) | Hors périmètre ; gardé pour la pédagogie |
| iptables | nftables + Wazuh AR | Moderne, sets à timeout |
| `install.sh` | Ansible (rôles) | Infrastructure as code, idempotent |
| Pas de MITRE | mitre.py + dashboard | Lecture analyste, valorisable |
| Pas de threat intel | enricher.py (GeoIP/AbuseIPDB/OTX) | Contexte de décision |

## Ce qui a été conservé (la vraie valeur ajoutée)

- Le schéma pivot `NetworkEvent` : colonne vertébrale qui unifie les sources.
- Le **corrélateur** : enrichi pour raisonner en chaînes MITRE multi-étapes.
- Le **dashboard topologie** Flask : enrichi (MITRE, actions, incidents).
- Le stockage Redis / InfluxDB / SQLite et Grafana.

## Compatibilité Pi

L'architecture reste déployable sur un Raspberry Pi 4 (8 Go) en profil `sensors`
seul (sans Wazuh, gourmand). Le nom « Mini-SOC » reflète cette portabilité.
