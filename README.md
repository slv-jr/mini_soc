# Mini-SOC — Security Operations Center auto-hébergé

> SOC complet sur PC Ubuntu : détection réseau (Suricata + Zeek), HIDS/SIEM
> (Wazuh), corrélation multi-source mappée **MITRE ATT&CK**, enrichissement
> threat-intel et réponse automatisée (SOAR). Déploiement Ansible, lab d'attaque
> intégré et scénarios rejouables.

[![CI](https://github.com/ton-user/mini-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/ton-user/mini-soc/actions)

---

## Pourquoi ce projet

Recyclage d'un vieux PC en sonde de sécurité réseau pour un réseau domestique
réel, tout en s'appuyant sur les **outils standards de l'industrie**. La valeur
ajoutée maison : la couche de corrélation Python qui transforme des alertes
isolées (Suricata, Zeek, Wazuh) en **incidents lisibles**, mappés MITRE ATT&CK,
enrichis (GeoIP/réputation) et accompagnés d'une réponse automatique.

Issu de la migration d'un prototype Raspberry Pi (voir [docs/migration.md](docs/migration.md)).

## Stack technique

| Couche | Technologie |
|---|---|
| IDS/IPS | Suricata 7 + ruleset ET Open + règles custom MITRE |
| Analyse protocolaire | Zeek 6 (conn/dns/http/ssl/notice) |
| HIDS + SIEM | Wazuh 4.9 (manager + indexer + dashboard) |
| Ingestion / normalisation | Vector (VRL → schéma `NetworkEvent`) |
| Bus de messages | Redis 7 |
| Métriques | InfluxDB 2 + Grafana 10 |
| Corrélation / MITRE / TI | Python (`detection/`) |
| Threat intel | GeoLite2, AbuseIPDB, AlienVault OTX |
| SOAR / réponse | nftables + active-response Wazuh, Slack/Telegram |
| Dashboard topologie | Flask + vis.js (SSE temps réel) |
| Déploiement | Docker Compose + Ansible + systemd |
| Qualité | pytest, ruff, pre-commit, GitHub Actions |

Architecture détaillée (avec diagramme) : [docs/architecture.md](docs/architecture.md).

## Prérequis

- Ubuntu 22.04+ (x86_64)
- **RAM** : 8 Go recommandé (4 Go possible sans Wazuh, voir profils)
- ~40 Go de disque libre
- Accès sudo, interface filaire

## Installation (Ansible)

```bash
git clone https://github.com/ton-user/mini-soc.git
cd mini-soc/ansible
ansible-galaxy collection install community.docker ansible.posix
# Ajuster ansible/group_vars/all.yml (profils, RAM, clés API)
ansible-playbook playbook.yml --ask-become-pass
```

Le playbook installe Docker, génère les secrets (`.env`), les certificats Wazuh,
déploie le code, crée le venv, installe l'agent Wazuh et le service `minisoc`.

> Guide de déploiement complet pas-à-pas (Ansible **et** manuel, vérification,
> dépannage) : [docs/deployment.md](docs/deployment.md).

## Démarrage manuel (sans Ansible)

```bash
cd docker
cp .env.example .env            # adapter SOC_IFACE et les mots de passe
# (profil siem) générer les certs Wazuh une fois :
docker compose -f generate-certs.yml run --rm generator
docker compose --profile sensors --profile siem up -d

cd ..
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python main.py    # moteur + dashboard
```

## Profils (consommation RAM)

| Profil | Contenu | RAM |
|---|---|---|
| core | redis + influxdb + grafana | ~0.5 Go |
| sensors | + suricata + zeek + vector | ~1 Go |
| siem | + wazuh (manager/indexer/dashboard) | ~3 Go |
| lab | + dvwa + juice-shop (réseau isolé) | ~0.5 Go |

```bash
docker compose --profile sensors up -d                 # SOC léger
docker compose --profile sensors --profile siem up -d  # SOC complet
```

## Accès

| Interface | URL | Identifiants |
|---|---|---|
| Dashboard Mini-SOC | http://&lt;hote&gt;:5000 | — |
| Grafana | http://&lt;hote&gt;:3000 | voir `.env` |
| Wazuh dashboard | https://&lt;hote&gt;:5601 | voir `.env` |
| DVWA (lab) | http://&lt;hote&gt;:8081 | admin / password |
| Juice Shop (lab) | http://&lt;hote&gt;:8082 | — |

## Démos rejouables

```bash
cd scenarios
make lab-up
make demo-all TARGET=<ip-hote>   # recon -> brute force -> exploitation
```

Détections attendues : [scenarios/EXPECTED_DETECTIONS.md](scenarios/EXPECTED_DETECTIONS.md).
Déroulé d'une démo : [docs/scenarios.md](docs/scenarios.md).

## Détection & corrélation

Suricata/Zeek/Wazuh produisent les alertes ; le moteur Python les enrichit et
détecte des **chaînes d'attaque** :

| Chaîne | Techniques | Incident |
|---|---|---|
| Reconnaissance puis brute force | T1046/T1018 → T1110 | HIGH |
| Brute force puis succès d'auth | T1110 + succès Wazuh | CRITICAL |
| Scan puis exploitation web | T1046 → T1190 | HIGH |
| Beaconing C2 | T1071 | HIGH |
| Multi-étapes | ≥ 3 techniques / ≥ 2 tactiques | HIGH |

## Structure du projet

```
mini-soc/
├── ansible/            # déploiement (rôles common/docker/minisoc/wazuh_agent/stack)
├── docker/             # compose + configs Suricata, Zeek, Vector, Wazuh, Grafana
│   └── docker-compose.yml
├── collector/probe.py  # sondes actives ICMP/HTTP
├── pipeline/           # schema (NetworkEvent) + queue Redis
├── detection/          # mitre.py, enricher.py, correlator.py, engine.py
├── alerting/           # notifier (multi-canal), responder (SOAR), wazuh_ingest
├── storage/            # influx.py, sqlite_db.py
├── dashboard/topology.py
├── scenarios/          # lab + démos rejouables
├── tests/              # pytest
├── docs/               # architecture, runbook, migration, scénarios
├── examples/           # anomaly_zscore.py (archivé, pédagogique)
├── config/             # settings.yaml, mitre_map.yaml
├── main.py
└── minisoc.service
```

## Tests & qualité

```bash
pip install pytest ruff
pytest          # tests unitaires (schema, mitre, correlator, enricher, wazuh_ingest)
ruff check .    # lint
```

## Réponse aux alertes

Voir le [runbook](docs/runbook.md) : interprétation de chaque alerte type et
actions associées.

---

*Projet réseaux & cybersécurité — déployé sur matériel réel, trafic réseau réel.*
