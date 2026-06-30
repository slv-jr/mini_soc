# Guide de déploiement — PC Ubuntu

Pas-à-pas pour mettre le Mini-SOC en production sur **la** machine Ubuntu.
Deux voies : **Ansible** (recommandé, idempotent) ou **manuelle** (pour comprendre /
dépanner). Le PC Ubuntu est sa propre cible (`localhost`).

---

## 0. Pré-requis matériel / OS

- Ubuntu 22.04 ou 24.04 LTS, 64 bits.
- RAM : **8 Go** recommandé pour la stack complète (sensors + siem).
  4 Go possible → voir [§ profil léger](#variante-machine-4-go).
- ~40 Go de disque libre.
- Un compte avec `sudo`.
- Connexion filaire de préférence (Suricata/Zeek écoutent une interface).

Vérifier le nom de l'interface réseau (on en aura besoin) :

```bash
ip -br link        # ex: enp3s0, ens33, eth0...
ip -br addr        # confirme l'IP et le sous-réseau
```

---

## 1. Récupérer le code sur la machine

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/ton-user/mini-soc.git ~/mini-soc
cd ~/mini-soc
```

> Le playbook copiera ensuite le code vers `/opt/mini-soc` (emplacement de prod).

---

## 2. Voie A — Déploiement Ansible (recommandé)

### 2.1 Installer Ansible et les collections

```bash
sudo apt install -y ansible
cd ~/mini-soc/ansible
ansible-galaxy collection install community.docker ansible.posix
```

### 2.2 Configurer le déploiement

Éditer `ansible/group_vars/all.yml` :

```yaml
soc_iface: "enp3s0"          # ← ton interface (vide = auto-détection)
soc_subnet: "192.168.1.0/24" # ← ton sous-réseau réel

soc_profiles:                # adapter à la RAM
  - sensors
  - siem                     # retirer si < 8 Go

opensearch_heap: "1g"        # "512m" si 4 Go

# Optionnel mais recommandé pour l'enrichissement :
maxmind_license_key: ""      # GeoLite2 (compte MaxMind gratuit)
abuseipdb_api_key: ""
otx_api_key: ""

# Optionnel — alerting :
slack_webhook_url: ""
telegram_bot_token: ""
telegram_chat_id: ""
```

### 2.3 Lancer le playbook

```bash
ansible-playbook playbook.yml --ask-become-pass
```

Le playbook, de façon idempotente :
1. installe les paquets de base, nftables, règle `vm.max_map_count=262144` ;
2. installe Docker + Compose ;
3. copie le code dans `/opt/mini-soc`, crée le venv, **génère un `.env` avec des
   mots de passe aléatoires** ;
4. installe l'agent Wazuh sur l'hôte (si `install_wazuh_agent: true`) ;
5. génère les certificats Wazuh (profil siem), démarre la stack Docker, branche
   l'intégration Wazuh → webhook ;
6. installe le service `minisoc`.

### 2.4 Démarrer le moteur Python

```bash
sudo systemctl enable --now minisoc
systemctl status minisoc
```

→ Passer directement à la [§ 4 Vérification](#4-vérification).

---

## 3. Voie B — Déploiement manuel

Si tu préfères tout faire à la main (ou déboguer).

### 3.1 Dépendances système

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl nftables make jq \
                    nmap hydra sqlmap            # (nmap/hydra/sqlmap : pour les démos)
sudo systemctl enable --now nftables
# Requis par l'indexer Wazuh (OpenSearch) :
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-minisoc.conf
sudo sysctl --system
```

### 3.2 Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker   # pour utiliser docker sans sudo
```

### 3.3 Configurer les secrets

```bash
cd ~/mini-soc/docker
cp .env.example .env
nano .env
```

À régler dans `.env` :
- `SOC_IFACE=` ton interface (ex. `enp3s0`) et `SOC_SUBNET=`,
- **changer tous les `change_me_*`** (Influx, Grafana, Wazuh, indexer, dashboard),
- `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` si 4 Go,
- clés threat-intel / alerting si tu en as.

### 3.4 Certificats Wazuh (profil siem uniquement)

```bash
cd ~/mini-soc/docker
docker compose -f generate-certs.yml run --rm generator
```

### 3.5 Démarrer la stack Docker

```bash
# SOC léger (sans Wazuh) :
docker compose --profile sensors up -d
# OU SOC complet :
docker compose --profile sensors --profile siem up -d
# + lab d'entraînement éventuel :
docker compose --profile sensors --profile siem --profile lab up -d

docker compose ps
```

### 3.6 Moteur Python + dashboard

```bash
cd ~/mini-soc
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python main.py      # sudo : requis pour nftables (active-response)
```

Pour en faire un service permanent, adapter et installer `minisoc.service` :

```bash
sudo cp minisoc.service /etc/systemd/system/
# vérifier les chemins (WorkingDirectory / ExecStart) dans le fichier
sudo systemctl daemon-reload
sudo systemctl enable --now minisoc
```

---

## 4. Vérification

```bash
# Conteneurs up ?
docker compose -f ~/mini-soc/docker/docker-compose.yml ps      # (ou /opt/mini-soc)

# Suricata voit-il du trafic ? (eve.json doit grossir)
docker logs --tail 20 minisoc-suricata
docker exec minisoc-suricata tail -f /var/log/suricata/eve.json

# Vector pousse-t-il vers Redis ?
docker logs --tail 20 minisoc-vector

# Moteur Python
sudo journalctl -fu minisoc
curl -s localhost:5000/api/status
```

Interfaces web (remplacer par l'IP de la machine) :

| Service | URL | Identifiants |
|---|---|---|
| Dashboard Mini-SOC | http://IP:5000 | — |
| Grafana | http://IP:3000 | `.env` (GRAFANA_*) |
| Wazuh dashboard | https://IP:5601 | `.env` (INDEXER_*) |

---

## 5. Test de bout en bout (depuis une 2e machine du LAN)

Suricata/Zeek voient le trafic qui **traverse l'interface** ; lancer les attaques
depuis un autre poste du réseau vers l'IP de l'hôte Mini-SOC :

```bash
# Sur la machine d'attaque (ou l'hôte avec le profil lab) :
cd ~/mini-soc/scenarios
make demo-portscan   TARGET=<ip-hote-minisoc>
make demo-bruteforce TARGET=<ip-hote-minisoc>
make demo-all        TARGET=<ip-hote-minisoc>
```

→ Les alertes (avec tags MITRE) et l'**incident corrélé** doivent apparaître en
temps réel sur http://IP:5000. Détail attendu :
[scenarios/EXPECTED_DETECTIONS.md](../scenarios/EXPECTED_DETECTIONS.md).

---

## 6. Variante machine 4 Go

- `soc_profiles: [sensors]` seulement (pas de `siem`) **ou**
- garder `siem` mais `opensearch_heap: "512m"` (Ansible) /
  `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` (manuel),
- fermer le navigateur/Wazuh dashboard quand inutilisé.

---

## 7. Dépannage

| Symptôme | Piste |
|---|---|
| Indexer Wazuh redémarre en boucle | `vm.max_map_count` non appliqué → `sudo sysctl vm.max_map_count` doit valoir 262144 |
| Aucune alerte Suricata | mauvaise `SOC_IFACE` ; trafic ne traverse pas l'hôte ; tester depuis une autre machine |
| `permission denied` nftables | lancer le moteur avec `sudo` / via le service systemd |
| Dashboard 5000 ne répond pas | `sudo journalctl -u minisoc` ; Redis up ? `docker logs minisoc-redis` |
| Wazuh dashboard 5601 inaccessible | certs non générés → relancer l'étape 3.4 ; attendre 2-3 min au 1er boot |
| Conteneur Wazuh manager `unhealthy` | RAM insuffisante → réduire le heap / profil |

## 8. Mises à jour

```bash
cd ~/mini-soc && git pull
# Ansible :
cd ansible && ansible-playbook playbook.yml --ask-become-pass
# Manuel :
cd docker && docker compose pull && docker compose up -d
sudo systemctl restart minisoc
```
