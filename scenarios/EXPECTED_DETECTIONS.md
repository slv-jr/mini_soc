# Détections attendues par scénario

Référence pour les démos : ce qui DOIT se déclencher pour chaque scénario, à
vérifier dans le dashboard Mini-SOC (http://hote:5000), Grafana et le dashboard
Wazuh (https://hote:5601).

## Pré-requis monitoring (à lire avant toute démo)

Suricata et Zeek capturent le trafic de l'interface `SOC_IFACE` (ex. `eth0`).
Pour qu'une attaque soit visible :

- **Recommandé** : lancer les scénarios depuis une **2e machine du LAN** vers
  l'IP LAN de l'hôte Mini-SOC (ou un autre hôte réel du sous-réseau). Le trafic
  traverse alors l'interface surveillée.
- Les conteneurs du lab (DVWA, Juice Shop) servent de **cibles d'entraînement**.
  Une attaque `hôte -> conteneur` passe par le bridge Docker et n'est pas vue par
  Suricata sur `eth0`. Pour démontrer la détection web de bout en bout, soit
  attaquer l'IP LAN de l'hôte (port 8081/8082 publiés), depuis une autre machine,
  soit ajouter le bridge Docker comme interface Suricata supplémentaire.

| Scénario | Commande | Technique | Doit déclencher |
|---|---|---|---|
| Scan de ports | `make demo-portscan` | T1046 | Suricata SID 1000001 + ET SCAN ; Zeek `Horizontal_Scan` ; alerte HIGH dashboard |
| Brute force SSH | `make demo-bruteforce` | T1110 | Suricata SID 1000003 ; Wazuh 5710/5712/5760 sur l'hôte cible |
| Injection SQL | `make demo-sqli` | T1190 | Suricata SID 1000005/1000006 ; règle Wazuh 100011 (web attack) |
| Beaconing C2 | `make demo-beacon` | T1071 | Suricata SID 1000007 ; Zeek `Possible_Beacon` ; incident HIGH |
| Chaîne complète | `make demo-all` | T1046→T1110→T1190 | **Incident corrélé** (correlator) : recon -> brute / exploit, sévérité HIGH/CRITICAL |

## Vérifs corrélation (le cœur de la valeur Mini-SOC)

Après `make demo-all` depuis la même IP source, le corrélateur Python doit créer
un **incident** car la chaîne `T1046 (recon) -> T1110 (brute force)` est détectée
sur une même IP source dans la fenêtre de corrélation
(`detection.correlation.context_ttl_seconds`).

Vérifier dans le dashboard, panneau « Incidents corrélés » :
- titre `Incident HIGH — <ip>`
- chaîne affichée : `T1046(Discovery) -> T1110(Credential Access) ...`

Si un succès d'authentification SSH est ensuite remonté par Wazuh (règle 100020),
l'incident est escaladé en **CRITICAL** (compromission probable).

## Active response

Avec `responder.auto_block: true` (settings.yaml) et une règle Wazuh de niveau
>= 10, l'IP source est ajoutée au set nftables `minisoc blackhole` (timeout 1h).
Vérifier sur l'hôte :

```bash
sudo nft list set inet minisoc blackhole
```

## Capture d'écran à réaliser pour le portfolio

1. Dashboard Mini-SOC avec un incident corrélé + tags MITRE.
2. Grafana « Threat Landscape » avec le pic d'alertes.
3. Dashboard Wazuh montrant les alertes Suricata + MITRE.
4. `nft list set` montrant l'IP bloquée par l'active response.
