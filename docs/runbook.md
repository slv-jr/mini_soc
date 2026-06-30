# Runbook — réponse aux alertes

Guide d'interprétation et d'action pour les alertes types du Mini-SOC.
Pour chaque alerte : ce que ça signifie, comment confirmer, quoi faire.

## Convention de sévérité

| Sévérité | Niveau Wazuh | Réaction attendue |
|---|---|---|
| low | 4-6 | observation |
| medium | 7-9 | investigation |
| high | 10-11 | investigation prioritaire + blocage possible |
| critical | 12-15 | réponse immédiate |

---

## T1046 — Scan de ports (Suricata `MINISOC SCAN`)

- **Signification** : une source sonde plusieurs ports/hôtes (reconnaissance).
- **Confirmer** : dashboard -> alertes avec tag `T1046` ; Zeek `Horizontal_Scan` ;
  Grafana « Threat Landscape » (pic d'alertes depuis une IP).
- **Action** : si l'IP est externe et inconnue, surveiller la suite (souvent suivie
  d'un brute force ou d'une exploitation). Bloquer si scan agressif et répété.

## T1110 — Brute force (Suricata `MINISOC BRUTEFORCE` / Wazuh 5710-5763)

- **Signification** : tentatives d'authentification répétées (SSH, HTTP login).
- **Confirmer** : corréler IP source côté Suricata ET Wazuh (auth.log de l'hôte).
- **Action** :
  1. Vérifier si une **connexion réussie** a suivi (règle Wazuh 100020 -> incident
     CRITICAL : compromission probable).
  2. Bloquer l'IP (`/api/block` ou active-response automatique).
  3. Si succès : isoler l'hôte cible, réinitialiser les identifiants, analyser.

## T1190 — Attaque web / SQLi (Suricata `MINISOC WEBATTACK`)

- **Signification** : injection SQL, path traversal ou autre exploitation applicative.
- **Confirmer** : URI suspecte dans l'alerte ; logs du serveur web cible.
- **Action** : bloquer l'IP, vérifier les logs applicatifs pour une exploitation
  réussie (exfiltration, upload), patcher l'application.

## T1071 — Beaconing C2 (Suricata `MINISOC C2` / Zeek `Possible_Beacon`)

- **Signification** : un hôte interne contacte régulièrement une IP externe
  (caractéristique d'un implant / C2).
- **Confirmer** : régularité des connexions (Zeek conn.log), réputation de la
  destination (enrichissement AbuseIPDB/OTX).
- **Action** : **prioritaire**. Isoler l'hôte interne (potentiellement compromis),
  analyser les processus, bloquer la destination en sortie.

## Incident corrélé (correlator)

- **Signification** : plusieurs techniques d'une même IP forment une chaîne
  d'attaque (ex. `T1046 -> T1110`). C'est le signal le plus fiable.
- **Action** : traiter en priorité selon la sévérité de l'incident ; la chaîne
  affichée dans le dashboard guide l'investigation (par où l'attaquant est passé).

---

## Opérations courantes

```bash
# Bloquer / débloquer manuellement une IP
curl -XPOST localhost:5000/api/block   -H 'Content-Type: application/json' -d '{"ip":"x.x.x.x"}'
curl -XPOST localhost:5000/api/unblock -H 'Content-Type: application/json' -d '{"ip":"x.x.x.x"}'

# Voir les IP bloquées (active-response nftables)
sudo nft list set inet minisoc blackhole

# Logs du moteur Python
sudo journalctl -fu minisoc

# Logs des capteurs
docker logs -f minisoc-suricata
docker logs -f minisoc-vector
```

## Faux positifs

- Ajouter les IP de confiance dans `responder.whitelist_ips` (settings.yaml).
- Ajuster les seuils des règles dans `docker/suricata/rules/custom.rules`.
- Pour ET Open trop bruyant : désactiver des SID via `suricata-update`.
