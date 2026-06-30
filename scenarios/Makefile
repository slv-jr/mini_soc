# ============================================================
# Mini-SOC — scénarios d'attaque rejouables (démos)
#
# IMPORTANT (monitoring) : Suricata/Zeek écoutent l'interface SOC_IFACE.
# Pour qu'ils VOIENT le trafic, l'attaque doit traverser cette interface :
#   - idéalement, lancer ces scénarios depuis une AUTRE machine du LAN
#     en pointant TARGET vers l'IP LAN de l'hôte Mini-SOC ;
#   - ou viser un autre hôte réel du réseau surveillé.
# Les attaques host -> conteneurs lab passent par le bridge Docker et ne sont
# PAS vues par Suricata sur eth0 (voir EXPECTED_DETECTIONS.md).
#
# Variables :
#   TARGET   IP/hôte cible           (défaut: 192.168.1.10)
#   WEBPORT  port web pour SQLi      (défaut: 8081 = DVWA)
#
# Exemples :
#   make demo-portscan TARGET=192.168.1.10
#   make demo-all TARGET=192.168.1.10
# ============================================================

TARGET ?= 192.168.1.10
WEBPORT ?= 8081

.PHONY: help check demo-portscan demo-bruteforce demo-sqli demo-beacon demo-all lab-up lab-down

help:
	@echo "Cibles disponibles :"
	@echo "  make check            - vérifie les outils requis (nmap, hydra, sqlmap)"
	@echo "  make lab-up           - démarre les cibles vulnérables (DVWA, Juice Shop)"
	@echo "  make lab-down         - arrête le lab"
	@echo "  make demo-portscan    - scan de ports (T1046)"
	@echo "  make demo-bruteforce  - brute force SSH (T1110)"
	@echo "  make demo-sqli        - injection SQL (T1190)"
	@echo "  make demo-beacon      - beaconing C2 simulé (T1071)"
	@echo "  make demo-all         - chaîne complète recon -> access -> C2"
	@echo "  (variables: TARGET=$(TARGET) WEBPORT=$(WEBPORT))"

check:
	@for t in nmap hydra sqlmap; do \
	  command -v $$t >/dev/null 2>&1 && echo "[ok] $$t" || echo "[manquant] $$t (sudo apt install $$t)"; \
	done

lab-up:
	docker compose -f ../docker/docker-compose.yml --profile lab up -d
	@echo "DVWA      -> http://localhost:8081  (admin/password, créer la DB au 1er accès)"
	@echo "Juice Shop-> http://localhost:8082"

lab-down:
	docker compose -f ../docker/docker-compose.yml --profile lab down

demo-portscan:
	@echo ">> [T1046] Scan de ports SYN sur $(TARGET)"
	./portscan.sh $(TARGET)

demo-bruteforce:
	@echo ">> [T1110] Brute force SSH sur $(TARGET)"
	./bruteforce.sh $(TARGET)

demo-sqli:
	@echo ">> [T1190] Injection SQL sur $(TARGET):$(WEBPORT)"
	./sqli.sh $(TARGET) $(WEBPORT)

demo-beacon:
	@echo ">> [T1071] Beaconing C2 simulé vers $(TARGET)"
	python3 beacon.py --target $(TARGET) --count 15 --interval 5

demo-all: demo-portscan demo-bruteforce demo-sqli
	@echo ">> Chaîne d'attaque complète jouée. Vérifier le dashboard (incident corrélé attendu)."
