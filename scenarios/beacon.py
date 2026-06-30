#!/usr/bin/env python3
"""
Scénario T1071 — beaconing C2 simulé (command and control).

Émet des requêtes HTTP régulières (intervalle quasi constant) vers une cible,
sans User-Agent : c'est le motif que détectent la règle Suricata SID 1000007 et
le script Zeek mitre-tagging (Possible_Beacon).

Usage : python3 beacon.py --target 192.168.1.10 --count 15 --interval 5
Aucune dépendance externe (urllib).
"""
import argparse
import time
import urllib.request


def beacon(target: str, port: int, count: int, interval: float) -> None:
    url = f"http://{target}:{port}/"
    print(f"[*] Beaconing vers {url} — {count} requêtes, intervalle {interval}s, sans User-Agent")
    for i in range(1, count + 1):
        try:
            # Requête volontairement sans User-Agent (motif de beacon).
            req = urllib.request.Request(url, headers={"Accept": "*/*"})
            req.remove_header("User-agent")  # urllib en ajoute un par défaut
            with urllib.request.urlopen(req, timeout=3) as resp:
                code = resp.status
        except Exception as e:
            code = f"err({type(e).__name__})"
        print(f"  beacon {i:02d}/{count} -> {code}")
        time.sleep(interval)
    print("[+] Terminé. Détection attendue : Suricata 'MINISOC C2' / Zeek Possible_Beacon (T1071).")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Beaconing C2 simulé (T1071)")
    p.add_argument("--target", default="192.168.1.10")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--count", type=int, default=15)
    p.add_argument("--interval", type=float, default=5.0)
    a = p.parse_args()
    beacon(a.target, a.port, a.count, a.interval)
