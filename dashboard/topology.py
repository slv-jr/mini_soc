"""
dashboard/topology.py
Serveur Flask — API REST + dashboard temps réel du Mini-SOC.
  - carte topologique réseau (scan ARP)
  - alertes & incidents avec tags MITRE ATT&CK et threat-intel
  - actions manuelles (bloquer / débloquer une IP) -> responder SOAR
  - webhook entrant /api/wazuh-event (boucle de feedback Wazuh -> corrélateur)
  - flux temps réel via Server-Sent Events
Accessible sur http://<ip-hote>:5000
"""
import functools
import hmac
import json
import logging
import subprocess
import threading
import time
from datetime import datetime, timezone

import redis as redis_lib
from flask import Flask, Response, abort, jsonify, render_template_string, request
from flask_cors import CORS

from config import loader
from storage.sqlite_db import get_db

logger = logging.getLogger(__name__)
app = Flask(__name__)

# CORS restreint aux origines configurées (jamais "tout autorisé" par défaut).
_cors_origins = [o.strip() for o in str(loader.get("dashboard.cors_origins", "")).split(",") if o.strip()]
CORS(app, origins=_cors_origins or ["http://localhost:5000", "http://127.0.0.1:5000"])

# Jeton partagé exigé sur les endpoints qui modifient l'état (POST).
_API_TOKEN = str(loader.get("dashboard.api_token", "") or "")
if not _API_TOKEN:
    logger.warning("MINISOC_API_TOKEN non défini : les endpoints POST sont ouverts. "
                   "Ne pas exposer le dashboard hors de la loopback sans token.")

_topology: dict[str, dict] = {}
_topology_lock = threading.Lock()


def require_token(view):
    """Protège un endpoint : exige un Bearer token constant-time si configuré."""
    @functools.wraps(view)
    def _wrapped(*args, **kwargs):
        if _API_TOKEN:
            auth = request.headers.get("Authorization", "")
            provided = auth[7:] if auth.startswith("Bearer ") else request.headers.get("X-API-Token", "")
            if not hmac.compare_digest(provided, _API_TOKEN):
                abort(401)
        return view(*args, **kwargs)
    return _wrapped


# ── Topologie réseau (scan ARP) ──────────────────────────────────────────────
def _arp_scan() -> list[dict]:
    hosts: list[dict] = []
    try:
        result = subprocess.run(["arp-scan", "--localnet", "--quiet"],
                                capture_output=True, text=True, timeout=30)
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip, mac = parts[0].strip(), parts[1].strip()
                if ip and mac and not ip.startswith("Interface"):
                    hosts.append({"ip": ip, "mac": mac})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == "0x2":
                        hosts.append({"ip": parts[0], "mac": parts[3]})
        except Exception as e:
            logger.warning(f"Fallback ARP échoué: {e}")
    return hosts


def _topology_scanner():
    interval = loader.get("dashboard.arp_scan_interval", 60)
    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()
            with _topology_lock:
                for h in _arp_scan():
                    ip = h["ip"]
                    node = _topology.setdefault(ip, {"ip": ip, "mac": h.get("mac", "?"),
                                                      "first_seen": now, "status": "up"})
                    node["last_seen"] = now
                    node["mac"] = h.get("mac", node.get("mac", "?"))
        except Exception as e:
            logger.error(f"Erreur scan topologie: {e}")
        time.sleep(interval)


# ── SSE : flux d'alertes temps réel ──────────────────────────────────────────
def _alert_stream():
    r = redis_lib.Redis(host=loader.get("redis.host", "localhost"),
                        port=loader.get("redis.port", 6379), decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe("pisoc:alerts:live")
    for message in pubsub.listen():
        if message["type"] == "message":
            yield f"data: {message['data']}\n\n"


# ── Routes API ────────────────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    stats = get_db().get_stats()
    with _topology_lock:
        stats["hosts_discovered"] = len(_topology)
    stats["timestamp"] = datetime.now(timezone.utc).isoformat()
    return jsonify(stats)


@app.route("/api/topology")
def api_topology():
    with _topology_lock:
        nodes = [dict(n) for n in _topology.values()]
    gateway = loader.get("network.gateway", "")
    for n in nodes:
        n["is_gateway"] = (n["ip"] == gateway)
    return jsonify({"nodes": nodes, "count": len(nodes)})


@app.route("/api/alerts")
def api_alerts():
    alerts = get_db().get_recent_alerts(limit=50)
    for a in alerts:  # extrait les techniques MITRE depuis les tags JSON
        try:
            tags = json.loads(a.get("tags") or "{}")
            a["mitre"] = [t.get("id") for t in tags.get("mitre", [])]
        except (json.JSONDecodeError, AttributeError):
            a["mitre"] = []
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/incidents")
def api_incidents():
    return jsonify({"incidents": get_db().get_open_incidents()})


@app.route("/api/wazuh-event", methods=["POST"])
@require_token
def api_wazuh_event():
    """Boucle de feedback : réinjecte une alerte Wazuh dans le corrélateur."""
    try:
        from alerting.wazuh_ingest import ingest_wazuh_alert
        event = ingest_wazuh_alert(request.get_json(force=True))
        return jsonify({"status": "ok", "event_id": event.event_id}), 202
    except Exception as e:
        logger.error(f"Webhook Wazuh: {e}")
        return jsonify({"status": "error", "detail": str(e)}), 400


@app.route("/api/block", methods=["POST"])
@require_token
def api_block():
    ip = (request.get_json(force=True) or {}).get("ip")
    if not ip:
        return jsonify({"status": "error", "detail": "ip manquante"}), 400
    from alerting.responder import get_responder
    ok = get_responder().block_ip(ip, reason="blocage manuel via dashboard")
    return jsonify({"status": "ok" if ok else "failed", "ip": ip})


@app.route("/api/unblock", methods=["POST"])
@require_token
def api_unblock():
    ip = (request.get_json(force=True) or {}).get("ip")
    if not ip:
        return jsonify({"status": "error", "detail": "ip manquante"}), 400
    from alerting.responder import get_responder
    ok = get_responder().unblock_ip(ip)
    return jsonify({"status": "ok" if ok else "failed", "ip": ip})


@app.route("/api/stream")
def api_stream():
    return Response(_alert_stream(), mimetype="text/event-stream")


# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mini-SOC Dashboard</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #e6edf3; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px;
             display: flex; align-items: center; gap: 16px; }
    header h1 { font-size: 16px; color: #58a6ff; }
    .badge { background: #21262d; border: 1px solid #30363d; border-radius: 4px;
             padding: 2px 8px; font-size: 12px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px; }
    .panel { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }
    .panel h2 { font-size: 13px; color: #8b949e; margin-bottom: 12px; text-transform: uppercase; }
    .stat-row { display: flex; gap: 16px; margin-bottom: 16px; }
    .stat { background: #21262d; border-radius: 6px; padding: 12px 16px; flex: 1; text-align: center; }
    .stat .val { font-size: 28px; font-weight: bold; color: #58a6ff; }
    .stat .lbl { font-size: 11px; color: #8b949e; margin-top: 4px; }
    #network { height: 320px; background: #0d1117; border-radius: 4px; }
    #alerts-list, #incidents-list { max-height: 280px; overflow-y: auto; }
    .alert-item { border-left: 3px solid #f0a500; padding: 8px 12px; margin-bottom: 6px;
                  background: #21262d; border-radius: 0 4px 4px 0; font-size: 12px; }
    .alert-item.critical { border-color: #7b0099; }
    .alert-item.high { border-color: #e01e5a; }
    .alert-item.medium { border-color: #f0a500; }
    .alert-item.low { border-color: #a0d4fb; }
    .alert-sev { font-size: 10px; font-weight: bold; text-transform: uppercase;
                 padding: 1px 6px; border-radius: 3px; margin-right: 6px; background: #30363d; }
    .mitre-tag { display: inline-block; background: #1f6feb33; color: #58a6ff;
                 border: 1px solid #1f6feb; border-radius: 3px; padding: 0 5px;
                 font-size: 10px; margin-left: 4px; }
    .ts { color: #8b949e; font-size: 10px; }
    .btn { cursor: pointer; background: #21262d; border: 1px solid #30363d; color: #e6edf3;
           border-radius: 3px; font-size: 10px; padding: 1px 6px; margin-left: 4px; }
    .btn:hover { border-color: #e01e5a; color: #e01e5a; }
    .incident-item { border-left: 3px solid #7b0099; padding: 8px 12px; margin-bottom: 6px;
                     background: #21262d; border-radius: 0 4px 4px 0; font-size: 12px; }
    .live-dot { width: 8px; height: 8px; background: #3fb950; border-radius: 50%;
                display: inline-block; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
  </style>
</head>
<body>
<header>
  <span class="live-dot"></span>
  <h1>Mini-SOC — Network Security Monitor</h1>
  <span class="badge" id="host-count">hôtes: —</span>
  <span class="badge" id="alert-count">alertes: —</span>
  <span class="badge" id="incident-count">incidents: —</span>
</header>

<div class="grid">
  <div class="panel" style="grid-column: 1 / -1;">
    <div class="stat-row">
      <div class="stat"><div class="val" id="s-events">—</div><div class="lbl">événements</div></div>
      <div class="stat"><div class="val" id="s-alerts">—</div><div class="lbl">alertes</div></div>
      <div class="stat"><div class="val" id="s-incidents">—</div><div class="lbl">incidents ouverts</div></div>
      <div class="stat"><div class="val" id="s-blocked">—</div><div class="lbl">IPs bloquées</div></div>
    </div>
  </div>

  <div class="panel"><h2>Carte réseau</h2><div id="network"></div></div>

  <div class="panel">
    <h2>Alertes récentes <span class="live-dot" style="margin-left:6px"></span></h2>
    <div id="alerts-list"></div>
  </div>

  <div class="panel" style="grid-column: 1 / -1;">
    <h2>Incidents corrélés (chaînes MITRE)</h2>
    <div id="incidents-list"></div>
  </div>
</div>

<script>
const nodes = new vis.DataSet([]);
const edges = new vis.DataSet([]);
const network = new vis.Network(document.getElementById('network'), {nodes, edges}, {
  nodes: { shape: 'dot', size: 14, font: { color: '#e6edf3', size: 11 },
           color: { background: '#21262d', border: '#58a6ff' } },
  edges: { color: '#30363d', width: 1 },
  physics: { stabilization: false, barnesHut: { gravitationalConstant: -3000 } },
});
let gatewayId = null;

async function loadTopology() {
  const data = await (await fetch('/api/topology')).json();
  document.getElementById('host-count').textContent = `hôtes: ${data.count}`;
  data.nodes.forEach(n => {
    const nodeData = { id: n.ip, label: n.ip,
      title: `MAC: ${n.mac || '?'}`,
      color: n.is_gateway ? { background: '#3fb950', border: '#3fb950' }
                          : { background: '#21262d', border: '#58a6ff' },
      size: n.is_gateway ? 22 : 14 };
    nodes.get(n.ip) ? nodes.update(nodeData) : nodes.add(nodeData);
    if (n.is_gateway) gatewayId = n.ip;
  });
  if (gatewayId) nodes.getIds().forEach(id => {
    if (id !== gatewayId && !edges.get(`${gatewayId}-${id}`))
      edges.add({ id: `${gatewayId}-${id}`, from: gatewayId, to: id });
  });
}

function mitreTags(list) {
  return (list || []).map(t => `<span class="mitre-tag">${t}</span>`).join('');
}

async function blockIp(ip) {
  await fetch('/api/block', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ip})});
  loadStats();
}

async function loadAlerts() {
  const data = await (await fetch('/api/alerts')).json();
  document.getElementById('alert-count').textContent = `alertes: ${data.count}`;
  document.getElementById('alerts-list').innerHTML = data.alerts.slice(0, 25).map(a => {
    const ts = a.timestamp ? a.timestamp.substring(11, 19) : '';
    const btn = a.src_ip ? `<span class="btn" onclick="blockIp('${a.src_ip}')">bloquer ${a.src_ip}</span>` : '';
    return `<div class="alert-item ${a.severity}">
      <span class="alert-sev">${a.severity}</span><span class="ts">${ts}</span>
      ${mitreTags(a.mitre)} — ${a.message || ''} ${btn}</div>`;
  }).join('');
}

async function loadIncidents() {
  const data = await (await fetch('/api/incidents')).json();
  document.getElementById('incidents-list').innerHTML = (data.incidents || []).map(i =>
    `<div class="incident-item"><span class="alert-sev">${i.severity}</span>
      <b>#${i.id}</b> ${i.title} — <span class="ts">${i.description || ''}</span></div>`
  ).join('') || '<div class="ts">aucun incident ouvert</div>';
}

async function loadStats() {
  const d = await (await fetch('/api/status')).json();
  document.getElementById('s-events').textContent = d.total_events ?? '—';
  document.getElementById('s-alerts').textContent = d.total_alerts ?? '—';
  document.getElementById('s-incidents').textContent = d.open_incidents ?? '—';
  document.getElementById('s-blocked').textContent = d.blocked_ips ?? '—';
  document.getElementById('incident-count').textContent = `incidents: ${d.open_incidents ?? '—'}`;
}

const evtSource = new EventSource('/api/stream');
evtSource.onmessage = (e) => {
  try {
    const alert = JSON.parse(e.data);
    if (alert.src_ip && nodes.get(alert.src_ip)) {
      nodes.update({ id: alert.src_ip, color: { background: '#e01e5a', border: '#e01e5a' } });
      setTimeout(() => nodes.update({ id: alert.src_ip,
        color: { background: '#21262d', border: '#58a6ff' } }), 2000);
    }
    loadAlerts(); loadIncidents(); loadStats();
  } catch (_) {}
};

loadTopology(); loadAlerts(); loadIncidents(); loadStats();
setInterval(loadTopology, 30000);
setInterval(loadAlerts, 10000);
setInterval(loadIncidents, 15000);
setInterval(loadStats, 5000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


def start_dashboard():
    threading.Thread(target=_topology_scanner, daemon=True, name="topo-scanner").start()
    host = loader.get("dashboard.flask_host", "0.0.0.0")
    port = loader.get("dashboard.flask_port", 5000)
    logger.info(f"Dashboard démarré sur http://{host}:{port}")
    app.run(host=host, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from config import loader as cfg_loader
    cfg_loader.load()
    logging.basicConfig(level=logging.INFO)
    start_dashboard()
