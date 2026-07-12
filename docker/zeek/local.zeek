##! Mini-SOC — configuration Zeek (site/local.zeek)
##! Analyse protocolaire passive : conn, dns, http, ssl, files, notice.
##! Les logs sont écrits en JSON (LogAscii::use_json=T passé en CLI) et lus
##! par Vector, qui les normalise vers le schéma NetworkEvent.

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp
@load base/frameworks/files
@load base/frameworks/notice

# Détecte les scans (paquets vers des ports/hôtes fermés). Heuristiques utiles
# pour corréler avec Suricata côté Python.
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/notice/extend-email/hostnames

# Ajoute community-id à conn.log -> clé de jointure commune avec Suricata.
@load policy/protocols/conn/community-id-logging

# NB : l'enrichissement géographique n'est PAS chargé ici. Le script
# policy/protocols/conn/geo-data n'existe plus dans Zeek 6.x, et la géoloc
# est de toute façon réalisée côté moteur Python (base GeoLite2).

# Notre script de tagging MITRE.
@load ./mini-soc/mitre-tagging

redef LogAscii::use_json = T;

# Identifie le réseau local (utilisé par les heuristiques de scan/notice).
redef Site::local_nets += {
    192.168.0.0/16,
    10.0.0.0/8,
    172.16.0.0/12,
};

# Rotation des logs toutes les heures.
redef Log::default_rotation_interval = 1 hr;
