import pyshark
import requests
import json
import ipaddress
import hashlib
from datetime import datetime

# === CONFIGURATION ===
VIRUSTOTAL_API_KEY = "5287a157111d8e431e7d5b83f42ce9437974e6201575603f68b365025969ddf0"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
pcap_file = "logs/log_2025-03-31.pcap"

EXTENSIONS_SUSPICIEUSES = [".exe", ".dll", ".bin", ".msi", ".scr", ".com", ".pif", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".bz2", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".jar", ".apk", ".iso", ".img", ".py", ".hta"]
SAFE_DOMAINS = ["microsoft", "windowsupdate", "google", "facebook", "cloudflare", "youtube", "apple", "gstatic", "mozilla", "office365"]
ASN_SAFE_LIST = ["AS15169", "AS13335", "AS32934", "AS16509", "AS8075", "AS20940", "AS14618", "AS14061"]

# === MITRE DICT ===
MITRE_DICT = {
    "port_scan": {"type_activite": "Scan de ports", "mitre_tactique": "Reconnaissance", "mitre_technique": "Active Scanning (T1595)"},
    "tls_suspect": {"type_activite": "Communication TLS suspecte", "mitre_tactique": "Command and Control", "mitre_technique": "Encrypted Channel (T1573)"},
    "http_exfil": {"type_activite": "Transfert HTTP suspect", "mitre_tactique": "Exfiltration", "mitre_technique": "Exfiltration Over Web Service (T1567)"},
    "multicast_discovery": {"type_activite": "Multicast / Discovery", "mitre_tactique": "Discovery", "mitre_technique": "Remote System Discovery (T1018)"},
    "initial_access": {"type_activite": "Tentative d'accès initial", "mitre_tactique": "Initial Access", "mitre_technique": "Drive-by Compromise (T1189)"},
    "execution_script": {"type_activite": "Exécution de scripts malveillants", "mitre_tactique": "Execution", "mitre_technique": "Command and Scripting Interpreter (T1059)"},
    "privilege_escalation": {"type_activite": "Escalade de privilèges", "mitre_tactique": "Privilege Escalation", "mitre_technique": "Valid Accounts (T1078)"},
    "lateral_movement": {"type_activite": "Déplacement latéral", "mitre_tactique": "Lateral Movement", "mitre_technique": "Remote Services (T1021)"}
}

# === GLOBAUX ===
anomalies_globales = []
champs_absents = []

# === UTILS ===
def log_champ_absent(champ):
    if champ not in champs_absents:
        champs_absents.append(champ)

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def is_safe_domain(domain):
    return any(safe in domain for safe in SAFE_DOMAINS)

# === ANOMALIES LOCALES ===
def detect_local_anomalies(packet):
    anomalies = {"http": [], "dns": [], "payload": [], "meta": []}
    try:
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_full_uri'):
            url = packet.http.request_full_uri.lower()
            if not is_safe_domain(url) and any(ext in url for ext in EXTENSIONS_SUSPICIEUSES):
                anomalies["http"].append(f"URL suspecte : {url}")
                hash_url = hashlib.sha256(url.encode()).hexdigest()
                anomalies["http"] += [
                    f"HASH URL: {hash_url}",
                    f"🔎 Voir sur VirusTotal: https://www.virustotal.com/gui/file/{hash_url}"
                ]
        else:
            log_champ_absent("http.request_full_uri")

        if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
            domain = packet.dns.qry_name.lower()
            if not is_safe_domain(domain):
                anomalies["dns"].append(f"Domaine DNS inconnu: {domain}")
        else:
            log_champ_absent("dns.qry_name")

        raw_content = ""
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            raw_content = packet.tcp.payload.lower()
        elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
            raw_content = packet.udp.payload.lower()
        elif hasattr(packet, 'data') and hasattr(packet.data, 'data'):
            raw_content = packet.data.data.lower()
        else:
            log_champ_absent("payload")

        if raw_content:
            if any(cmd in raw_content for cmd in ['cmd', 'powershell']):
                anomalies["payload"].append("Commande malveillante détectée")
            if 'ipc$' in raw_content:
                anomalies["payload"].append("Accès SMB (IPC$) détecté")
            hash_payload = hashlib.sha256(raw_content.encode()).hexdigest()
            anomalies["payload"] += [
                f"HASH payload: {hash_payload}",
                f"🔎 Voir sur VirusTotal: https://www.virustotal.com/gui/file/{hash_payload}"
            ]
        else:
            anomalies["meta"].append("Pas de contenu applicatif")
    except Exception as e:
        anomalies["meta"].append(f"Erreur analyse : {e}")

    if any(anomalies.values()):
        anomalies_globales.append(anomalies)

    return anomalies

# === MITRE LOGIQUE ===
def get_mitre(ip, vt_score, protocols, ports_count):
    if vt_score == "IP locale (non testable)":
        return {}
    if "TLS" in protocols and isinstance(vt_score, int) and vt_score >= 5:
        return MITRE_DICT["tls_suspect"]
    if "HTTP" in protocols and isinstance(vt_score, int) and vt_score > 0:
        return MITRE_DICT["http_exfil"]
    if "SSDP" in protocols or "IGMP" in protocols:
        return MITRE_DICT["multicast_discovery"]
    if ports_count >= 10:
        return MITRE_DICT["port_scan"]
    if "HTTP" in protocols:
        return MITRE_DICT["initial_access"]
    return {}

def get_advanced_mitre(protocols, connexions):
    activites = []
    if "KERBEROS" in protocols or "LDAP" in protocols:
        activites.append({
            "type_activite": "Accès aux identifiants",
            "mitre_tactique": "Credential Access",
            "mitre_technique": "Brute Force (T1110)"
        })
    if "SMB" in protocols or "RPC_NETLOGON" in protocols or "WMI" in protocols:
        activites.append({
            "type_activite": "Persistance via services Windows",
            "mitre_tactique": "Persistence",
            "mitre_technique": "Create or Modify System Process (T1543)"
        })
    if "DNS" in protocols or "SSDP" in protocols or "IGMP" in protocols:
        if len(connexions) >= 3:
            activites.append({
                "type_activite": "Exploration réseau",
                "mitre_tactique": "Discovery",
                "mitre_technique": "Remote System Discovery (T1018)"
            })
    if "TLS" in protocols and len(connexions) == 1:
        activites.append({
            "type_activite": "Évasion via canal chiffré",
            "mitre_tactique": "Defense Evasion",
            "mitre_technique": "Obfuscated Files or Information (T1027)"
        })
    return activites

# === VIRUSTOTAL ===
def check_ip_virustotal(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(VT_URL + ip, headers=headers)
        if r.status_code == 200:
            attr = r.json()["data"]["attributes"]
            return {
                "malicious": attr['last_analysis_stats']['malicious'],
                "country": attr.get("country", "Inconnu"),
                "asn": attr.get("asn", "N/A"),
                "as_owner": attr.get("as_owner", "N/A"),
                "network": attr.get("network", "N/A")
            }
        else:
            return {"malicious": "Erreur API"}
    except:
        return {"malicious": "Erreur API"}

def should_check_vt(ip_info):
    if any(ip_info["anomalies"][k] for k in ip_info["anomalies"]):
        return True
    if any(p in ip_info["protocols"] for p in ["TLS", "HTTP", "SMB", "LDAP"]):
        return True
    return ip_info.get("asn", "") not in ASN_SAFE_LIST

# === PCAP PARSING ===
def extract_details_from_pcap(pcap_file):
    ip_data = {}
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"

            for ip in [src_ip, dst_ip]:
                if ip not in ip_data:
                    ip_data[ip] = {
                        "protocols": set(), "connections": set(), "count": 0,
                        "anomalies": {"http": [], "dns": [], "payload": [], "meta": []}
                    }

            anomalies = detect_local_anomalies(packet)
            for key in anomalies:
                ip_data[src_ip]["anomalies"][key].extend(anomalies[key])

            ip_data[src_ip]["protocols"].add(proto)
            ip_data[src_ip]["connections"].add(dst_ip)
            ip_data[dst_ip]["protocols"].add(proto)
            ip_data[dst_ip]["connections"].add(src_ip)
            ip_data[src_ip]["count"] += 1
    capture.close()

    for ip in ip_data:
        ip_data[ip]["protocols"] = list(ip_data[ip]["protocols"])
        ip_data[ip]["connections"] = list(ip_data[ip]["connections"])
        for k in ip_data[ip]["anomalies"]:
            ip_data[ip]["anomalies"][k] = list(set(ip_data[ip]["anomalies"][k]))

    return ip_data

# === MAIN ===
def main():
    ip_data = extract_details_from_pcap(pcap_file)
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    heure_str = now.strftime("%H:%M:%S")

    results = []

    for ip, info in ip_data.items():
        if is_public_ip(ip):
            vt_info = check_ip_virustotal(ip) if should_check_vt(info) else {}
            vt_score = vt_info.get("malicious", 0)
        else:
            vt_info = {}
            vt_score = "IP locale (non testable)"

        mitre_info = get_mitre(ip, vt_score, info["protocols"], len(info["protocols"]))
        advanced = get_advanced_mitre(info["protocols"], info["connections"])

        results.append({
            "ip": ip,
            "date": date_str,
            "heure": heure_str,
            "paquets": info["count"],
            "ports_diff": len(info["protocols"]),
            "protocoles": info["protocols"],
            "connexions": info["connections"],
            "vt_malicious": vt_score,
            "country": vt_info.get("country", "Inconnu"),
            "asn": vt_info.get("asn", "N/A"),
            "as_owner": vt_info.get("as_owner", "N/A"),
            "network": vt_info.get("network", "N/A"),
            **mitre_info,
            "autres_activites": advanced,
            "anomalies_detectees": info["anomalies"]
        })

    with open("analyse_ips_mitre.json", "w") as f:
        json.dump(results, f, indent=4)
    with open("anomalies_globales.json", "w") as f:
        json.dump(anomalies_globales, f, indent=4)
    with open("champs_absents_log.json", "w") as f:
        json.dump(champs_absents, f, indent=4)

    print("✅ Analyse terminée. Données enregistrées.")

if __name__ == "__main__":
    main()