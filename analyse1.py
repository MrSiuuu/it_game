import pyshark
import requests
import json
import ipaddress
import os
import time
from datetime import datetime

# === Clé API perso ===
VIRUSTOTAL_API_KEY = "ec5d009b7cea4342d4245ff7908b5105ce8d8e83a401f3cf071034299bcc8bfd"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
pcap_file = "logs/log_2025-03-31.pcap"

# === MITRE DICTIONNAIRE AVANCÉ ===
MITRE_DICT = {
    "port_scan": {
        "type_activite": "Scan de ports",
        "mitre_tactique": "Reconnaissance",
        "mitre_technique": "Active Scanning (T1595)"
    },
    "tls_suspect": {
        "type_activite": "Communication TLS suspecte",
        "mitre_tactique": "Command and Control",
        "mitre_technique": "Encrypted Channel (T1573)"
    },
    "http_exfil": {
        "type_activite": "Transfert HTTP suspect",
        "mitre_tactique": "Exfiltration",
        "mitre_technique": "Exfiltration Over Web Service (T1567)"
    },
    "multicast_discovery": {
        "type_activite": "Multicast / Discovery",
        "mitre_tactique": "Discovery",
        "mitre_technique": "Remote System Discovery (T1018)"
    }
}

# === Nouvelle détection avancée ===
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

    return {}

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def check_ip_virustotal(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        time.sleep(15)
        r = requests.get(VT_URL + ip, headers=headers)
        if r.status_code == 200:
            data = r.json()
            attr = data['data']['attributes']
            return {
                "malicious": attr['last_analysis_stats']['malicious'],
                "country": attr.get("country", "Inconnu"),
                "asn": attr.get("asn", "N/A"),
                "as_owner": attr.get("as_owner", "N/A"),
                "network": attr.get("network", "N/A")
            }
        else:
            print(f"[!] Erreur API {r.status_code} pour IP {ip}")
            return {"malicious": "Erreur API"}
    except Exception as e:
        print(f"[!] Exception pour {ip} : {e}")
        return {"malicious": "Erreur API"}

def extract_details_from_pcap(pcap_file):
    print(f"📥 Lecture du fichier : {pcap_file}")
    capture = pyshark.FileCapture(pcap_file)
    ip_details = {}

    for packet in capture:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"

            for ip in [src_ip, dst_ip]:
                if ip not in ip_details:
                    ip_details[ip] = {"protocols": set(), "connections": set(), "count": 0}

            ip_details[src_ip]["protocols"].add(protocol)
            ip_details[src_ip]["connections"].add(dst_ip)
            ip_details[dst_ip]["protocols"].add(protocol)
            ip_details[dst_ip]["connections"].add(src_ip)
            ip_details[src_ip]["count"] += 1

    capture.close()

    for ip in ip_details:
        ip_details[ip]["protocols"] = list(ip_details[ip]["protocols"])
        ip_details[ip]["connections"] = list(ip_details[ip]["connections"])

    return ip_details

# === MAIN ===
def main():
    print("🔍 Analyse du fichier PCAP...")
    ip_data = extract_details_from_pcap(pcap_file)
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    heure_str = now.strftime("%H:%M:%S")

    results = []
    print("\n🌐 Analyse VirusTotal en cours...\n")
    for ip, details in ip_data.items():
        if is_public_ip(ip):
            vt_info = check_ip_virustotal(ip)
            vt_score = vt_info.get("malicious", "Erreur API")
        else:
            vt_info = {}
            vt_score = "IP locale (non testable)"

        mitre_info = get_mitre(ip, vt_score, details["protocols"], len(details["protocols"]))
        advanced_mitre = get_advanced_mitre(details["protocols"], details["connections"])

        entry = {
            "ip": ip,
            "date": date_str,
            "heure": heure_str,
            "paquets": details["count"],
            "ports_diff": len(details["protocols"]),
            "protocoles": details["protocols"],
            "connexions": details["connections"],
            "vt_malicious": vt_score,
            "country": vt_info.get("country", "Inconnu"),
            "asn": vt_info.get("asn", "N/A"),
            "as_owner": vt_info.get("as_owner", "N/A"),
            "network": vt_info.get("network", "N/A"),
            **mitre_info,
            "autres_activites": advanced_mitre
        }

        results.append(entry)
        print(f"{ip} → {vt_score}")

    with open("analyse_ips_mitre.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\n✅ Résultats enrichis enregistrés dans : analyse_ips_mitre.json")

if __name__ == "__main__":
    main()
