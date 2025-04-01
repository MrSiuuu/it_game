import pyshark
import requests
import json
import ipaddress
import os
import time

# === Clé API perso ===
VIRUSTOTAL_API_KEY = "ec5d009b7cea4342d4245ff7908b5105ce8d8e83a401f3cf071034299bcc8bfd"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# === Fichier pcap ===
pcap_file = "logs/log_2025-03-31.pcap"  # adapte si tu changes de date

# === Vérifie si une IP est publique ===
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

# === Appel API VirusTotal ===
def check_ip_virustotal(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        time.sleep(15)  # anti-rate-limit
        response = requests.get(VT_URL + ip, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['last_analysis_stats']['malicious']
        else:
            print(f"[!] Erreur API {response.status_code} pour IP {ip}")
            return "Erreur API"
    except Exception as e:
        print(f"[!] Exception pour {ip} : {e}")
        return "Erreur API"

# === Extraction IPs et protocoles ===
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
                    ip_details[ip] = {"protocols": set(), "connections": set()}

            ip_details[src_ip]["protocols"].add(protocol)
            ip_details[src_ip]["connections"].add(dst_ip)
            ip_details[dst_ip]["protocols"].add(protocol)
            ip_details[dst_ip]["connections"].add(src_ip)

    capture.close()

    # Convertir sets en listes
    for ip in ip_details:
        ip_details[ip]["protocols"] = list(ip_details[ip]["protocols"])
        ip_details[ip]["connections"] = list(ip_details[ip]["connections"])

    return ip_details

# === MAIN ===
def main():
    print("🔍 Analyse du fichier PCAP...")
    ip_details = extract_details_from_pcap(pcap_file)

    results = {}
    print("\n🌐 Analyse VirusTotal en cours...\n")
    for ip, details in ip_details.items():
        if is_public_ip(ip):
            vt_score = check_ip_virustotal(ip)
        else:
            vt_score = "IP locale (non testable)"

        results[ip] = {
            "malicious": vt_score,
            "protocols": details["protocols"],
            "connections": details["connections"]
        }
        print(f"{ip} → {vt_score}")

    # Export JSON
    with open("analyse_ips_vt.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
    print("\n✅ Résultats enregistrés dans : analyse_ips_vt.json")

if __name__ == "__main__":
    main()
