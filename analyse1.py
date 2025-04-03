import pyshark
import requests
import json
import ipaddress
import hashlib
from datetime import datetime
import base64
import io
import tempfile
import os
import time
import glob

# === CONFIGURATION ===
API_BASE_URL = "http://93.127.203.48:5000"
PCAP_DIR = "logs"  # Dossier pour stocker les fichiers PCAP
os.makedirs(PCAP_DIR, exist_ok=True)

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

# === FONCTIONS DE TÉLÉCHARGEMENT ===
def get_current_filename():
    """Récupère le nom du fichier PCAP actif"""
    try:
        response = requests.get(f"{API_BASE_URL}/pcap/latest/filename")
        if response.status_code == 200:
            return response.json().get("filename")
        return None
    except Exception as e:
        print(f"Erreur lors de la récupération du nom de fichier: {e}")
        return None

def download_latest_pcap():
    """Télécharge le dernier fichier PCAP disponible"""
    try:
        # Récupérer le nom du fichier actif
        filename = get_current_filename()
        if not filename:
            print("Impossible de récupérer le nom du fichier actif")
            return None
            
        filepath = os.path.join(PCAP_DIR, filename)
        
        # Vérifier si le fichier existe déjà
        if os.path.exists(filepath):
            print(f"Le fichier {filename} existe déjà localement")
            return filepath
        
        # Télécharger le fichier
        print(f"Téléchargement du fichier {filename}...")
        response = requests.get(f"{API_BASE_URL}/pcap/latest", stream=True)
        if response.status_code == 200:
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Fichier {filename} téléchargé avec succès")
            return filepath
        else:
            print(f"Erreur lors du téléchargement: {response.status_code}")
            return None
    except Exception as e:
        print(f"Erreur lors du téléchargement: {e}")
        return None

# === UTILS ===
def log_champ_absent(champ):
    if champ not in champs_absents:
        champs_absents.append(champ)

def is_public_ip(ip):
    """Vérifie si une adresse IP est publique (non privée)"""
    try:
        # Convertir l'adresse IP en objet ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        # Vérifier si l'IP est privée
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local)
    except:
        # En cas d'erreur (par exemple, si l'IP n'est pas valide), retourner False
        return False

def should_check_vt(ip_info):
    """Détermine si une IP doit être vérifiée sur VirusTotal"""
    # Vérifier si l'IP a des anomalies
    has_anomalies = any(len(ip_info["anomalies"][k]) > 0 for k in ip_info["anomalies"])
    
    # Vérifier si l'IP utilise des protocoles suspects
    suspicious_protocols = ["TOR", "IRC", "SMB", "RDP", "TELNET"]
    uses_suspicious_protocol = any(p in ip_info["protocols"] for p in suspicious_protocols)
    
    # Vérifier si l'IP a beaucoup de connexions
    many_connections = len(ip_info["connections"]) > 10
    
    return has_anomalies or uses_suspicious_protocol or many_connections

def detect_local_anomalies(packet):
    """Détecte les anomalies locales dans un paquet"""
    anomalies = {"http": [], "dns": [], "payload": [], "meta": []}
    
    # Vérifier les anomalies HTTP
    if hasattr(packet, 'http'):
        # Vérifier les méthodes HTTP suspectes
        if hasattr(packet.http, 'request_method'):
            method = packet.http.request_method
            if method not in ["GET", "POST", "HEAD"]:
                anomalies["http"].append(f"Méthode HTTP non standard: {method}")
        
        # Vérifier les User-Agents suspects
        if hasattr(packet.http, 'user_agent'):
            user_agent = packet.http.user_agent
            if any(x in user_agent.lower() for x in ["curl", "wget", "python", "go-http", "scanner", "nikto", "sqlmap"]):
                anomalies["http"].append(f"User-Agent suspect: {user_agent}")
        
        # Vérifier les tentatives de directory traversal
        if hasattr(packet.http, 'request_uri'):
            uri = packet.http.request_uri
            if "../" in uri or "..%2f" in uri.lower():
                anomalies["http"].append(f"Tentative de directory traversal: {uri}")
            
            # Vérifier les extensions de fichiers suspects dans les URI
            for ext in EXTENSIONS_SUSPICIEUSES:
                if uri.lower().endswith(ext):
                    anomalies["http"].append(f"Téléchargement de fichier suspect: {uri}")
                    break
        
        # Vérifier les codes de statut HTTP suspects
        if hasattr(packet.http, 'response_code'):
            code = packet.http.response_code
            if code in ["500", "501", "502", "503", "504", "505"]:
                anomalies["http"].append(f"Erreur serveur HTTP: {code}")
            elif code in ["400", "401", "403", "404", "405"]:
                anomalies["http"].append(f"Erreur client HTTP: {code}")
    
    # Vérifier les anomalies DNS
    if hasattr(packet, 'dns'):
        # Vérifier les requêtes DNS suspectes
        if hasattr(packet.dns, 'qry_name'):
            domain = packet.dns.qry_name
            
            # Vérifier les domaines suspects
            if len(domain) > 50:
                anomalies["dns"].append(f"Nom de domaine anormalement long: {domain}")
            
            # Vérifier l'entropie du domaine (noms aléatoires)
            if domain.count('.') > 4:
                anomalies["dns"].append(f"Domaine avec trop de sous-domaines: {domain}")
            
            # Vérifier si le domaine contient des caractères suspects
            if any(c.isdigit() for c in domain.split('.')[0]) and sum(c.isdigit() for c in domain.split('.')[0]) > 5:
                anomalies["dns"].append(f"Domaine avec beaucoup de chiffres: {domain}")
            
            # Vérifier si c'est un domaine sûr connu
            is_safe = any(safe in domain for safe in SAFE_DOMAINS)
            if not is_safe and domain.count('.') >= 2:
                # Extraire les données de la requête DNS
                if hasattr(packet.dns, 'qry_type'):
                    qtype = packet.dns.qry_type
                    if qtype in ["TXT", "NULL", "ANY"]:
                        anomalies["dns"].append(f"Type de requête DNS suspect: {qtype} pour {domain}")
    
    # Vérifier les anomalies de payload
    if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
        try:
            # Extraire les données brutes
            raw_data = packet.data.data
            
            # Vérifier les signatures de fichiers exécutables
            if "MZ" in raw_data[:10] or "PE" in raw_data[:10]:
                anomalies["payload"].append("Signature de fichier exécutable Windows détectée")
            elif "ELF" in raw_data[:10]:
                anomalies["payload"].append("Signature de fichier exécutable Linux détectée")
            
            # Vérifier les commandes shell
            shell_commands = ["cmd.exe", "powershell", "bash", "wget ", "curl ", "nc ", "ncat ", "certutil", "bitsadmin"]
            for cmd in shell_commands:
                if cmd in raw_data:
                    anomalies["payload"].append(f"Commande shell détectée: {cmd}")
            
            # Calculer le hash du payload pour référence
            try:
                data_bytes = bytes.fromhex(raw_data.replace(':', ''))
                if len(data_bytes) > 100:  # Ignorer les petits payloads
                    hash_sha256 = hashlib.sha256(data_bytes).hexdigest()
                    anomalies["payload"].append(f"HASH payload: {hash_sha256}")
            except:
                pass
        except:
            pass
    
    # Vérifier les métadonnées suspectes
    if hasattr(packet, 'tcp'):
        # Vérifier les ports suspects
        if hasattr(packet.tcp, 'dstport'):
            port = int(packet.tcp.dstport)
            suspicious_ports = [22, 23, 445, 1433, 3306, 3389, 4444, 5900, 8080, 8443, 9001]
            if port in suspicious_ports:
                anomalies["meta"].append(f"Port suspect: {port}")
    
    return anomalies

def get_mitre(ip, vt_score, protocols, port_count):
    """Détermine la tactique MITRE ATT&CK la plus probable"""
    # Déterminer le type d'activité en fonction des protocoles et du score
    if "DNS" in protocols and port_count > 5:
        return MITRE_DICT["port_scan"]
    elif "TLS" in protocols and port_count > 3:
        return MITRE_DICT["tls_suspect"]
    elif "HTTP" in protocols and port_count > 2:
        return MITRE_DICT["http_exfil"]
    elif "BROWSER" in protocols or "MDNS" in protocols:
        return MITRE_DICT["multicast_discovery"]
    elif "SMB" in protocols or "RDP" in protocols:
        return MITRE_DICT["lateral_movement"]
    elif "SSH" in protocols or "TELNET" in protocols:
        return MITRE_DICT["privilege_escalation"]
    else:
        # Par défaut, considérer comme reconnaissance
        return MITRE_DICT["port_scan"]

def get_advanced_mitre(protocols, connections):
    """Détecte des tactiques MITRE supplémentaires"""
    tactics = []
    
    # Vérifier les indicateurs de mouvement latéral
    if "SMB" in protocols or "RDP" in protocols:
        tactics.append({
            "type_activite": "Mouvement latéral",
            "mitre_tactique": "Lateral Movement",
            "mitre_technique": "Remote Services (T1021)"
        })
    
    # Vérifier les indicateurs de Command and Control
    if "HTTPS" in protocols and len(connections) > 5:
        tactics.append({
            "type_activite": "Communication C2",
            "mitre_tactique": "Command and Control",
            "mitre_technique": "Encrypted Channel (T1573)"
        })
    
    # Vérifier les indicateurs d'exfiltration
    if "HTTP" in protocols and len(connections) > 3:
        tactics.append({
            "type_activite": "Exfiltration de données",
            "mitre_tactique": "Exfiltration",
            "mitre_technique": "Exfiltration Over Web Service (T1567)"
        })
    
    return tactics

def calculate_threat_score(ip_info, protocols, connections, anomalies):
    """Calcule un score de menace basé sur différents facteurs"""
    score = 0
    
    # Nombre de protocoles différents
    score += min(len(protocols), 10) * 0.5
    
    # Nombre de connexions
    score += min(len(connections), 20) * 0.3
    
    # Anomalies détectées (facteur le plus important)
    for category in anomalies:
        score += len(anomalies[category]) * 2.0
    
    # Vérifier les protocoles suspects
    suspicious_protocols = ["SMB", "RDP", "SSH", "TELNET", "FTP", "IRC", "TOR"]
    for proto in suspicious_protocols:
        if proto in protocols:
            score += 3.0
    
    # Vérifier les connexions vers des IPs externes suspectes
    for conn in connections:
        if is_public_ip(conn) and not conn.startswith(("13.", "40.", "52.", "20.")):  # Exclure les IPs Microsoft
            score += 2.0
    
    return score

# === PCAP PARSING ===
def extract_packet_timestamps(packet):
    """Extrait le timestamp d'un paquet"""
    try:
        if hasattr(packet, 'sniff_time'):
            return packet.sniff_time
        return None
    except:
        return None

def extract_details_from_pcap(pcap_file):
    ip_data = {}
    packet_times = {}  # Dictionnaire pour stocker les timestamps par IP
    
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"
            
            # Extraire le timestamp
            timestamp = extract_packet_timestamps(packet)
            
            for ip in [src_ip, dst_ip]:
                if ip not in ip_data:
                    ip_data[ip] = {
                        "protocols": set(), "connections": set(), "count": 0,
                        "anomalies": {"http": [], "dns": [], "payload": [], "meta": []},
                        "first_seen": None,
                        "last_seen": None
                    }
                    packet_times[ip] = []
                
                # Mettre à jour les timestamps
                if timestamp:
                    packet_times[ip].append(timestamp)
                    if ip_data[ip]["first_seen"] is None or timestamp < ip_data[ip]["first_seen"]:
                        ip_data[ip]["first_seen"] = timestamp
                    if ip_data[ip]["last_seen"] is None or timestamp > ip_data[ip]["last_seen"]:
                        ip_data[ip]["last_seen"] = timestamp
            
            # Le reste du code reste inchangé
            anomalies = detect_local_anomalies(packet)
            for key in anomalies:
                ip_data[src_ip]["anomalies"][key].extend(anomalies[key])
            
            ip_data[src_ip]["protocols"].add(proto)
            ip_data[src_ip]["connections"].add(dst_ip)
            ip_data[dst_ip]["protocols"].add(proto)
            ip_data[dst_ip]["connections"].add(src_ip)
            ip_data[src_ip]["count"] += 1
    
    capture.close()
    
    # Finaliser les données
    for ip in ip_data:
        ip_data[ip]["protocols"] = list(ip_data[ip]["protocols"])
        ip_data[ip]["connections"] = list(ip_data[ip]["connections"])
        for k in ip_data[ip]["anomalies"]:
            ip_data[ip]["anomalies"][k] = list(set(ip_data[ip]["anomalies"][k]))
        
        # Convertir les timestamps en chaînes pour la sérialisation JSON
        if ip_data[ip]["first_seen"]:
            ip_data[ip]["first_seen"] = ip_data[ip]["first_seen"].isoformat()
        if ip_data[ip]["last_seen"]:
            ip_data[ip]["last_seen"] = ip_data[ip]["last_seen"].isoformat()
    
    return ip_data

# === MAIN ===
def main():
    """Fonction principale d'analyse"""
    # Télécharger le dernier fichier PCAP disponible
    pcap_path = download_latest_pcap()
    if not pcap_path:
        print("Échec du téléchargement, recherche d'un fichier local...")
        # Chercher des fichiers PCAP locaux
        local_pcaps = glob.glob(os.path.join(PCAP_DIR, "*.pcap"))
        if local_pcaps:
            pcap_path = local_pcaps[0]  # Utiliser le premier fichier trouvé
            print(f"Utilisation du fichier local: {pcap_path}")
        else:
            print("Aucun fichier PCAP trouvé localement")
            return
    
    # Analyser le fichier PCAP
    print(f"Analyse du fichier {pcap_path}...")
    ip_data = extract_details_from_pcap(pcap_path)
    
    # Traiter les données extraites
    processed_data = []
    
    # Date et heure actuelles pour l'horodatage
    now = datetime.now()
    current_date = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%H:%M:%S")
    
    # Traiter chaque IP
    for ip, info in ip_data.items():
        # Déterminer le type d'IP (interne ou externe)
        ip_type = "Interne" if not is_public_ip(ip) else "Externe"
        
        # Déterminer le pays (simplifié)
        country = "Local" if ip_type == "Interne" else "Inconnu"
        
        # Calculer le score de menace
        threat_score = calculate_threat_score(info, info["protocols"], info["connections"], info["anomalies"])
        
        # Déterminer l'activité principale et la tactique MITRE
        activity_info = get_mitre(ip, threat_score, info["protocols"], len(info["protocols"]))
        
        # Détecter d'autres tactiques MITRE
        other_activities = get_advanced_mitre(info["protocols"], info["connections"])
        
        # Créer l'entrée pour cette IP
        ip_entry = {
            "ip": ip,
            "date": current_date,
            "heure": current_time,
            "paquets": info["count"],
            "ports_diff": len(info["protocols"]),
            "protocoles": info["protocols"],
            "connexions": list(info["connections"]),
            "threat_score": threat_score,
            "ip_type": ip_type,
            "country": country,
            "asn": "N/A",
            "as_owner": "N/A",
            "network": "N/A",
            "type_activite": activity_info["type_activite"],
            "mitre_tactique": activity_info["mitre_tactique"],
            "mitre_technique": activity_info["mitre_technique"],
            "autres_activites": other_activities,
            "anomalies_detectees": info["anomalies"],
            "first_seen": info.get("first_seen", ""),
            "last_seen": info.get("last_seen", "")
        }
        
        processed_data.append(ip_entry)
    
    # Trier les données par score de menace (décroissant)
    processed_data.sort(key=lambda x: x["threat_score"], reverse=True)
    
    # Sauvegarder les résultats
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    
    # Sauvegarder les données traitées
    with open(f"analyse_ips_mitre_{timestamp}.json", "w") as f:
        json.dump(processed_data, f, indent=4)
    
    # Sauvegarder également dans un fichier fixe pour faciliter l'accès
    with open("analyse_ips_mitre.json", "w") as f:
        json.dump(processed_data, f, indent=4)
    
    # Sauvegarder les anomalies globales
    with open("anomalies_globales.json", "w") as f:
        json.dump(anomalies_globales, f, indent=4)
    
    # Sauvegarder les champs absents
    with open("champs_absents_log.json", "w") as f:
        json.dump(champs_absents, f, indent=4)
    
    print(f"Analyse terminée. {len(processed_data)} IPs trouvées.")
    return processed_data

# Configuration de l'API
API_BASE_URL = "http://93.127.203.48:5000"  # Remplacer par l'URL de l'API fournie
LOGS_DIR = "logs"  # Dossier pour stocker les fichiers PCAP

# Créer le dossier s'il n'existe pas
os.makedirs(LOGS_DIR, exist_ok=True)

def get_current_filename():
    """Récupère le nom du fichier PCAP actif"""
    try:
        response = requests.get(f"{API_BASE_URL}/pcap/latest/filename")
        if response.status_code == 200:
            return response.json().get("filename")
        return None
    except Exception as e:
        print(f"Erreur lors de la récupération du nom de fichier: {e}")
        return None

def download_pcap():
    """Télécharge le fichier PCAP actif"""
    try:
        filename = get_current_filename()
        if not filename:
            print("Impossible de récupérer le nom du fichier actif")
            return None
            
        filepath = os.path.join(LOGS_DIR, filename)
        
        # Vérifier si le fichier existe déjà
        if os.path.exists(filepath):
            print(f"Le fichier {filename} existe déjà localement")
            return filepath
        
        response = requests.get(f"{API_BASE_URL}/pcap/latest", stream=True)
        if response.status_code == 200:
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Fichier {filename} téléchargé avec succès")
            return filepath
        else:
            print(f"Erreur lors du téléchargement: {response.status_code}")
            return None
    except Exception as e:
        print(f"Erreur lors du téléchargement: {e}")
        return None

# Ajouter ces fonctions pour améliorer la couverture MITRE ATT&CK

def detect_collection_tactics(protocols, anomalies):
    """Détecte les tactiques de collection de données"""
    collection_info = {}
    
    # Vérifier les protocoles typiquement utilisés pour la collection
    if "HTTP" in protocols and any("POST" in a for a in anomalies.get("http", [])):
        collection_info = {
            "type_activite": "Collection de données via HTTP",
            "mitre_tactique": "Collection",
            "mitre_technique": "Data from Local System (T1005)"
        }
    elif "SMB" in protocols or "FTP" in protocols:
        collection_info = {
            "type_activite": "Transfert de fichiers",
            "mitre_tactique": "Collection",
            "mitre_technique": "Data Staged (T1074)"
        }
    elif "DNS" in protocols and len(anomalies.get("dns", [])) > 3:
        collection_info = {
            "type_activite": "Exfiltration via DNS",
            "mitre_tactique": "Collection",
            "mitre_technique": "Data from Network Shared Drive (T1039)"
        }
    
    return collection_info

def detect_persistence_tactics(protocols, anomalies):
    """Détecte les tactiques de persistance"""
    persistence_info = {}
    
    # Vérifier les indicateurs de persistance
    if "RPC" in protocols or "SMB" in protocols:
        if any("registry" in a.lower() for a in anomalies.get("payload", [])):
            persistence_info = {
                "type_activite": "Modification du registre",
                "mitre_tactique": "Persistence",
                "mitre_technique": "Registry Run Keys / Startup Folder (T1547.001)"
            }
        elif any("service" in a.lower() for a in anomalies.get("payload", [])):
            persistence_info = {
                "type_activite": "Création de service",
                "mitre_tactique": "Persistence",
                "mitre_technique": "Create or Modify System Process (T1543)"
            }
    elif "HTTP" in protocols and any("cron" in a.lower() or "scheduled task" in a.lower() for a in anomalies.get("payload", [])):
        persistence_info = {
            "type_activite": "Tâche planifiée",
            "mitre_tactique": "Persistence",
            "mitre_technique": "Scheduled Task/Job (T1053)"
        }
    
    return persistence_info

def detect_defense_evasion(protocols, anomalies):
    """Détecte les tactiques d'évasion de défense"""
    evasion_info = {}
    
    # Vérifier les indicateurs d'évasion
    if any("obfuscated" in a.lower() or "encoded" in a.lower() or "base64" in a.lower() for a in anomalies.get("payload", [])):
        evasion_info = {
            "type_activite": "Code obfusqué",
            "mitre_tactique": "Defense Evasion",
            "mitre_technique": "Obfuscated Files or Information (T1027)"
        }
    elif "TLS" in protocols and len(anomalies.get("meta", [])) > 2:
        evasion_info = {
            "type_activite": "Communication chiffrée",
            "mitre_tactique": "Defense Evasion",
            "mitre_technique": "Encrypted Channel (T1573)"
        }
    
    return evasion_info

def detect_impact_tactics(protocols, anomalies):
    """Détecte les tactiques d'impact"""
    impact_info = {}
    
    # Vérifier les indicateurs d'impact
    if any("encryption" in a.lower() or "ransom" in a.lower() for a in anomalies.get("payload", [])):
        impact_info = {
            "type_activite": "Chiffrement de données",
            "mitre_tactique": "Impact",
            "mitre_technique": "Data Encrypted for Impact (T1486)"
        }
    elif "ICMP" in protocols and len(anomalies.get("meta", [])) > 5:
        impact_info = {
            "type_activite": "Déni de service",
            "mitre_tactique": "Impact",
            "mitre_technique": "Network Denial of Service (T1498)"
        }
    
    return impact_info

def run_periodic_analysis(interval_minutes=30):
    """Exécute l'analyse périodiquement"""
    print(f"Démarrage de l'analyse périodique (intervalle: {interval_minutes} minutes)")
    
    while True:
        try:
            print(f"Exécution de l'analyse à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            main()
        except Exception as e:
            print(f"Erreur lors de l'analyse: {e}")
        
        # Attendre l'intervalle spécifié
        print(f"Prochaine analyse dans {interval_minutes} minutes")
        time.sleep(interval_minutes * 60)

# Modifier la partie principale pour permettre l'exécution périodique
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--periodic":
        # Exécution périodique
        interval = 30  # Par défaut: 30 minutes
        if len(sys.argv) > 2:
            try:
                interval = int(sys.argv[2])
            except:
                pass
        run_periodic_analysis(interval)
    else:
        # Exécution unique
        main()