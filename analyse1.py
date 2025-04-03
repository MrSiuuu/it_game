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

# === CONFIGURATION ===
VIRUSTOTAL_API_KEY = "ec5d009b7cea4342d4245ff7908b5105ce8d8e83a401f3cf071034299bcc8bfd"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
pcap_file = "logs/log_2025-04-02-15h.pcap"

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

# === FONCTION D'ENVOI À VIRUSTOTAL ===
def submit_to_virustotal(content, filename="suspicious_file"):
    """Envoie directement un fichier à VirusTotal et retourne l'ID d'analyse"""
    try:
        # Préparer les données pour l'API VirusTotal
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "accept": "application/json"
        }
        
        # S'assurer que le contenu est binaire et non vide
        if isinstance(content, str):
            content = content.encode()
        
        # Vérifier que le contenu n'est pas vide
        if not content or len(content) < 10:
            return {
                "success": False,
                "error": "Contenu trop petit pour être analysé",
                "permalink": None
            }
        
        # Créer un fichier temporaire
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(content)
            temp_path = temp.name
        
        # Envoyer le fichier à VirusTotal
        with open(temp_path, 'rb') as file:
            files = {'file': (filename, file)}
            response = requests.post(url, headers=headers, files=files)
        
        # Supprimer le fichier temporaire
        os.unlink(temp_path)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get('data', {}).get('id', '')
            file_id = result.get('data', {}).get('links', {}).get('self', '').split('/')[-1]
            
            return {
                "success": True,
                "analysis_id": analysis_id,
                "file_id": file_id,
                "permalink": f"https://www.virustotal.com/gui/file/{file_id}/detection"
            }
        else:
            return {
                "success": False,
                "error": f"Erreur API: {response.status_code} - {response.text}",
                "permalink": None
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Exception: {str(e)}",
            "permalink": None
        }

# === ANOMALIES LOCALES ===
def detect_local_anomalies(packet):
    anomalies = {"http": [], "dns": [], "payload": [], "meta": []}
    try:
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_full_uri'):
            url = packet.http.request_full_uri.lower()
            if not is_safe_domain(url) and any(ext in url for ext in EXTENSIONS_SUSPICIEUSES):
                anomalies["http"].append(f"URL suspecte : {url}")
                
                # Si l'URL contient un fichier binaire, essayer de le télécharger et l'envoyer à VT
                if any(ext in url for ext in [".exe", ".dll", ".bin"]):
                    try:
                        file_response = requests.get(url, timeout=5)
                        if file_response.status_code == 200:
                            file_content = file_response.content
                            filename = url.split('/')[-1]
                            vt_result = submit_to_virustotal(file_content, filename)
                            
                            if vt_result["success"]:
                                anomalies["http"] += [
                                    f"✅ Fichier envoyé à VirusTotal: {filename}",
                                    f"🔎 Voir l'analyse: {vt_result['permalink']}"
                                ]
                            else:
                                anomalies["http"].append(f"❌ Échec d'envoi à VirusTotal: {vt_result['error']}")
                                
                            # Toujours calculer le hash pour référence
                            hash_url = hashlib.sha256(url.encode()).hexdigest()
                            file_hash = hashlib.sha256(file_content).hexdigest()
                            anomalies["http"] += [
                                f"HASH URL: {hash_url}",
                                f"HASH Fichier: {file_hash}",
                                f"🔎 Voir sur VirusTotal: https://www.virustotal.com/gui/file/{file_hash}"
                            ]
                    except Exception as e:
                        # En cas d'échec, revenir à la méthode du hash
                        hash_url = hashlib.sha256(url.encode()).hexdigest()
                        anomalies["http"] += [
                            f"HASH URL: {hash_url}",
                            f"🔎 Voir sur VirusTotal: https://www.virustotal.com/gui/file/{hash_url}",
                            f"❌ Échec téléchargement: {str(e)}"
                        ]
                else:
                    # Comportement standard pour les URLs non-binaires
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
        raw_bytes = None
        
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            try:
                # Convertir la représentation hex en bytes réels
                raw_bytes = bytes.fromhex(packet.tcp.payload.replace(':', ''))
                hash_payload = hashlib.sha256(raw_bytes).hexdigest()
                raw_content = packet.tcp.payload.lower()
            except:
                raw_content = packet.tcp.payload.lower()
                hash_payload = hashlib.sha256(raw_content.encode()).hexdigest()
                
        elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
            try:
                raw_bytes = bytes.fromhex(packet.udp.payload.replace(':', ''))
                hash_payload = hashlib.sha256(raw_bytes).hexdigest()
                raw_content = packet.udp.payload.lower()
            except:
                raw_content = packet.udp.payload.lower()
                hash_payload = hashlib.sha256(raw_content.encode()).hexdigest()
                
        elif hasattr(packet, 'data') and hasattr(packet.data, 'data'):
            try:
                raw_bytes = bytes.fromhex(packet.data.data.replace(':', ''))
                hash_payload = hashlib.sha256(raw_bytes).hexdigest()
                raw_content = packet.data.data.lower()
            except:
                raw_content = packet.data.data.lower()
                hash_payload = hashlib.sha256(raw_content.encode()).hexdigest()
        else:
            log_champ_absent("payload")
            anomalies["meta"].append("Pas de contenu applicatif")
            return anomalies

        if raw_content:
            # Détection de contenu suspect
            if any(cmd in raw_content for cmd in ['cmd', 'powershell']):
                anomalies["payload"].append("Commande malveillante détectée")
            if 'ipc$' in raw_content:
                anomalies["payload"].append("Accès SMB (IPC$) détecté")
                
            # Si le contenu semble être un exécutable ou un script
            is_executable = False
            if raw_bytes:
                # Vérifier les signatures d'en-tête de fichiers exécutables
                if ((len(raw_bytes) > 2 and raw_bytes[0:2] == b'MZ') or    # PE/EXE
                    (len(raw_bytes) > 4 and raw_bytes[0:4] == b'\x7FELF') or    # ELF
                    (raw_bytes.startswith(b'#!/')) or    # Script
                    (b'powershell' in raw_bytes) or    # PowerShell
                    (b'function ' in raw_bytes and b'return' in raw_bytes)):    # Script
                    is_executable = True
            
            if is_executable:
                # Vérifier d'abord si le hachage existe sur VirusTotal
                hash_check = check_hash_on_virustotal(hash_payload)
                
                if hash_check["exists"]:
                    # Le fichier est déjà connu de VirusTotal
                    malicious = hash_check.get("malicious_count", 0)
                    suspicious = hash_check.get("suspicious_count", 0)
                    
                    if malicious > 0 or suspicious > 0:
                        anomalies["payload"] += [
                            f"⚠️ Fichier MALVEILLANT détecté sur VirusTotal: {malicious} détections",
                            f"🔎 Voir l'analyse: {hash_check['permalink']}",
                            f"HASH payload: {hash_payload}"
                        ]
                    else:
                        anomalies["payload"] += [
                            f"✅ Fichier vérifié sur VirusTotal (non malveillant)",
                            f"🔎 Voir l'analyse: {hash_check['permalink']}",
                            f"HASH payload: {hash_payload}"
                        ]
                else:
                    # Le fichier n'est pas connu, l'envoyer à VirusTotal
                    filename = f"suspicious_payload_{hash_payload[:8]}.bin"
                    vt_result = submit_to_virustotal(raw_bytes, filename)
                    
                    if vt_result["success"]:
                        anomalies["payload"] += [
                            f"✅ Contenu suspect envoyé à VirusTotal",
                            f"🔎 Voir l'analyse: {vt_result['permalink']}",
                            f"HASH payload: {hash_payload}"
                        ]
                    else:
                        anomalies["payload"] += [
                            f"❌ Échec d'envoi à VirusTotal: {vt_result['error']}",
                            f"HASH payload: {hash_payload}",
                            f"🔎 Voir sur VirusTotal: https://www.virustotal.com/gui/file/{hash_payload}"
                        ]
            else:
                # Comportement standard
                anomalies["payload"] += [
                    f"HASH payload: {hash_payload}",
                    f"🔎 Voir sur VirusTotal: https://www.virustotal.com/gui/file/{hash_payload}"
                ]
        else:
            anomalies["meta"].append("Pas de contenu applicatif")

        # Analyse approfondie des requêtes HTTP
        if hasattr(packet, 'http'):
            # Vérifier si c'est une requête HTTP
            if hasattr(packet.http, 'request'):
                # Extraire la méthode HTTP
                if hasattr(packet.http, 'request_method'):
                    method = packet.http.request_method
                    if method not in ["GET", "HEAD", "OPTIONS"]:
                        anomalies["http"].append(f"Méthode HTTP non standard: {method}")
                
                # Extraire et analyser le User-Agent
                if hasattr(packet.http, 'user_agent'):
                    user_agent = packet.http.user_agent
                    suspicious_agents = ["curl", "wget", "python-requests", "Go-http-client", 
                                        "malware", "bot", "scan", "nikto", "sqlmap"]
                    if any(agent in user_agent.lower() for agent in suspicious_agents):
                        anomalies["http"].append(f"User-Agent suspect: {user_agent}")
                
                # Analyser les headers pour détecter des comportements suspects
                if hasattr(packet.http, 'request_line'):
                    request_line = packet.http.request_line
                    if "/../" in request_line or "/etc/" in request_line or "/bin/" in request_line:
                        anomalies["http"].append(f"Tentative de directory traversal: {request_line}")
            
            # Vérifier si c'est une réponse HTTP
            if hasattr(packet.http, 'response'):
                # Analyser le code de statut
                if hasattr(packet.http, 'response_code'):
                    code = int(packet.http.response_code)
                    if code >= 500:
                        anomalies["http"].append(f"Erreur serveur HTTP: {code}")
                    elif code == 403 or code == 401:
                        anomalies["http"].append(f"Accès refusé: {code}")
                
                # Analyser le type de contenu
                if hasattr(packet.http, 'content_type'):
                    content_type = packet.http.content_type
                    suspicious_types = ["application/x-executable", "application/octet-stream", 
                                       "application/x-dosexec", "application/x-msdownload"]
                    if any(stype in content_type for stype in suspicious_types):
                        anomalies["http"].append(f"Type de contenu suspect: {content_type}")
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

# Au début du script
HASH_CACHE = {}

def check_hash_on_virustotal(file_hash):
    """Vérifie si un hachage existe réellement sur VirusTotal"""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "accept": "application/json"
        }
        response = requests.get(url, headers=headers)
        
        # Vérifier si la réponse est valide et contient des données
        if response.status_code == 200 and 'data' in response.json():
            result = response.json()
            # Vérifier si l'attribut 'last_analysis_stats' existe
            if 'attributes' in result.get('data', {}) and 'last_analysis_stats' in result['data']['attributes']:
                stats = result['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                # Vérifier si le fichier existe réellement en testant un autre attribut
                if 'meaningful_name' in result['data']['attributes'] or 'type_description' in result['data']['attributes']:
                    return {
                        "exists": True,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                    }
        
        # Si on arrive ici, le fichier n'existe pas ou la réponse est invalide
        return {"exists": False, "error": "Fichier non trouvé sur VirusTotal"}
    except Exception as e:
        return {"exists": False, "error": str(e)}

def check_multiple_hashes(hash_list):
    """Vérifie plusieurs hachages en une seule requête"""
    if not hash_list:
        return {}
    
    # Limiter à 100 hachages par requête (limite de l'API)
    hash_batch = hash_list[:100]
    hash_str = ", ".join([f'"{h}"' for h in hash_batch])
    
    try:
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "accept": "application/json",
            "content-type": "application/json"
        }
        
        data = {
            "data": {
                "type": "file_batch",
                "attributes": {
                    "hashes": hash_batch
                }
            }
        }
        
        response = requests.post(url + "/analyse", headers=headers, json=data)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

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
    # Télécharger le fichier PCAP actif
    pcap_file_path = download_pcap()
    if not pcap_file_path:
        print("Impossible de télécharger le fichier PCAP")
        return
    
    print(f"Analyse du fichier: {pcap_file_path}")
    
    # Analyser le fichier PCAP
    ip_data = extract_details_from_pcap(pcap_file_path)
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
        
        # Obtenir les informations MITRE
        mitre_info = get_mitre(ip, vt_score, info["protocols"], len(info["protocols"]))
        advanced = get_advanced_mitre(info["protocols"], info["connections"])
        
        # Ajouter les nouvelles tactiques MITRE
        collection_info = detect_collection_tactics(info["protocols"], info["anomalies"])
        persistence_info = detect_persistence_tactics(info["protocols"], info["anomalies"])
        
        if collection_info:
            advanced.append(collection_info)
        if persistence_info:
            advanced.append(persistence_info)
        
        # Créer l'entrée de résultat
        result_entry = {
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
            "anomalies_detectees": info["anomalies"],
            "first_seen": info.get("first_seen"),
            "last_seen": info.get("last_seen")
        }
        
        results.append(result_entry)
    
    # Sauvegarder les résultats
    with open("analyse_ips_mitre.json", "w") as f:
        json.dump(results, f, indent=4)
    with open("anomalies_globales.json", "w") as f:
        json.dump(anomalies_globales, f, indent=4)
    with open("champs_absents_log.json", "w") as f:
        json.dump(champs_absents, f, indent=4)
    
    print("✅ Analyse terminée. Données enregistrées.")
    
    # Ajouter un timestamp au nom de fichier pour conserver l'historique
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    with open(f"analyse_ips_mitre_{timestamp}.json", "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"✅ Sauvegarde historique créée: analyse_ips_mitre_{timestamp}.json")

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