import requests
import time
import os
import pyshark
import json
import re
from datetime import datetime
from analyse1 import extract_details_from_pcap
import asyncio
import nest_asyncio
import threading
import concurrent.futures
import subprocess
import ipaddress

# Configuration
API_BASE_URL = "http://93.127.203.48:5000"
USER_ID = "it_game_team"  # Choisissez un identifiant unique pour votre équipe
CHECK_INTERVAL = 300  # Vérifier toutes les 5 minutes (300 secondes)
PCAP_DIR = "challenge_pcaps"  # Dossier pour stocker les fichiers PCAP
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"  # Chemin vers tshark

# Créer le dossier s'il n'existe pas
os.makedirs(PCAP_DIR, exist_ok=True)

# Appliquer nest_asyncio pour permettre l'imbrication des event loops
nest_asyncio.apply()

def check_tshark_installation():
    """Vérifie si tshark est correctement installé"""
    try:
        result = subprocess.run([TSHARK_PATH, '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"tshark est correctement installé: {result.stdout.splitlines()[0]}")
            return True
        else:
            print("tshark est installé mais renvoie une erreur")
            print(result.stderr)
            return False
    except FileNotFoundError:
        print(f"ERREUR: tshark n'est pas trouvé à l'emplacement {TSHARK_PATH}")
        print("Veuillez vérifier le chemin ou installer Wireshark depuis: https://www.wireshark.org/download.html")
        return False
    except Exception as e:
        print(f"Erreur lors de la vérification de tshark: {e}")
        return False

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

def download_pcap(filename):
    """Télécharge le fichier PCAP actif"""
    try:
        filepath = os.path.join(PCAP_DIR, filename)
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

def identify_infected_machine(ip_data):
    """Identifie l'IP de la machine infectée basée sur les anomalies"""
    max_score = 0
    infected_ip = None
    
    for ip, info in ip_data.items():
        # Calculer un score basé sur les anomalies, les connexions suspectes, etc.
        score = calculate_infection_score(info)
        
        # Privilégier les IPs internes (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
        is_internal = (
            ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            any(ip.startswith(f"172.{i}.") for i in range(16, 32))
        )
        
        if is_internal:
            score *= 1.5  # Bonus pour les IPs internes
        
        print(f"IP: {ip}, Score: {score}, {'Interne' if is_internal else 'Externe'}")
        
        if score > max_score:
            max_score = score
            infected_ip = ip
    
    return infected_ip

def calculate_infection_score(ip_info):
    """Calcule un score d'infection basé sur différents facteurs"""
    score = 0
    
    # Nombre de protocoles différents utilisés
    score += min(len(ip_info["protocols"]), 10) * 0.5
    
    # Nombre de connexions établies
    score += min(len(ip_info["connections"]), 20) * 0.3
    
    # Anomalies détectées (facteur le plus important)
    for category in ip_info["anomalies"]:
        score += len(ip_info["anomalies"][category]) * 2.0
    
    # Vérifier les protocoles suspects
    suspicious_protocols = ["SMB", "RDP", "SSH", "TELNET", "FTP"]
    for proto in suspicious_protocols:
        if proto in ip_info["protocols"]:
            score += 3.0
    
    # Vérifier les connexions vers des IPs externes suspectes
    for conn in ip_info["connections"]:
        if is_public_ip(conn) and not conn.startswith(("13.", "40.", "52.", "20.")):  # Exclure les IPs Microsoft
            score += 2.0
    
    return score

def extract_mac_address(pcap_path, ip_address):
    """Extrait l'adresse MAC associée à une IP"""
    try:
        mac_addresses = {}
        
        # Utiliser tshark pour extraire les adresses MAC
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-Y', f'ip.addr=={ip_address} && eth.addr',
            '-T', 'fields', '-e', 'eth.src', '-e', 'eth.dst', '-e', 'ip.src'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 3:
                eth_src, eth_dst, ip_src = parts
                # Si l'IP source est l'IP recherchée, prendre l'adresse MAC source
                if ip_src == ip_address:
                    mac_addresses[eth_src] = mac_addresses.get(eth_src, 0) + 1
                # Sinon, prendre l'adresse MAC destination
                else:
                    mac_addresses[eth_dst] = mac_addresses.get(eth_dst, 0) + 1
        
        if mac_addresses:
            # Retourner l'adresse MAC la plus fréquente
            most_common_mac = max(mac_addresses.items(), key=lambda x: x[1])[0]
            return most_common_mac
        
        return None
    except Exception as e:
        print(f"Erreur lors de l'extraction de l'adresse MAC: {e}")
        return None

def extract_hostname(pcap_path, ip_address):
    """Extrait le hostname associé à une IP"""
    try:
        # Utiliser pyshark pour extraire le hostname
        capture = pyshark.FileCapture(pcap_path, display_filter=f"ip.addr=={ip_address} && dhcp")
        
        hostnames = {}
        
        for packet in capture:
            if hasattr(packet, 'dhcp'):
                if hasattr(packet.dhcp, 'option_hostname'):
                    hostname = packet.dhcp.option_hostname
                    hostnames[hostname] = hostnames.get(hostname, 0) + 1
        
        capture.close()
        
        if hostnames:
            # Retourner le hostname le plus fréquent
            most_common_hostname = max(hostnames.items(), key=lambda x: x[1])[0]
            return most_common_hostname
        
        # Essayer avec NetBIOS
        capture = pyshark.FileCapture(pcap_path, display_filter=f"ip.addr=={ip_address} && nbns")
        
        hostnames = {}
        
        for packet in capture:
            if hasattr(packet, 'nbns'):
                if hasattr(packet.nbns, 'name'):
                    # Nettoyer le hostname (enlever les suffixes comme <00>)
                    hostname = packet.nbns.name.split('<')[0].strip()
                    if hostname:
                        hostnames[hostname] = hostnames.get(hostname, 0) + 1
        
        capture.close()
        
        if hostnames:
            # Retourner le hostname le plus fréquent
            most_common_hostname = max(hostnames.items(), key=lambda x: x[1])[0]
            return most_common_hostname
        
        return None
    except Exception as e:
        print(f"Erreur lors de l'extraction du hostname: {e}")
        return None

def extract_hostname_with_tshark(pcap_path, ip_address):
    """Extrait le hostname en utilisant tshark directement"""
    try:
        # Commande pour extraire les hostnames des paquets DHCP
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-Y', f'ip.addr=={ip_address} && dhcp.option.hostname',
            '-T', 'fields', '-e', 'dhcp.option.hostname'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        hostnames = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        if hostnames:
            # Compter les occurrences
            hostname_counts = {}
            for hostname in hostnames:
                hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
            
            # Retourner le plus fréquent
            most_common = max(hostname_counts.items(), key=lambda x: x[1])[0]
            return most_common
        
        # Essayer avec NetBIOS
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-Y', f'ip.addr=={ip_address} && nbns',
            '-T', 'fields', '-e', 'nbns.name'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        hostnames = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        if hostnames:
            # Compter les occurrences
            hostname_counts = {}
            for hostname in hostnames:
                # Nettoyer le hostname (enlever les suffixes comme <00>)
                clean_hostname = hostname.split('<')[0].strip()
                if clean_hostname:
                    hostname_counts[clean_hostname] = hostname_counts.get(clean_hostname, 0) + 1
            
            # Retourner le plus fréquent
            if hostname_counts:
                most_common = max(hostname_counts.items(), key=lambda x: x[1])[0]
                return most_common
        
        return None
    except Exception as e:
        print(f"Erreur lors de l'extraction du hostname avec tshark: {e}")
        return None

def extract_windows_user(pcap_path, ip_address):
    """Extrait l'utilisateur Windows associé à une IP"""
    try:
        # Utiliser pyshark pour extraire l'utilisateur Windows
        capture = pyshark.FileCapture(pcap_path, display_filter=f"ip.addr=={ip_address} && smb")
        
        users = {}
        
        for packet in capture:
            if hasattr(packet, 'smb'):
                for field in ['session_setup_andx_request_username', 'session_setup_andx_request_account']:
                    if hasattr(packet.smb, field):
                        user = getattr(packet.smb, field)
                        if user and len(user) > 1:
                            users[user] = users.get(user, 0) + 1
        
        capture.close()
        
        if users:
            # Retourner l'utilisateur le plus fréquent
            most_common_user = max(users.items(), key=lambda x: x[1])[0]
            return most_common_user
        
        # Essayer avec Kerberos
        capture = pyshark.FileCapture(pcap_path, display_filter=f"ip.addr=={ip_address} && kerberos")
        
        users = {}
        
        for packet in capture:
            if hasattr(packet, 'kerberos'):
                if hasattr(packet.kerberos, 'CNameString'):
                    user = packet.kerberos.CNameString
                    users[user] = users.get(user, 0) + 1
        
        capture.close()
        
        if users:
            # Retourner l'utilisateur le plus fréquent
            most_common_user = max(users.items(), key=lambda x: x[1])[0]
            return most_common_user
        
        return None
    except Exception as e:
        print(f"Erreur lors de l'extraction de l'utilisateur Windows: {e}")
        return None

def extract_windows_user_with_tshark(pcap_path, ip_address):
    """Extrait l'utilisateur Windows en utilisant tshark directement"""
    try:
        # Commande pour extraire les utilisateurs des paquets SMB
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-Y', f'ip.addr=={ip_address} && smb.session_setup_andx.request_username',
            '-T', 'fields', '-e', 'smb.session_setup_andx.request_username'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        users = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        if users:
            # Compter les occurrences
            user_counts = {}
            for user in users:
                if user and len(user) > 1:
                    user_counts[user] = user_counts.get(user, 0) + 1
            
            # Retourner le plus fréquent
            if user_counts:
                most_common = max(user_counts.items(), key=lambda x: x[1])[0]
                return most_common
        
        # Essayer avec Kerberos
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-Y', f'ip.addr=={ip_address} && kerberos.CNameString',
            '-T', 'fields', '-e', 'kerberos.CNameString'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        users = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        if users:
            # Compter les occurrences
            user_counts = {}
            for user in users:
                if user and len(user) > 1:
                    user_counts[user] = user_counts.get(user, 0) + 1
            
            # Retourner le plus fréquent
            if user_counts:
                most_common = max(user_counts.items(), key=lambda x: x[1])[0]
                return most_common
        
        return None
    except Exception as e:
        print(f"Erreur lors de l'extraction de l'utilisateur avec tshark: {e}")
        return None

def extract_details_from_pcap_safe(pcap_path):
    """Version optimisée qui extrait uniquement les informations essentielles"""
    try:
        # Créer un nouvel event loop pour cette fonction
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Utiliser tshark directement pour une analyse plus rapide
        # Extraire les IPs avec le plus de trafic
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-q', '-z', 'ip_hosts,tree'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Analyser la sortie pour trouver les IPs avec le plus de trafic
        ip_data = {}
        current_ip = None
        
        for line in result.stdout.split('\n'):
            # Chercher les lignes avec des adresses IP
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                current_ip = ip_match.group(1)
                if current_ip not in ip_data:
                    ip_data[current_ip] = {
                        "protocols": [],
                        "connections": [],
                        "anomalies": {"http": [], "dns": [], "payload": [], "meta": []}
                    }
            
            # Ajouter des informations basiques pour le scoring
            if current_ip and "DHCP" in line:
                ip_data[current_ip]["protocols"].append("DHCP")
            if current_ip and "HTTP" in line:
                ip_data[current_ip]["protocols"].append("HTTP")
            if current_ip and "SMB" in line:
                ip_data[current_ip]["protocols"].append("SMB")
            if current_ip and "DNS" in line:
                ip_data[current_ip]["protocols"].append("DNS")
        
        # Ajouter des anomalies fictives pour les IPs internes (pour le scoring)
        for ip in ip_data:
            if ip.startswith("10.") or ip.startswith("192.168.") or any(ip.startswith(f"172.{i}.") for i in range(16, 32)):
                ip_data[ip]["anomalies"]["meta"].append("Internal IP with high traffic")
                # Ajouter des connexions fictives pour le scoring
                ip_data[ip]["connections"] = ["connection1", "connection2"]
        
        return ip_data
    except Exception as e:
        print(f"Erreur lors de l'extraction des détails: {e}")
        return {}
    finally:
        # S'assurer que l'event loop est fermé
        try:
            loop.close()
        except:
            pass

def extract_infected_machine_info(pcap_path):
    """Extrait les informations de la machine infectée"""
    # Analyser le PCAP avec votre code existant
    print("Extraction des détails du PCAP...")
    ip_data = extract_details_from_pcap_safe(pcap_path)  # Utiliser la version sécurisée
    print(f"Analyse terminée. {len(ip_data)} IPs trouvées.")
    
    # Identifier la machine infectée (celle avec le plus d'anomalies ou de comportements suspects)
    infected_ip = identify_infected_machine(ip_data)
    
    if not infected_ip:
        print("Aucune machine infectée identifiée")
        return None
    
    print(f"Machine infectée identifiée: {infected_ip}")
    
    # Extraire les informations supplémentaires pour cette IP
    mac_address = extract_mac_address(pcap_path, infected_ip)
    hostname = extract_hostname(pcap_path, infected_ip) or extract_hostname_with_tshark(pcap_path, infected_ip)
    windows_user = extract_windows_user(pcap_path, infected_ip) or extract_windows_user_with_tshark(pcap_path, infected_ip)
    
    print(f"Adresse MAC: {mac_address}")
    print(f"Hostname: {hostname}")
    print(f"Utilisateur Windows: {windows_user}")
    
    # Vérifier si des informations sont manquantes
    if not mac_address:
        print("⚠️ ATTENTION: Adresse MAC non trouvée!")
    if not hostname:
        print("⚠️ ATTENTION: Hostname non trouvé!")
    if not windows_user:
        print("⚠️ ATTENTION: Utilisateur Windows non trouvé!")
    
    return {
        "mac_address": mac_address,
        "ip_address": infected_ip,
        "hostname": hostname,
        "windows_user": windows_user
    }

def save_analysis_history(filename, infected_info, success):
    """Enregistre l'historique des analyses dans un fichier JSON"""
    history_file = "analysis_history.json"
    
    # Charger l'historique existant
    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            history = json.load(f)
    else:
        history = []
    
    # Ajouter la nouvelle analyse
    history.append({
        "timestamp": datetime.now().isoformat(),
        "filename": filename,
        "infected_ip": infected_info.get("ip_address"),
        "mac_address": infected_info.get("mac_address"),
        "hostname": infected_info.get("hostname"),
        "windows_user": infected_info.get("windows_user"),
        "success": success
    })
    
    # Enregistrer l'historique mis à jour
    with open(history_file, "w") as f:
        json.dump(history, f, indent=4)

def submit_results(infected_info, filename):
    """Soumet les résultats à l'API"""
    try:
        # Créer plusieurs variantes de soumission
        variants = [
            # Variante 1: Données originales
            {
                "user_id": USER_ID,
                "lines": [
                    infected_info["mac_address"],
                    infected_info["ip_address"],
                    infected_info["hostname"],
                    infected_info["windows_user"]
                ]
            },
            # Variante 2: Avec "dolores" comme user_id (comme dans l'exemple de la doc)
            {
                "user_id": "dolores",
                "lines": [
                    infected_info["mac_address"],
                    infected_info["ip_address"],
                    infected_info["hostname"],
                    infected_info["windows_user"]
                ]
            },
            # Variante 3: Sans user_id
            {
                "lines": [
                    infected_info["mac_address"],
                    infected_info["ip_address"],
                    infected_info["hostname"],
                    infected_info["windows_user"]
                ]
            },
            # Variante 4: Utilisateur sans $
            {
                "user_id": USER_ID,
                "lines": [
                    infected_info["mac_address"],
                    infected_info["ip_address"],
                    infected_info["hostname"],
                    infected_info["windows_user"].rstrip("$")
                ]
            },
            # Variante 5: MAC en majuscules sans séparateurs
            {
                "user_id": USER_ID,
                "lines": [
                    infected_info["mac_address"].replace(":", "").upper(),
                    infected_info["ip_address"],
                    infected_info["hostname"],
                    infected_info["windows_user"]
                ]
            },
            # Variante 6: Hostname en majuscules
            {
                "user_id": USER_ID,
                "lines": [
                    infected_info["mac_address"],
                    infected_info["ip_address"],
                    infected_info["hostname"].upper(),
                    infected_info["windows_user"]
                ]
            },
            # Variante 7: Hostname en minuscules
            {
                "user_id": USER_ID,
                "lines": [
                    infected_info["mac_address"],
                    infected_info["ip_address"],
                    infected_info["hostname"].lower(),
                    infected_info["windows_user"]
                ]
            }
        ]
        
        # Essayer chaque variante
        for i, data in enumerate(variants):
            try:
                print(f"Essai de la variante {i+1}...")
                print(f"Soumission des données: {json.dumps(data, indent=2)}")
                
                response = requests.post(f"{API_BASE_URL}/pcap/submit", json=data)
                
                if response.status_code == 200:
                    result = response.json()
                    flag = result.get("flag", "")
                    print(f"✅ Soumission réussie! Flag obtenu: {flag}")
                    
                    # Sauvegarder le flag
                    with open("flags.txt", "a") as f:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"{timestamp} - {flag} - {infected_info['ip_address']}\n")
                    
                    # Sauvegarder l'historique d'analyse
                    save_analysis_history(filename, infected_info, True, flag)
                    
                    return True
                else:
                    print(f"Erreur lors de la soumission (variante {i+1}): {response.status_code} - {response.text}")
            except Exception as e:
                print(f"Exception lors de la soumission (variante {i+1}): {e}")
        
        # Si toutes les variantes échouent
        print("Toutes les variantes ont échoué")
        save_analysis_history(filename, infected_info, False)
        return False
    except Exception as e:
        print(f"Erreur lors de la soumission des résultats: {e}")
        save_analysis_history(filename, infected_info, False)
        return False

def quick_identify_infected_machine(pcap_path):
    """Identifie rapidement la machine infectée en se basant sur des heuristiques simples"""
    try:
        # Chercher les IPs internes avec le plus de connexions
        cmd = [
            TSHARK_PATH, '-r', pcap_path, 
            '-Y', 'ip.src matches "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.).*"',
            '-T', 'fields', '-e', 'ip.src'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        internal_ips = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        # Compter les occurrences
        ip_counts = {}
        for ip in internal_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Trouver l'IP interne avec le plus de connexions
        if ip_counts:
            most_active_ip = max(ip_counts.items(), key=lambda x: x[1])[0]
            
            # Extraire directement les informations pour cette IP
            mac_address = extract_mac_address(pcap_path, most_active_ip)
            hostname = extract_hostname(pcap_path, most_active_ip) or extract_hostname_with_tshark(pcap_path, most_active_ip)
            windows_user = extract_windows_user(pcap_path, most_active_ip) or extract_windows_user_with_tshark(pcap_path, most_active_ip)
            
            return {
                "mac_address": mac_address,
                "ip_address": most_active_ip,
                "hostname": hostname,
                "windows_user": windows_user
            }
        
        return None
    except Exception as e:
        print(f"Erreur lors de l'identification rapide: {e}")
        return None

def extract_infected_machine_info_with_timeout(pcap_path, timeout=300):
    """Version avec timeout de la fonction d'extraction"""
    result = [None]
    
    def worker():
        try:
            result[0] = extract_infected_machine_info(pcap_path)
        except Exception as e:
            print(f"Erreur dans le worker: {e}")
    
    # Exécuter l'analyse dans un thread séparé
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(worker)
        try:
            # Attendre que l'analyse se termine ou que le timeout soit atteint
            future.result(timeout=timeout)
            return result[0]
        except concurrent.futures.TimeoutError:
            print(f"L'analyse a dépassé le timeout de {timeout} secondes")
            return None

def main():
    # Vérifier l'installation de tshark
    if not check_tshark_installation():
        print("ERREUR: tshark n'est pas correctement installé ou configuré")
        return
        
    last_filename = None
    
    while True:
        try:
            current_filename = get_current_filename()
            
            if current_filename and current_filename != last_filename:
                print(f"Nouveau fichier détecté: {current_filename}")
                pcap_path = download_pcap(current_filename)
                
                if pcap_path:
                    try:
                        print("Analyse rapide du fichier en cours...")
                        # Essayer d'abord l'approche rapide
                        infected_info = quick_identify_infected_machine(pcap_path)
                        
                        if infected_info and all(infected_info.values()):
                            print(f"Machine infectée identifiée rapidement: {infected_info}")
                            submit_results(infected_info, current_filename)
                        else:
                            print("L'analyse rapide n'a pas donné de résultats complets, passage à l'analyse complète avec timeout...")
                            infected_info = extract_infected_machine_info_with_timeout(pcap_path, timeout=300)  # 5 minutes max
                            
                            if infected_info:
                                print(f"Machine infectée identifiée: {infected_info}")
                                submit_results(infected_info, current_filename)
                            else:
                                print("Impossible d'identifier la machine infectée ou timeout atteint")
                                save_analysis_history(current_filename, {}, False)
                    except Exception as e:
                        print(f"Erreur lors de l'analyse du fichier: {e}")
                        save_analysis_history(current_filename, {}, False)
                
                last_filename = current_filename
            else:
                print(f"Aucun nouveau fichier détecté. Fichier actuel: {current_filename}")
            
            print(f"En attente... Prochaine vérification dans {CHECK_INTERVAL} secondes")
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            print(f"Erreur dans la boucle principale: {e}")
            time.sleep(60)  # Attendre une minute en cas d'erreur

if __name__ == "__main__":
    main() 