import pyshark
import requests
import json
import os
import glob

def extract_kerberos_info(pcap_file, filter_str="kerberos.CNameString and kerberos.addr_nb"):
    """
    Extrait les informations Kerberos d'un fichier PCAP : adresse MAC, IP, nom d'hôte, utilisateur Windows.
    """
    unique_results = {}
    capture = pyshark.FileCapture(pcap_file, display_filter=filter_str)

    for packet in capture:
        if hasattr(packet, 'kerberos'):
            kerberos_layer = packet.kerberos
            if hasattr(kerberos_layer, 'CNameString') and hasattr(kerberos_layer, 'addr_nb'):
                if "$" in kerberos_layer.CNameString.lower():
                    continue
                
                ip = packet.ip.src if hasattr(packet, 'ip') else (packet.ipv6.src if hasattr(packet, 'ipv6') else None)
                mac = packet.eth.src if hasattr(packet, 'eth') else None

                if ip and ip not in unique_results:
                    unique_results[ip] = (mac, ip, kerberos_layer.addr_nb, kerberos_layer.CNameString)
    
    capture.close()
    return list(unique_results.values())

def save_to_json(data, filename="results.json"):
    """Enregistre les données dans un fichier JSON sans écraser les anciennes entrées."""
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as file:
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    existing_data.append(data)

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(existing_data, file, indent=4, ensure_ascii=False)

def send_flag(info):
    """Envoie les informations extraites à l'API et enregistre le flag dans un fichier JSON."""
    url = "http://93.127.203.48:5000/pcap/submit"
    
    data = {
        "user_id": "marchand",  # Vérifiez si cela doit être un autre ID
        "lines": [
            info[0],  # MAC address
            info[1],  # IP address
            info[2],  # Host name
            info[3]   # Windows user account
        ]
    }

    try:
        print(f"Envoi des données : {data}")
        response = requests.post(url, json=data)
        response.raise_for_status()
        response_data = response.json()
        print("Réponse de l'API :", response_data)

        # Ajout du flag aux données avant d'enregistrer
        data["flag"] = response_data.get("flag", "Erreur : Flag non reçu")

        # Sauvegarde des résultats dans un fichier JSON
        save_to_json(data)

    except requests.exceptions.RequestException as e:
        print("Erreur lors de l'envoi de la requête :", e)
        data["flag"] = f"Erreur : {str(e)}"
        save_to_json(data)

def get_latest_pcap():
    """Récupère le chemin du fichier PCAP le plus récent dans le dossier logs"""
    logs_dir = "logs"
    pcap_files = glob.glob(os.path.join(logs_dir, "*.pcap"))
    
    if not pcap_files:
        # Si aucun fichier n'est trouvé dans logs, chercher dans le répertoire courant
        pcap_files = glob.glob("*.pcap")
        if not pcap_files:
            return None
    
    # Trier les fichiers par date de modification (le plus récent en premier)
    pcap_files.sort(key=os.path.getmtime, reverse=True)
    return pcap_files[0]

if __name__ == "__main__":
    # Récupérer le dernier fichier PCAP
    pcap_path = get_latest_pcap()
    
    if not pcap_path:
        print("Aucun fichier PCAP trouvé. Veuillez exécuter analyse1.py pour télécharger un fichier.")
    else:
        print(f"Utilisation du fichier PCAP: {pcap_path}")
        results = extract_kerberos_info(pcap_path)
        
        if results:
            for info in results:
                send_flag(info)
        else:
            print("Aucune information Kerberos valide trouvée.")