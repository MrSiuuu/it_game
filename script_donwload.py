import requests
import os
from datetime import datetime

# URL de l'API pour récupérer le dernier fichier .pcap
API_URL = "http://93.127.203.48:5000/pcap/latest"

# Dossier où on va stocker les fichiers
LOG_DIR = "logs"

# Crée le dossier s'il n'existe pas
os.makedirs(LOG_DIR, exist_ok=True)

# Nom du fichier avec la date du jour
today_str = datetime.now().strftime("%Y-%m-%d")
file_name = f"log_{today_str}.pcap"
file_path = os.path.join(LOG_DIR, file_name)

# Vérifie si le fichier du jour existe déjà
if os.path.exists(file_path):
    print(f"[✓] Le fichier '{file_name}' a déjà été téléchargé aujourd'hui.")
else:
    print(f"[*] Téléchargement de '{file_name}' depuis l'API...")

    try:
        response = requests.get(API_URL)
        content_type = response.headers.get('Content-Type', '')

        # Vérifie que c'est bien un fichier .pcap
        if response.status_code == 200 and ("pcap" in content_type or "application/octet-stream" in content_type):
            with open(file_path, 'wb') as f:
                f.write(response.content)
            print(f"[✓] Fichier enregistré dans : {file_path}")
        else:
            print("[!] Le contenu téléchargé n'est pas un fichier .pcap.")
            print(f"[i] Type de contenu : {content_type}")

    except Exception as e:
        print(f"[!] Une erreur est survenue : {e}")
