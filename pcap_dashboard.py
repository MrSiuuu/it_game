import streamlit as st
import pandas as pd
import json
import os
import time
import matplotlib.pyplot as plt
import requests
from datetime import datetime

# Configuration
API_BASE_URL = "http://93.127.203.48:5000"
PCAP_DIR = "challenge_pcaps"
REFRESH_INTERVAL = 30  # Rafraîchir toutes les 30 secondes

# Fonction pour récupérer le nom du fichier actif
def get_current_filename():
    try:
        response = requests.get(f"{API_BASE_URL}/pcap/latest/filename")
        if response.status_code == 200:
            return response.json().get("filename")
        return "Erreur de récupération"
    except Exception as e:
        return f"Erreur: {str(e)}"

# Fonction pour charger les flags obtenus
def load_flags():
    if os.path.exists("flags.txt"):
        flags = []
        with open("flags.txt", "r") as f:
            for line in f:
                parts = line.strip().split(" - ")
                if len(parts) >= 3:
                    flags.append({
                        "timestamp": parts[0],
                        "flag": parts[1],
                        "ip": parts[2]
                    })
        return flags
    return []

# Fonction pour charger l'historique des analyses
def load_analysis_history():
    history_file = "analysis_history.json"
    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            return json.load(f)
    return []

# Configuration de la page
st.set_page_config(
    page_title="Dashboard Challenge PCAP",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Titre et description
st.title("🔍 Dashboard Challenge PCAP")
st.markdown("""
Ce dashboard affiche l'état actuel du challenge PCAP, les fichiers analysés et les résultats obtenus.
""")

# Sidebar avec informations sur le challenge
with st.sidebar:
    st.header("Informations")
    st.markdown(f"**API URL**: {API_BASE_URL}")
    
    # Afficher le fichier actif
    current_file = get_current_filename()
    st.markdown(f"**Fichier actif**: {current_file}")
    
    # Afficher le nombre de flags obtenus
    flags = load_flags()
    st.markdown(f"**Flags obtenus**: {len(flags)}")
    
    # Bouton pour rafraîchir manuellement
    if st.button("🔄 Rafraîchir"):
        st.rerun()
    
    # Afficher le temps avant le prochain rafraîchissement
    st.markdown("---")
    st.markdown("Le dashboard se rafraîchit automatiquement toutes les 30 secondes.")
    
    # Afficher les instructions du challenge
    st.markdown("---")
    st.header("Instructions du challenge")
    st.markdown("""
    1. Un nouveau fichier PCAP est activé toutes les 30 minutes
    2. Chaque fichier contient des informations sur une machine infectée
    3. Il faut extraire:
       - Adresse MAC
       - Adresse IP
       - Hostname
       - Compte utilisateur Windows
    4. Ces informations doivent être soumises à l'API
    """)

# Créer un layout à deux colonnes
col1, col2 = st.columns([2, 1])

# Colonne 1: Historique des analyses
with col1:
    st.header("Historique des analyses")
    
    # Charger l'historique des analyses
    analysis_history = load_analysis_history()
    
    if analysis_history:
        # Créer un DataFrame pour l'affichage
        df = pd.DataFrame(analysis_history)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp", ascending=False)
        
        # Afficher le tableau
        st.dataframe(df[["timestamp", "filename", "infected_ip", "mac_address", "hostname", "windows_user", "success"]])
        
        # Afficher un graphique des IPs infectées
        st.subheader("IPs infectées détectées")
        ip_counts = df["infected_ip"].value_counts().head(10)
        fig, ax = plt.subplots(figsize=(10, 6))
        ip_counts.plot(kind="bar", ax=ax)
        st.pyplot(fig)
    else:
        st.info("Aucune analyse n'a encore été effectuée.")

# Colonne 2: Flags obtenus et fichiers PCAP
with col2:
    # Afficher les flags obtenus
    st.header("Flags obtenus")
    if flags:
        for flag in flags:
            st.success(f"**{flag['flag']}** - IP: {flag['ip']} - {flag['timestamp']}")
    else:
        st.info("Aucun flag n'a encore été obtenu.")
    
    # Afficher les fichiers PCAP disponibles
    st.header("Fichiers PCAP")
    if os.path.exists(PCAP_DIR):
        pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
        if pcap_files:
            for pcap_file in sorted(pcap_files, reverse=True):
                file_path = os.path.join(PCAP_DIR, pcap_file)
                file_size = os.path.getsize(file_path) / (1024 * 1024)  # Taille en MB
                file_time = os.path.getmtime(file_path)
                file_time_str = datetime.fromtimestamp(file_time).strftime("%Y-%m-%d %H:%M:%S")
                
                st.markdown(f"**{pcap_file}** - {file_size:.2f} MB - {file_time_str}")
        else:
            st.info("Aucun fichier PCAP n'a été téléchargé.")
    else:
        st.info("Le dossier des fichiers PCAP n'existe pas encore.")

# Ajouter un tableau de bord pour la dernière analyse
st.header("Dernière analyse")
if analysis_history:
    last_analysis = analysis_history[-1]
    
    # Créer des colonnes pour les informations
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Fichier", last_analysis["filename"])
    
    with col2:
        st.metric("IP infectée", last_analysis["infected_ip"])
    
    with col3:
        st.metric("Hostname", last_analysis["hostname"] or "Non trouvé")
    
    with col4:
        st.metric("Utilisateur", last_analysis["windows_user"] or "Non trouvé")
    
    # Afficher les détails de l'analyse
    with st.expander("Détails de l'analyse"):
        st.json(last_analysis)
else:
    st.info("Aucune analyse n'a encore été effectuée.")

# Ajouter un délai avant le rafraîchissement automatique
st.empty()
time.sleep(REFRESH_INTERVAL)
st.rerun() 