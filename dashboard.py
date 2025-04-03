import streamlit as st
import json
import pandas as pd
import matplotlib.pyplot as plt
import re
import requests
import glob
from datetime import datetime, timedelta
import os

# Fonction pour charger les analyses historiques
def load_historical_analyses():
    """Charge tous les fichiers d'analyse historiques"""
    files = glob.glob("analyse_ips_mitre_*.json")
    analyses = []
    
    for file in sorted(files, reverse=True):
        try:
            timestamp = re.search(r'analyse_ips_mitre_(\d{8}_\d{6})\.json', file)
            if timestamp:
                timestamp = timestamp.group(1)
                timestamp = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                
                with open(file, "r") as f:
                    data = json.load(f)
                
                analyses.append({
                    "timestamp": timestamp,
                    "filename": file,
                    "data": data
                })
        except Exception as e:
            print(f"Erreur lors du chargement du fichier {file}: {e}")
    
    return analyses

def extract_mitre_tactics(data):
    """Extrait toutes les tactiques MITRE des données"""
    tactics = set()
    
    for ip_info in data:
        # Tactique principale
        if "mitre_tactique" in ip_info and ip_info["mitre_tactique"]:
            tactics.add(ip_info["mitre_tactique"])
        
        # Autres tactiques
        for activity in ip_info.get("autres_activites", []):
            if isinstance(activity, dict) and "mitre_tactique" in activity and activity["mitre_tactique"]:
                tactics.add(activity["mitre_tactique"])
    
    return sorted(list(tactics))

# Configuration de la page
st.set_page_config(page_title="Analyse Réseau - IT GAME", layout="wide")

st.title("🔍 Dashboard d'analyse des IPs (PCAP + MITRE ATT&CK)")
st.markdown("Projet IT Game – Analyse automatique des fichiers `.pcap` enrichie avec **MITRE ATT&CK + Analyse locale**.")

# Sidebar pour les filtres
st.sidebar.header("🪰 Filtres")

# Charger l'historique des analyses
historical_analyses = load_historical_analyses()

# Option pour afficher l'historique des analyses
show_history = st.sidebar.checkbox("Afficher l'historique des analyses", value=False)

if show_history and historical_analyses:
    selected_analysis = st.sidebar.selectbox(
        "Sélectionner une analyse historique",
        options=range(len(historical_analyses)),
        format_func=lambda x: historical_analyses[x]["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    )
    
    data = historical_analyses[selected_analysis]["data"]
    timestamp = historical_analyses[selected_analysis]["timestamp"]
    
    st.markdown(f"## Analyse du {timestamp.strftime('%Y-%m-%d à %H:%M:%S')}")
else:
    # Charger les données les plus récentes
    try:
        with open("analyse_ips_mitre.json", "r") as f:
            data = json.load(f)
        st.markdown("## Analyse la plus récente")
    except:
        st.error("Aucune analyse disponible. Veuillez exécuter analyse1.py pour générer des données.")
        st.stop()

# Charger les anomalies globales
try:
    with open("anomalies_globales.json", "r") as f:
        anomalies_globales = json.load(f)
except:
    anomalies_globales = []

# Charger les champs absents
try:
    with open("champs_absents_log.json", "r") as f:
        champs_absents = json.load(f)
except:
    champs_absents = []

# Convertir les données en DataFrame
df = pd.DataFrame(data)

# Filtres
st.sidebar.subheader("Filtres de données")

# Filtre par type d'IP
ip_types = ["Toutes"] + sorted(df["ip_type"].unique().tolist())
selected_ip_type = st.sidebar.selectbox("Type d'IP", ip_types)

# Filtre par tactique MITRE
mitre_tactics = ["Toutes"] + extract_mitre_tactics(data)
selected_tactic = st.sidebar.selectbox("Tactique MITRE", mitre_tactics)

# Filtre par score de menace
min_score = st.sidebar.slider("Score de menace minimum", 0.0, 30.0, 0.0, 0.5)

# Filtre par protocole
all_protocols = set()
for protocols in df["protocoles"]:
    all_protocols.update(protocols)
selected_protocol = st.sidebar.selectbox("Protocole", ["Tous"] + sorted(list(all_protocols)))

# Appliquer les filtres
filtered_df = df.copy()

if selected_ip_type != "Toutes":
    filtered_df = filtered_df[filtered_df["ip_type"] == selected_ip_type]

if selected_tactic != "Toutes":
    # Filtrer par tactique principale
    main_tactic_mask = filtered_df["mitre_tactique"] == selected_tactic
    
    # Filtrer par tactiques secondaires
    other_tactics_mask = filtered_df.apply(
        lambda row: any(
            activity.get("mitre_tactique") == selected_tactic 
            for activity in row.get("autres_activites", [])
            if isinstance(activity, dict)
        ),
        axis=1
    )
    
    # Combiner les masques
    filtered_df = filtered_df[main_tactic_mask | other_tactics_mask]

if min_score > 0:
    filtered_df = filtered_df[filtered_df["threat_score"] >= min_score]

if selected_protocol != "Tous":
    filtered_df = filtered_df[filtered_df["protocoles"].apply(lambda x: selected_protocol in x)]

# Afficher les statistiques générales
st.markdown("## 📊 Statistiques générales")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Nombre d'IPs analysées", len(df))
with col2:
    st.metric("IPs suspectes (Score > 5)", len(df[df["threat_score"] > 5]))
with col3:
    st.metric("Pays détectés", df["country"].nunique())
with col4:
    st.metric("Protocoles uniques", len(set([p for protocols in df["protocoles"] for p in protocols])))

# Afficher les IPs les plus suspectes
st.markdown("## 🚨 Top 10 des IPs les plus suspectes")
top_ips = df.sort_values("threat_score", ascending=False).head(10)

for i, (_, ip_info) in enumerate(top_ips.iterrows()):
    col1, col2 = st.columns([1, 3])
    
    with col1:
        st.markdown(f"### #{i+1}: {ip_info['ip']}")
        st.markdown(f"**Score**: {ip_info['threat_score']:.1f}")
        st.markdown(f"**Type**: {ip_info['ip_type']}")
        st.markdown(f"**Pays**: {ip_info['country']}")
    
    with col2:
        st.markdown(f"**Activité principale**: {ip_info['type_activite']}")
        st.markdown(f"**Tactique MITRE**: {ip_info['mitre_tactique']}")
        st.markdown(f"**Technique MITRE**: {ip_info['mitre_technique']}")
        
        if ip_info['autres_activites']:
            st.markdown("**Autres activités détectées**:")
            for activity in ip_info['autres_activites']:
                st.markdown(f"- {activity['type_activite']} ({activity['mitre_tactique']})")
        
        # Afficher les anomalies
        anomalies = ip_info['anomalies_detectees']
        if any(len(anomalies[k]) > 0 for k in anomalies):
            with st.expander("Voir les anomalies détectées"):
                for category in ["http", "dns", "payload", "meta"]:
                    if anomalies[category]:
                        st.markdown(f"**Anomalies {category.upper()}**:")
                        for anomaly in anomalies[category]:
                            st.markdown(f"- {anomaly}")

# Afficher le tableau des IPs filtrées
st.markdown("## 📋 Tableau des IPs filtrées")
st.markdown(f"{len(filtered_df)} IPs correspondent aux critères de filtrage")

# Sélectionner les colonnes à afficher
display_columns = ["ip", "ip_type", "country", "threat_score", "mitre_tactique", "type_activite"]
st.dataframe(filtered_df[display_columns].sort_values("threat_score", ascending=False))

# Afficher les détails d'une IP spécifique
st.markdown("## 🔍 Détails d'une IP spécifique")
selected_ip = st.selectbox("Sélectionner une IP pour voir les détails", 
                          options=filtered_df["ip"].tolist(),
                          format_func=lambda x: f"{x} (Score: {filtered_df[filtered_df['ip'] == x]['threat_score'].values[0]:.1f})")

if selected_ip:
    ip_details = filtered_df[filtered_df["ip"] == selected_ip].iloc[0]
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"### IP: {ip_details['ip']}")
        st.markdown(f"**Type**: {ip_details['ip_type']}")
        st.markdown(f"**Pays**: {ip_details['country']}")
        st.markdown(f"**ASN**: {ip_details['asn']}")
        st.markdown(f"**Propriétaire AS**: {ip_details['as_owner']}")
        st.markdown(f"**Réseau**: {ip_details['network']}")
        
        # Afficher les timestamps
        if "first_seen" in ip_details and "last_seen" in ip_details:
            st.markdown(f"**Première observation**: {ip_details['first_seen']}")
            st.markdown(f"**Dernière observation**: {ip_details['last_seen']}")
    
    with col2:
        st.markdown("### Activité")
        st.markdown(f"**Score de menace**: {ip_details['threat_score']:.1f}")
        st.markdown(f"**Activité principale**: {ip_details['type_activite']}")
        st.markdown(f"**Tactique MITRE**: {ip_details['mitre_tactique']}")
        st.markdown(f"**Technique MITRE**: {ip_details['mitre_technique']}")
        
        # Afficher les statistiques de trafic
        st.markdown(f"**Nombre de paquets**: {ip_details['paquets']}")
        st.markdown(f"**Nombre de ports différents**: {ip_details['ports_diff']}")
    
    # Afficher les protocoles
    st.markdown("### Protocoles utilisés")
    st.write(", ".join(ip_details["protocoles"]))
    
    # Afficher les connexions
    st.markdown("### Connexions établies")
    st.write(", ".join(ip_details["connexions"]))
    
    # Afficher les autres activités
    if ip_details['autres_activites']:
        st.markdown("### Autres activités détectées")
        for activity in ip_details['autres_activites']:
            st.markdown(f"- **{activity['type_activite']}** ({activity['mitre_tactique']} - {activity['mitre_technique']})")
    
    # Afficher les anomalies
    anomalies = ip_details['anomalies_detectees']
    if any(len(anomalies[k]) > 0 for k in anomalies):
        st.markdown("### Anomalies détectées")
        
        tabs = st.tabs(["HTTP", "DNS", "Payload", "Meta"])
        
        with tabs[0]:
            if anomalies["http"]:
                for a in anomalies["http"]:
                    st.markdown(f"- {a}")
            else:
                st.info("Aucune anomalie HTTP détectée")
        
        with tabs[1]:
            if anomalies["dns"]:
                for a in anomalies["dns"]:
                    st.markdown(f"- {a}")
            else:
                st.info("Aucune anomalie DNS détectée")
        
        with tabs[2]:
            if anomalies["payload"]:
                for a in anomalies["payload"]:
                    if "HASH payload:" in a:
                        hash_val = a.split(":")[-1].strip()
                        st.code(f"HASH: {hash_val}")
                    else:
                        st.markdown(f"- {a}")
            else:
                st.info("Aucune anomalie de payload détectée")
        
        with tabs[3]:
            if anomalies["meta"]:
                for a in anomalies["meta"]:
                    st.markdown(f"- {a}")
            else:
                st.info("Aucune anomalie de métadonnées détectée")

# Afficher les graphiques
st.markdown("## 📈 Visualisations")

# Graphique des scores de menace
st.markdown("### 🦠 Distribution des scores de menace")
threat_scores = df["threat_score"]
fig, ax = plt.subplots(figsize=(10, 6))
pd.cut(threat_scores, bins=[0, 1, 2, 5, 10, 30]).value_counts().sort_index().plot(kind='bar', ax=ax)
ax.set_title("Distribution des scores de menace")
ax.set_xlabel("Score de menace")
ax.set_ylabel("Nombre d'IPs")
st.pyplot(fig)

# Graphique des tactiques MITRE
st.markdown("### 🛡️ Tactiques MITRE détectées")
mitre_tactics = df["mitre_tactique"].value_counts()
if not mitre_tactics.empty:
    fig, ax = plt.subplots(figsize=(10, 6))
    mitre_tactics.plot(kind='pie', ax=ax, autopct='%1.1f%%')
    ax.set_title("Répartition des tactiques MITRE")
    st.pyplot(fig)
else:
    st.info("Aucune tactique MITRE détectée")

# Graphique des protocoles
st.markdown("### 📊 Protocoles les plus fréquents")
all_protocols = []
for protocols in df["protocoles"]:
    all_protocols.extend(protocols)

protocol_counts = pd.Series(all_protocols).value_counts().head(10)
fig, ax = plt.subplots(figsize=(10, 6))
protocol_counts.plot(kind='bar', ax=ax)
ax.set_title("Top 10 des protocoles détectés")
ax.set_ylabel("Nombre d'occurrences")
st.pyplot(fig)

# Carte des pays (si disponible)
if "country" in df.columns and df["country"].nunique() > 1:
    st.markdown("### 🗺️ Répartition géographique")
    country_counts = df["country"].value_counts()
    fig, ax = plt.subplots(figsize=(10, 6))
    country_counts.plot(kind='pie', ax=ax, autopct='%1.1f%%')
    ax.set_title("Répartition par pays")
    st.pyplot(fig)

# Afficher les anomalies globales
if anomalies_globales:
    st.markdown("## 🔍 Anomalies globales")
    
    selected_type = st.selectbox("Voir toutes les anomalies de type", ["http", "dns", "payload", "meta"])
    
    count = 0
    for a in anomalies_globales:
        if selected_type in a and a[selected_type]:
            for ligne in a[selected_type]:
                if "HASH" in ligne:
                    hash_val = ligne.split(":")[-1].strip()
                    st.code(f"HASH: {hash_val}")
                else:
                    st.write(f"- {ligne}")
                count += 1
    if count == 0:
        st.info("Aucune anomalie de ce type détectée.")

# Afficher les champs absents (pour le débogage)
if champs_absents and st.sidebar.checkbox("Afficher les champs absents (debug)", value=False):
    st.sidebar.markdown("### Champs absents")
    for champ in champs_absents:
        st.sidebar.markdown(f"- {champ}")
