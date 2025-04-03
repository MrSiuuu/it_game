import streamlit as st
import json
import pandas as pd
import matplotlib.pyplot as plt
import re
import requests
import glob
from datetime import datetime, timedelta
import os

# Ajouter cette fonction pour formater les hachages
def format_hash_display(hash_value):
    """Formate un hachage pour un affichage plus lisible"""
    if len(hash_value) >= 64:  # SHA-256
        return f"{hash_value[:8]}...{hash_value[-8:]}"
    elif len(hash_value) >= 40:  # SHA-1
        return f"{hash_value[:6]}...{hash_value[-6:]}"
    else:
        return hash_value

def verify_vt_link(hash_value):
    """Vérifie si un lien VirusTotal est valide avant de l'afficher"""
    try:
        # Importer la clé API de analyse1.py
        from analyse1 import VIRUSTOTAL_API_KEY
        
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "accept": "application/json"
        }
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200 and 'data' in response.json():
            return True
        return False
    except:
        return False

# Ajouter cette fonction pour soumettre un hachage à VirusTotal
def submit_hash_to_vt(hash_value):
    """Soumet un hachage à VirusTotal pour analyse"""
    from analyse1 import VIRUSTOTAL_API_KEY, submit_to_virustotal
    import requests
    import tempfile
    import os
    
    try:
        # Créer un fichier plus substantiel avec le hachage
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            # Créer un contenu plus substantiel pour éviter les rejets
            content = f"HASH: {hash_value}\n"
            content += "Ce fichier a été créé pour soumettre un hachage à VirusTotal.\n"
            content += "Il ne contient aucun code malveillant.\n"
            content += "=" * 100  # Ajouter du remplissage
            temp.write(content.encode())
            temp_path = temp.name
        
        # Soumettre le fichier à VirusTotal
        result = submit_to_virustotal(open(temp_path, 'rb').read(), f"hash_{hash_value[:8]}.bin")
        
        # Supprimer le fichier temporaire
        os.unlink(temp_path)
        
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}

def rescan_hash_on_vt(hash_value):
    """Demande à VirusTotal de rescanner un fichier par son hachage"""
    from analyse1 import VIRUSTOTAL_API_KEY
    import requests
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}/analyse"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "accept": "application/json"
        }
        
        response = requests.post(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get('data', {}).get('id', '')
            return {
                "success": True,
                "analysis_id": analysis_id,
                "permalink": f"https://www.virustotal.com/gui/file-analysis/{analysis_id}/detection"
            }
        else:
            return {
                "success": False,
                "error": f"Erreur API: {response.status_code}",
                "permalink": None
            }
    except Exception as e:
        return {"success": False, "error": str(e)}

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

st.set_page_config(page_title="Analyse Réseau - IT GAME", layout="wide")

st.title("🔍 Dashboard d'analyse des IPs (PCAP + MITRE + Analyses VirusTotal)")
st.markdown("Projet IT Game – Analyse automatique des fichiers `.pcap` enrichie avec **VirusTotal + MITRE ATT&CK + Analyse locale**.")

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
    
    # Utiliser les données de l'analyse sélectionnée
    data = historical_analyses[selected_analysis]["data"]
    df = pd.json_normalize(data)
    df['vt_malicious'] = df['vt_malicious'].astype(str)
    
    st.sidebar.info(f"Affichage des données du {historical_analyses[selected_analysis]['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
else:
    # Charger les données JSON les plus récentes
    try:
        with open("analyse_ips_mitre.json", "r") as f:
            data = json.load(f)
        
        df = pd.json_normalize(data)
        df['vt_malicious'] = df['vt_malicious'].astype(str)
        
        st.sidebar.info("Affichage des données les plus récentes")
    except Exception as e:
        st.error(f"Erreur lors du chargement des données: {e}")
        st.stop()

# Charger les anomalies globales
try:
    with open("anomalies_globales.json", "r") as f:
        anomalies_globales = json.load(f)
except:
    anomalies_globales = []

# Filtres
min_score = st.sidebar.slider("Score VirusTotal minimum", 0, 20, 0)
selected_country = st.sidebar.multiselect("Pays", options=sorted(df["country"].unique()))
selected_protocols = st.sidebar.multiselect("Protocoles", options=sorted(set([p for protocols in df["protocoles"] for p in protocols])))

# Filtrer par tactique MITRE
all_tactics = extract_mitre_tactics(data)
selected_tactics = st.sidebar.multiselect("Tactiques MITRE", options=all_tactics)

# Appliquer les filtres
filtered_df = df.copy()

if min_score > 0:
    numeric_vt = filtered_df["vt_malicious"].astype(str).str.isnumeric()
    filtered_df = filtered_df[numeric_vt]
    if not filtered_df.empty:
        filtered_df = filtered_df[filtered_df["vt_malicious"].astype(int) >= min_score]

if selected_country:
    filtered_df = filtered_df[filtered_df["country"].isin(selected_country)]

if selected_protocols:
    filtered_df = filtered_df[filtered_df["protocoles"].apply(lambda x: any(p in x for p in selected_protocols))]

if selected_tactics:
    # Filtrer par tactique principale
    main_tactic_mask = filtered_df["mitre_tactique"].isin(selected_tactics)
    
    # Filtrer par tactiques dans autres_activites
    other_tactics_mask = filtered_df["autres_activites"].apply(
        lambda activities: any(
            isinstance(act, dict) and act.get("mitre_tactique") in selected_tactics 
            for act in activities
        )
    )
    
    # Combiner les masques
    filtered_df = filtered_df[main_tactic_mask | other_tactics_mask]

# Afficher les statistiques
st.markdown("## 📊 Statistiques générales")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Nombre d'IPs analysées", len(df))
with col2:
    numeric_vt = df["vt_malicious"].astype(str).str.isnumeric()
    st.metric("IPs suspectes (VT > 0)", len(df[numeric_vt & (df.loc[numeric_vt, "vt_malicious"].astype(int) > 0)]))
with col3:
    st.metric("Pays détectés", df["country"].nunique())
with col4:
    st.metric("Protocoles uniques", len(set([p for protocols in df["protocoles"] for p in protocols])))

# Afficher les IPs filtrées
st.markdown("## 🔍 IPs analysées")

# Trier par score VirusTotal (descendant)
sorted_df = filtered_df.copy()
sorted_df["vt_sort"] = sorted_df["vt_malicious"].apply(lambda x: int(x) if str(x).isdigit() else -1)
sorted_df = sorted_df.sort_values("vt_sort", ascending=False)

# Afficher le tableau des IPs
st.dataframe(
    sorted_df[["ip", "country", "vt_malicious", "mitre_tactique", "type_activite"]],
    column_config={
        "ip": "Adresse IP",
        "country": "Pays",
        "vt_malicious": "Score VT",
        "mitre_tactique": "Tactique MITRE",
        "type_activite": "Type d'activité"
    },
    use_container_width=True
)

# Afficher les détails d'une IP sélectionnée
st.markdown("## 🔎 Détails d'une IP")
selected_ip = st.selectbox("Sélectionner une IP pour voir les détails", options=sorted_df["ip"].tolist())

if selected_ip:
    details = sorted_df[sorted_df["ip"] == selected_ip].iloc[0].to_dict()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Adresse IP", details["ip"])
        st.metric("Pays", details["country"])
    with col2:
        st.metric("Score VirusTotal", details["vt_malicious"])
        st.metric("ASN", details["asn"])
    with col3:
        st.metric("Type d'activité", details["type_activite"])
        st.metric("Tactique MITRE", details.get("mitre_tactique", "-"))
    
    # Afficher les timestamps si disponibles
    if "first_seen" in details and "last_seen" in details and details["first_seen"] and details["last_seen"]:
        try:
            first_seen = datetime.fromisoformat(details["first_seen"])
            last_seen = datetime.fromisoformat(details["last_seen"])
            duration = (last_seen - first_seen).total_seconds()
            
            st.subheader("Activité temporelle")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Premier paquet", first_seen.strftime("%Y-%m-%d %H:%M:%S"))
            with col2:
                st.metric("Dernier paquet", last_seen.strftime("%Y-%m-%d %H:%M:%S"))
            with col3:
                st.metric("Durée d'activité", f"{duration:.2f} secondes")
        except Exception as e:
            st.warning(f"Impossible d'analyser les données temporelles: {e}")
    
    # Afficher les détails JSON
    st.markdown("#### 📊 Résumé des informations")
    
    # Afficher les protocoles
    st.markdown("**Protocoles détectés:**")
    protocols = details.get("protocoles", [])
    st.write(", ".join(protocols))
    
    # Afficher les connexions
    st.markdown("**Connexions établies:**")
    connections = details.get("connexions", [])
    if len(connections) > 20:
        st.write(", ".join(connections[:20]) + f" ... et {len(connections) - 20} autres")
    else:
        st.write(", ".join(connections))
    
    # Afficher les autres activités (tactiques MITRE supplémentaires)
    st.markdown("#### 🛡️ Tactiques MITRE détectées")
    
    autres_activites = details.get("autres_activites", [])
    if autres_activites:
        for i, activite in enumerate(autres_activites):
            if isinstance(activite, dict):
                with st.expander(f"{activite.get('type_activite', 'Activité')} - {activite.get('mitre_tactique', 'Tactique')}"):
                    for key, value in activite.items():
                        st.write(f"**{key}:** {value}")
    else:
        st.info("Aucune tactique MITRE supplémentaire détectée")
    
    # Afficher les anomalies
    st.markdown("#### ⚠️ Anomalies détectées")
    
    anomalies = details.get("anomalies_detectees", {})
    
    # Fonction pour extraire les analyses VirusTotal des anomalies
    def extract_vt_analyses(anomaly_list):
        analyses = []
        file_hashes = []
        
        for a in anomaly_list:
            if "HASH payload:" in a:
                hash_val = a.split(":")[-1].strip()
                file_hashes.append(hash_val)
            
            if "✅ Fichier envoyé à VirusTotal" in a or "🔎 Voir l'analyse:" in a:
                analyses.append(a)
        
        return analyses, file_hashes
    
    # Fonction pour catégoriser les anomalies HTTP
    def categorize_http_anomalies(http_anomalies):
        categories = {
            "traversal": [],  # Tentatives de directory traversal, LFI, etc.
            "method": [],     # Méthodes HTTP non standard
            "user_agent": [], # User-agents suspects
            "status": [],     # Codes de statut suspects
            "content": [],    # Types de contenu suspects
            "url": [],        # URLs suspectes
            "other": []       # Autres anomalies
        }
        
        for anomaly in http_anomalies:
            if any(x in anomaly.lower() for x in ["../", "directory traversal", "path traversal", "lfi", "rfi"]):
                categories["traversal"].append(anomaly)
            elif any(x in anomaly.lower() for x in ["method", "put", "delete", "trace", "connect"]):
                categories["method"].append(anomaly)
            elif "user-agent" in anomaly.lower():
                categories["user_agent"].append(anomaly)
            elif any(x in anomaly.lower() for x in ["status", "404", "500", "403"]):
                categories["status"].append(anomaly)
            elif any(x in anomaly.lower() for x in ["content-type", "application/", "text/"]):
                categories["content"].append(anomaly)
            elif any(x in anomaly.lower() for x in ["url", "uri", "http://", "https://"]):
                categories["url"].append(anomaly)
            else:
                categories["other"].append(anomaly)
        
        return categories
    
    # Afficher les analyses VirusTotal en premier
    for k, v in anomalies.items():
        vt_analyses, file_hashes = extract_vt_analyses(v)
        
        if vt_analyses:
            with st.expander(f"🔬 Analyses VirusTotal ({len(vt_analyses)})", expanded=True):
                for analysis in vt_analyses:
                    if "✅ Fichier envoyé à VirusTotal" in analysis:
                        st.success(analysis)
                    elif "🔎 Voir l'analyse:" in analysis:
                        # Extraire l'ID d'analyse plutôt que l'URL complète
                        analysis_id = re.search(r'file-analysis/([a-zA-Z0-9]+)', analysis)
                        if analysis_id:
                            analysis_id = analysis_id.group(1)
                            # Générer un lien vers la page de résultats plutôt que vers la page d'analyse
                            st.markdown(f"[🔗 Voir l'analyse sur VirusTotal](https://www.virustotal.com/gui/file-analysis/{analysis_id}/detection)")
    
    # Afficher les anomalies HTTP de manière organisée
    if "http" in anomalies and anomalies["http"]:
        with st.expander("🌐 Anomalies HTTP", expanded=True):
            http_categories = categorize_http_anomalies(anomalies["http"])
            
            # Afficher les tentatives d'attaque en premier (plus importantes)
            if http_categories["traversal"]:
                st.subheader("⚠️ Tentatives d'attaque détectées")
                for item in http_categories["traversal"]:
                    st.error(item)
            
            # Afficher les méthodes HTTP non standard
            if http_categories["method"]:
                st.subheader("🔄 Méthodes HTTP non standard")
                for item in http_categories["method"]:
                    st.warning(item)
            
            # Afficher les User-Agents suspects
            if http_categories["user_agent"]:
                st.subheader("👤 User-Agents suspects")
                for item in http_categories["user_agent"]:
                    st.warning(item)
            
            # Afficher les autres catégories
            for category, items in http_categories.items():
                if category not in ["traversal", "method", "user_agent"] and items:
                    st.subheader(f"🔍 {category.capitalize()}")
                    for item in items:
                        st.info(item)
    
    # Afficher les autres catégories d'anomalies
    for k, v in anomalies.items():
        if k != "http" and v:  # On a déjà traité les anomalies HTTP
            with st.expander(f"🧪 Anomalies {k.upper()}"):
                for a in v:
                    if "HASH payload:" in a:
                        hash_val = a.split(":")[-1].strip()
                        short_hash = format_hash_display(hash_val)
                        st.code(f"HASH: {short_hash} (complet: {hash_val})")
                        
                        # Vérifier si le lien est valide avant de l'afficher
                        if verify_vt_link(hash_val):
                            vt_url = f"https://www.virustotal.com/gui/file/{hash_val}/detection"
                            st.markdown(f"[🔍 Voir sur VirusTotal]({vt_url})")
                        else:
                            col1, col2 = st.columns([3, 1])
                            with col1:
                                st.warning("⚠️ Ce hachage n'est pas trouvable sur VirusTotal")
                                # Ajouter un lien vers la recherche VirusTotal
                                search_url = f"https://www.virustotal.com/gui/search/{hash_val}"
                                st.markdown(f"[🔎 Rechercher sur VirusTotal]({search_url})")
                    elif "✅ Fichier envoyé à VirusTotal" in a or "🔎 Voir l'analyse:" in a:
                        # Déjà affiché plus haut
                        pass
                    else:
                        st.write(f"- {a}")

# Afficher les graphiques
st.markdown("## 📈 Visualisations")

# Graphique des scores VirusTotal
st.markdown("### 🦠 Distribution des scores VirusTotal")
numeric_vt = df["vt_malicious"].astype(str).str.isnumeric()
if numeric_vt.any():
    vt_scores = df.loc[numeric_vt, "vt_malicious"].astype(int)
    if not vt_scores.empty:
        fig, ax = plt.subplots(figsize=(10, 6))
        vt_scores.value_counts().sort_index().plot(kind='bar', ax=ax)
        ax.set_title("Distribution des scores VirusTotal")
        ax.set_xlabel("Score VirusTotal")
        ax.set_ylabel("Nombre d'IPs")
        st.pyplot(fig)
    else:
        st.info("Aucune donnée VirusTotal numérique disponible pour générer le graphique")
else:
    st.info("Aucune donnée VirusTotal numérique disponible pour générer le graphique")

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
    
    # Compter les analyses VirusTotal réussies dans les anomalies globales
    vt_global_analyses = sum(1 for a in anomalies_globales 
                            for item in a.get("http", []) + a.get("payload", []) 
                            if "✅ Fichier envoyé à VirusTotal" in item)
    
    st.info(f"Nombre total d'analyses VirusTotal dans les anomalies globales: {vt_global_analyses}")
    
    selected_type = st.selectbox("Voir toutes les anomalies de type", ["http", "dns", "payload", "meta"])
    
    # Option pour filtrer uniquement les analyses VirusTotal
    show_only_vt = st.checkbox("Afficher uniquement les analyses VirusTotal")
    
    count = 0
    unique_hashes = set()
    for a in anomalies_globales:
        if selected_type in a and a[selected_type]:
            for ligne in a[selected_type]:
                if "HASH payload:" in ligne:
                    hash_val = ligne.split(":")[-1].strip()
                    if hash_val in unique_hashes:
                        continue  # Sauter les hachages déjà vus
                    unique_hashes.add(hash_val)
                
                if show_only_vt and not ("✅ Fichier envoyé à VirusTotal" in ligne or "🔎 Voir l'analyse:" in ligne):
                    continue
                    
                if "✅ Fichier envoyé à VirusTotal" in ligne:
                    st.success(ligne)
                elif "🔎 Voir l'analyse:" in ligne:
                    # Extraire l'ID d'analyse plutôt que l'URL complète
                    analysis_id = re.search(r'file-analysis/([a-zA-Z0-9]+)', ligne)
                    if analysis_id:
                        analysis_id = analysis_id.group(1)
                        # Générer un lien vers la page de résultats plutôt que vers la page d'analyse
                        st.markdown(f"[🔗 Voir l'analyse sur VirusTotal](https://www.virustotal.com/gui/file-analysis/{analysis_id}/detection)")
                elif "HASH" in ligne:
                    hash_val = ligne.split(":")[-1].strip()
                    short_hash = format_hash_display(hash_val)
                    st.code(f"HASH: {short_hash} (complet: {hash_val})")
                    
                    # Vérifier si le lien est valide avant de l'afficher
                    if verify_vt_link(hash_val):
                        vt_url = f"https://www.virustotal.com/gui/file/{hash_val}/detection"
                        st.markdown(f"[🔍 Voir sur VirusTotal]({vt_url})")
                    else:
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.warning("⚠️ Ce hachage n'est pas trouvable sur VirusTotal")
                            # Ajouter un lien vers la recherche VirusTotal
                            search_url = f"https://www.virustotal.com/gui/search/{hash_val}"
                            st.markdown(f"[🔎 Rechercher sur VirusTotal]({search_url})")
                else:
                    st.write(f"- {ligne}")
                count += 1
    if count == 0:
        st.info("Aucune anomalie de ce type détectée.")
