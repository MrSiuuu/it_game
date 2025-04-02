import streamlit as st
import json
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="Analyse Réseau - IT GAME", layout="wide")

st.title("🔍 Dashboard d'analyse des IPs (PCAP + MITRE + Anomalies)")
st.markdown("Projet IT Game – Analyse automatique des fichiers `.pcap` enrichie avec **VirusTotal + MITRE ATT&CK + Analyse locale**.")

# === Charger les données JSON ===
try:
    with open("analyse_ips_mitre.json", "r") as f:
        data = json.load(f)
except FileNotFoundError:
    st.error("Fichier 'analyse_ips_mitre.json' non trouvé.")
    st.stop()

# === Charger anomalies globales si dispo ===
try:
    with open("anomalies_globales.json", "r") as f:
        anomalies_globales = json.load(f)
except:
    anomalies_globales = []

# === Transformer en DataFrame pour affichage / filtres ===
df = pd.json_normalize(data)

# === Filtres latéraux ===
st.sidebar.header("🪰 Filtres")
pays = st.sidebar.multiselect("Filtrer par pays", sorted(df["country"].unique()))
max_score = df["vt_malicious"].apply(lambda x: x if isinstance(x, int) else 0).max()
# Assurez-vous que max_score est au moins 1 pour éviter l'erreur du slider
max_score = max(1, max_score)
score = st.sidebar.slider("Score VirusTotal (malicious)", 0, int(max_score), (0, int(max_score)))
st.sidebar.caption(f"Valeur maximale détectée : {max_score}")
anomaly_filter = st.sidebar.multiselect("Type d'anomalie locale", ["http", "dns", "payload", "meta"])

# Filtres MITRE
if "mitre_tactique" in df.columns:
    mitre_tactics = df["mitre_tactique"].dropna().unique()
    selected_tactics = st.sidebar.multiselect("Tactiques MITRE", mitre_tactics)

filtered_df = df.copy()
if pays:
    filtered_df = filtered_df[filtered_df["country"].isin(pays)]
filtered_df = filtered_df[filtered_df["vt_malicious"].apply(lambda x: isinstance(x, int) and score[0] <= x <= score[1] if isinstance(x, int) else True)]
if anomaly_filter:
    filtered_df = filtered_df[filtered_df["anomalies_detectees"].apply(lambda a: any(k in a and a[k] for k in anomaly_filter))]
if "mitre_tactique" in df.columns and selected_tactics:
    filtered_df = filtered_df[filtered_df["mitre_tactique"].isin(selected_tactics)]

# === Statistiques ===
st.markdown("### 📈 Statistiques globales")
total_ips = len(df)
public_ips = df[~df["vt_malicious"].isin(["IP locale (non testable)", "Erreur API"])]
local_ips = df[df["vt_malicious"] == "IP locale (non testable)"]
filtered_ips_count = len(filtered_df)

col1, col2, col3, col4 = st.columns(4)
with col1: st.metric("🌐 IPs totales", total_ips)
with col2:
    st.metric("🚨 IPs publiques", len(public_ips))
    with st.expander("Voir IPs publiques"):
        st.write(public_ips["ip"].tolist())
with col3:
    st.metric("🧳 IPs locales", len(local_ips))
    with st.expander("Voir IPs locales"):
        st.write(local_ips["ip"].tolist())
with col4:
    st.metric("🔍 IPs affichées (filtrées)", filtered_ips_count)

# === Suivi temporel version texte ===
st.markdown("### 🕒 Évolution des incidents par heure")
df["datetime"] = pd.to_datetime(df["date"] + " " + df["heure"])
incidents_par_heure = df.groupby(df["datetime"].dt.hour).size().sort_values(ascending=False)
for heure, count in incidents_par_heure.items():
    st.markdown(f"🔸 **{heure:02d}:00** → {count} incident(s)")

# === Tactiques MITRE ===
if "mitre_tactique" in df.columns:
    st.markdown("### 🌿 Tactiques MITRE principales")
    tactics = df["mitre_tactique"].fillna("Non classé").value_counts()
    
    fig, ax = plt.subplots(figsize=(10, 6))
    tactics.plot(kind='bar', ax=ax)
    ax.set_title("Répartition des tactiques MITRE")
    ax.set_ylabel("Nombre d'occurrences")
    st.pyplot(fig)
else:
    st.info("Aucune donnée MITRE disponible dans ce fichier.")

# === Tableau résumé ===
st.subheader("📋 Résumé des IPs détectées")
cols_to_show = [col for col in ["ip", "country", "vt_malicious", "type_activite", "mitre_tactique", "mitre_technique"] if col in filtered_df.columns]
st.dataframe(filtered_df[cols_to_show].fillna("-"), use_container_width=True)

# === Détails IP ===
st.subheader("🧐 Détails d'une IP")
selected_ip = st.selectbox("Choisir une IP pour voir les détails", filtered_df["ip"].unique())
details = filtered_df[filtered_df["ip"] == selected_ip].iloc[0]

st.markdown("#### 🧬 Informations enrichies")
details_json = {
    "IP": details["ip"],
    "Date / Heure": f"{details['date']} {details['heure']}",
    "Score VT": details["vt_malicious"],
    "Pays": details["country"],
    "ASN": details["asn"],
    "Fournisseur": details["as_owner"],
    "Réseau": details["network"],
    "Protocoles": details["protocoles"],
    "Connexions": details["connexions"]
}

# Ajouter les informations MITRE seulement si elles existent
if "mitre_tactique" in details:
    details_json["Tactique principale"] = details.get("mitre_tactique", "-")
if "mitre_technique" in details:
    details_json["Technique principale"] = details.get("mitre_technique", "-")
if "type_activite" in details:
    details_json["Type d'activité"] = details.get("type_activite", "-")
if "autres_activites" in details and details.get("autres_activites"):
    details_json["Toutes techniques MITRE détectées"] = [
        f"{a['mitre_tactique']} - {a['mitre_technique']} ({a['type_activite']})"
        for a in details.get("autres_activites", [])
    ]

st.json(details_json)

# === Anomalies locales ===
st.markdown("#### ⚠️ Anomalies détectées localement")
anomalies = details.get("anomalies_detectees", {})
if not any(anomalies.values()):
    st.success("Aucune anomalie locale détectée pour cette IP.")
else:
    for k, v in anomalies.items():
        if v:
            with st.expander(f"🧪 Anomalies {k.upper()}"):
                for a in v:
                    st.write(f"- {a}")
                    if "HASH" in a:
                        hash_value = a.split(":")[-1].strip()
                        vt_url = f"https://www.virustotal.com/gui/file/{hash_value}"
                        st.markdown(f"[🔗 Vérifier sur VirusTotal]({vt_url})")

# === Anomalies globales (audit complet) ===
if anomalies_globales:
    st.markdown("#### 🗭 Vue d'ensemble : anomalies globales")
    selected_type = st.selectbox("Voir toutes les anomalies de type", ["http", "dns", "payload", "meta"])
    count = 0
    for a in anomalies_globales:
        if selected_type in a and a[selected_type]:
            for ligne in a[selected_type]:
                st.markdown(f"- {ligne}")
                if "HASH" in ligne:
                    hash_val = ligne.split(":")[-1].strip()
                    vt_url = f"https://www.virustotal.com/gui/file/{hash_val}"
                    st.markdown(f"[🔍 Voir sur VirusTotal]({vt_url})")
                count += 1
    if count == 0:
        st.info("Aucune anomalie de ce type détectée.")

# === Protocoles les plus fréquents ===
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

# === Carte des pays (si disponible) ===
if "country" in df.columns and df["country"].nunique() > 1:
    st.markdown("### 🗺️ Répartition géographique")
    country_counts = df["country"].value_counts()
    fig, ax = plt.subplots(figsize=(10, 6))
    country_counts.plot(kind='pie', ax=ax, autopct='%1.1f%%')
    ax.set_title("Répartition par pays")
    st.pyplot(fig)
