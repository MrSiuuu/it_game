import streamlit as st
import json
import pandas as pd

st.set_page_config(page_title="Analyse Réseau - IT GAME", layout="wide")

st.title("🔍 Dashboard d’analyse des IPs (PCAP + MITRE)")
st.markdown("Projet IT Game – Analyse automatique des fichiers `.pcap` enrichie avec **VirusTotal + MITRE ATT&CK**.")

# === Charger les données JSON ===
try:
    with open("analyse_ips_mitre.json", "r") as f:
        data = json.load(f)
except FileNotFoundError:
    st.error("Fichier 'analyse_ips_mitre.json' non trouvé. Lance d'abord le script d'analyse.")
    st.stop()

# === Transformer en DataFrame pour affichage / filtres ===
df = pd.json_normalize(data)

# === Filtres latéraux ===
st.sidebar.header("🧰 Filtres")

pays = st.sidebar.multiselect("Filtrer par pays", sorted(df["country"].unique()))
score = st.sidebar.slider("Score VirusTotal (malicious)", 0, 20, (0, 20))

filtered_df = df.copy()

if pays:
    filtered_df = filtered_df[filtered_df["country"].isin(pays)]
filtered_df = filtered_df[filtered_df["vt_malicious"].apply(lambda x: isinstance(x, int) and score[0] <= x <= score[1])]

# === Statistiques globales ===
total_ips = len(df)
public_ips = df[~df["vt_malicious"].isin(["IP locale (non testable)", "Erreur API"])]
public_ips_count = len(public_ips)
local_ips = df[df["vt_malicious"] == "IP locale (non testable)"]
local_ips_count = len(local_ips)
filtered_ips_count = len(filtered_df)

st.markdown("### 📈 Statistiques globales")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🌐 IPs totales", total_ips)

with col2:
    st.metric("🛰️ IPs publiques", public_ips_count)
    with st.expander("Voir IPs publiques"):
        st.write(public_ips["ip"].tolist())

with col3:
    st.metric("🧊 IPs locales", local_ips_count)
    with st.expander("Voir IPs locales"):
        st.write(local_ips["ip"].tolist())

with col4:
    st.metric("🔍 IPs affichées (filtrées)", filtered_ips_count)

# === Tableau principal ===
st.subheader("📋 Résumé des IPs détectées")
st.dataframe(
    filtered_df[[
        "ip", "country", "vt_malicious", "type_activite", "mitre_tactique", "mitre_technique"
    ]].fillna("-"),
    use_container_width=True
)

# === Détail d'une IP sélectionnée ===
st.subheader("🧠 Détails d’une IP")

selected_ip = st.selectbox("Choisir une IP pour voir les détails", filtered_df["ip"].unique())

details = filtered_df[filtered_df["ip"] == selected_ip].iloc[0]

st.json({
    "IP": details["ip"],
    "Date / Heure": f"{details['date']} {details['heure']}",
    "Score VT": details["vt_malicious"],
    "Pays": details["country"],
    "ASN": details["asn"],
    "Fournisseur": details["as_owner"],
    "Réseau": details["network"],
    "Protocoles": details["protocoles"],
    "Connexions": details["connexions"],
    "Tactique principale": details.get("mitre_tactique", "-"),
    "Technique": details.get("mitre_technique", "-"),
    "Autres activités": details.get("autres_activites", [])
})
