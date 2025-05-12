# 🛡️ IT GAME – Analyse Réseau Automatisée

Projet académique de cybersécurité développé dans le cadre d’un marathon de code à KEYCE Academy.  
L’objectif : créer une solution complète permettant d’analyser des fichiers PCAP, détecter les menaces, et visualiser les résultats dans un dashboard interactif.

## 🚀 Objectifs du projet

- Télécharger automatiquement les fichiers PCAP depuis une API
- Analyser les paquets pour identifier les menaces (brute force, reconnaissance, etc.)
- Enrichir les données via VirusTotal
- Afficher les résultats dans un dashboard intuitif
- Proposer une solution valorisable commercialement

## 🔧 Stack & outils utilisés

- **Langage** : Python
- **Librairies principales** :
  - `pyshark` – Analyse de paquets PCAP
  - `requests` – Connexion à l’API et envoi de requêtes
  - `streamlit` – Création du dashboard interactif
  - `hashlib`, `re`, `pandas` – Traitement de données
- **Outils externes** :
  - [VirusTotal API](https://www.virustotal.com/)
  - Framework [MITRE ATT&CK](https://attack.mitre.org/) pour la détection des tactiques
  - Wireshark (référence PCAP)

## 🧩 Structure du projet

```bash
.
├── analyse1.py         # Script principal d’analyse des fichiers PCAP
├── dashboard.py        # Dashboard interactif avec Streamlit
├── test.py             # Script de test API et détection machine cible
├── README.md           # Ce fichier

Analyse des fichiers .pcap et extraction des paquets réseau

Détection d’activités suspectes (ex. brute force T1110 via MITRE)

Hash et enrichissement des payloads via VirusTotal

Affichage des données :

IP source/destination

MAC et hostname des machines ciblées

Tactiques MITRE

Hashs et scores de réputation

🧠 Contexte
Ce projet a été réalisé par une équipe d’étudiants dans un contexte académique de type “challenge entreprise”.
Une présentation commerciale de 15 minutes a été faite devant un jury composé de 4 personnes (technique et business).

📌 Chef de projet
Ce projet a été dirigé par @MrSiuuu, en charge :

De la coordination de l’équipe

De la conception et du développement de la solution

De la présentation orale et marketing finale
