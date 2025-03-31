import pyshark
from collections import defaultdict, Counter

# === Chemin du fichier .pcap ===
file = "logs/log_2025-03-31.pcap"  # ou ton ex4.pcap si tu veux

# === Structures pour l'analyse ===
ip_counter = Counter()
port_scan = defaultdict(set)
icmp_counter = Counter()

# === Lire le fichier .pcap ===
cap = pyshark.FileCapture(file)

for pkt in cap:
    try:
        if 'IP' in pkt:
            src = pkt.ip.src
            ip_counter[src] += 1

            # Détection Ping Sweep (ICMP)
            if hasattr(pkt, 'icmp'):
                icmp_counter[src] += 1

            # Détection Port Scan
            if hasattr(pkt, pkt.transport_layer.lower()):
                layer = getattr(pkt, pkt.transport_layer.lower())
                dst_port = getattr(layer, 'dstport', None)
                if dst_port:
                    port_scan[src].add(dst_port)
    except:
        continue

# === Affichage des résultats ===
print("\n=== Résumé IPs ===")
for ip, count in ip_counter.items():
    print(f"- {ip} : {count} paquets")

print("\n=== Suspects Port Scan ===")
for ip, ports in port_scan.items():
    if len(ports) > 10:
        print(f"- {ip} → {len(ports)} ports différents")

print("\n=== Suspects Ping Sweep ===")
for ip, count in icmp_counter.items():
    if count > 20:
        print(f"- {ip} → {count} paquets ICMP")

cap.close()
