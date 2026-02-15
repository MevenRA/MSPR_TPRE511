import csv
import ipaddress
import platform
import sys
import os
import socket
import ctypes
from datetime import datetime
import concurrent.futures

# Vérification des priviléges Admin (Nécessaire pour Scapy)
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("PB DE PERMISSIONS : Ce script doit être lancé en tant qu'administrateur pour utiliser Scapy.")
    print("Veuillez relancer le script avec les droits d'administration.")
    # On continue quand même pour l'analyse CSV, mais le scan échouera
    # sys.exit(1)

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from tabulate import tabulate
    from scapy.all import IP, ICMP, sr1, conf
except ImportError as e:
    print(f"ERREUR D'IMPORT : Il manque des dépendances ({e}).")
    print("Essayez : pip install scapy tabulate")
    sys.exit(1)

# Configuration Scapy et Socket
conf.verb = 0
socket.setdefaulttimeout(1) # Timeout pour les résolutions DNS

# =============================================================================
# BASE DE DONNÉES EOL (End of Life)
# =============================================================================
EOL_DB = {
    "Windows": {
        "10": "2025-10-14",
        "11": "2031-10-14",
        "7": "2020-01-14",
        "Server 2012": "2023-10-10",
        "Server 2016": "2027-01-12",
        "Server 2019": "2029-01-09"
    },
    "Linux/Unix": {
        "Ubuntu 20.04": "2025-04-01",
        "Ubuntu 22.04": "2027-04-01",a
        "Debian 11": "2026-06-30",
        "Debian 12": "2028-06-10"
    }
}

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def valider_chemin_sortie(chemin_saisi):
    """Vérifie le chemin et crée les dossiers si nécessaire."""
    if not chemin_saisi.endswith('.csv'):
        chemin_saisi += ".csv"
    
    # Récupérer le dossier (si aucun dossier, prend le répertoire courant)
    repertoire = os.path.dirname(chemin_saisi)
    
    if repertoire and not os.path.exists(repertoire):
        try:
            os.makedirs(repertoire)
            print(f"[Info] Dossier créé : {repertoire}")
        except Exception as e:
            print(f"[Erreur] Impossible de créer le dossier : {e}")
            return None
            
    return chemin_saisi

def get_eol_status(os_name, version_estimee="10"):
    os_key = next((k for k in EOL_DB if k.lower() in os_name.lower()), None)
    if not os_key:
        return "N/A", " INCONNU", "N/A"

    date_str = EOL_DB[os_key].get(version_estimee, "N/A")
    if date_str == "N/A":
        return "N/A", " VERSION À VÉRIFIER", "N/A"

    eol_date = datetime.strptime(date_str, "%Y-%m-%d")
    days_left = (eol_date - datetime.now()).days

    if days_left < 0:
        return date_str, " NON SUPPORTÉ (EOL)", f"{days_left} j"
    elif days_left < 180:
        return date_str, " FIN PROCHE", f"{days_left} j"
    else:
        return date_str, " SUPPORTÉ", f"{days_left} j"

def detect_os_scapy(ip):
    try:
        packet = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if packet:
            ttl = packet.getlayer(IP).ttl
            if ttl <= 64: return "Linux/Unix", ttl
            if ttl <= 128: return "Windows", ttl
            return "Équipement Réseau", ttl
    except:
        pass
    return None, None

# =============================================================================
# ACTIONS DU MENU
# =============================================================================

def scan_ip_worker(ip):
    """Fonction exécutée par chaque thread pour scanner une IP."""
    os_type, ttl = detect_os_scapy(ip)
    if os_type:
        version_probale = "10" if os_type == "Windows" else "Ubuntu 22.04"
        date_eol, statut, reste = get_eol_status(os_type, version_probale)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "N/A"
        
        # Affichage thread-safe (simple print est généralement OK ici)
        print(f"[+] {ip:15} | {os_type:12} | {statut}")
        return [ip, hostname, os_type, ttl, date_eol, statut, reste]
    return None

def action_scan_complet():
    print("\n---  SCAN RÉSEAU & AUDIT EOL (TURBO / MULTI-THREAD) ---")
    start_ip = input("IP de début (ex: 192.168.1.1) : ")
    end_ip = input("IP de fin (ex: 192.168.1.50) : ")
    exclues = input("IP à exclure (séparées par virgules) : ").replace(" ", "").split(",")
    
    path_input = input("Où enregistrer le rapport ? (ex: C:/Rapports/audit.csv ou audit.csv) : ")
    save_path = valider_chemin_sortie(path_input)
    
    if not save_path: return

    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        ips = [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
        
        results = []
        print(f"[*] Analyse de {len(ips)} adresses en cours (Max 50 threads simultanés)...\n")

        # Utilisation de ThreadPoolExecutor pour paralléliser les scans
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # Lancement des tâches
            future_to_ip = {executor.submit(scan_ip_worker, ip): ip for ip in ips if ip not in exclues}
            
            # Récupération des résultats au fil de l'eau
            for future in concurrent.futures.as_completed(future_to_ip):
                res = future.result()
                if res:
                    results.append(res)

        if results:
            headers = ["IP", "Hostname", "OS (Guess)", "TTL", "Date EOL", "Statut Support", "Reste"]
            print("\n" + tabulate(results, headers=headers, tablefmt="grid"))
            
            with open(save_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(results)
            print(f"\n[OK] Rapport enregistré sous : {os.path.abspath(save_path)}")
        else:
            print("[!] Aucun appareil trouvé.")

    except Exception as e:
        print(f"[Erreur] : {e}")

def action_analyser_csv_existant():
    print("\n---  ANALYSE EOL DE FICHIER CSV ---")
    file_path = input("Fichier CSV source (existant) : ")
    
    if not os.path.exists(file_path):
        print("[!] Fichier source introuvable.")
        return

    path_input = input("Où enregistrer le résultat ? : ")
    save_path = valider_chemin_sortie(path_input)
    
    if not save_path: return

    audit_results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                os_val = row.get('OS') or row.get('os') or "Windows"
                ver_val = row.get('Version') or row.get('version') or "10"
                comp_val = row.get('IP') or row.get('Composant') or "Inconnu"

                date_eol, statut, reste = get_eol_status(os_val, ver_val)
                audit_results.append([comp_val, os_val, ver_val, date_eol, statut, reste])

        headers = ["Composant", "OS", "Version", "Date EOL", "Statut Support", "Reste"]
        print("\n" + tabulate(audit_results, headers=headers, tablefmt="fancy_grid"))

        with open(save_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(audit_results)
        print(f"[OK] Audit terminé et enregistré : {os.path.abspath(save_path)}")

    except Exception as e:
        print(f"[Erreur] : {e}")

# =============================================================================
# MENU PRINCIPAL
# =============================================================================

def main():
    while True:
        print("\n" + "="*65)
        print("         AUDIT RÉSEAU & CONFORMITÉ EOL (Flash 3.0)")
        print("="*65)
        print("1. [SCAN & AUDIT] Découverte réseau + Analyse EOL automatique")
        print("2. [IMPORT CSV]   Analyser un fichier CSV d'inventaire existant")
        print("3. [QUITTER]")
        
        choix = input("\nAction (1-3) : ")

        if choix == "1":
            action_scan_complet()
        elif choix == "2":
            action_analyser_csv_existant()
        elif choix == "3":
            print("Fermeture du programme...")
            break
        else:
            print("Choix invalide.")

if __name__ == "__main__":
    main()