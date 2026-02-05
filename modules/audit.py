#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script System Inventory & EOL Scanner (s.py)

Fonctionnalités :
1. Scan réseau (Ping Sweep) avec détection d'OS basée sur le TTL.
2. Base de données interne des dates de fin de vie (EOL) des OS.
3. Analyse de fichiers CSV pour vérifier la conformité EOL.
4. Génération de rapports.

Compatibilité : Windows & Linux
"""

import sys
import os
import platform
import subprocess
import argparse
import socket
import csv
import threading
import ipaddress
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import io

# Configurer l'encodage pour Windows (pour afficher les accents)
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


# =============================================================================
# BASE DE DONNÉES EOL (End of Life)
# =============================================================================
# Format: "OS Name": {"Version": "YYYY-MM-DD"}
EOL_DB = {
    "Windows": {
        "10": "2025-10-14",
        "11": "2031-10-14",  # Estimation/Standard
        "7": "2020-01-14",
        "8.1": "2023-01-10",
        "XP": "2014-04-08",
        "2008 R2": "2020-01-14",
        "2012 R2": "2023-10-10",
        "2016": "2027-01-12",
        "2019": "2029-01-09",
        "2022": "2031-10-14"
    },
    "Ubuntu": {
        "24.04": "2029-04-01",
        "22.04": "2027-04-01",
        "20.04": "2025-04-01",
        "18.04": "2023-05-31",
        "16.04": "2021-04-30"
    },
    "Debian": {
        "12": "2028-06-10", # Bookworm (approx)
        "11": "2026-06-30", # Bullseye
        "10": "2024-06-30", # Buster
        "9": "2022-06-30"   # Stretch
    },
    "CentOS": {
        "7": "2024-06-30",
        "8": "2021-12-31"
    }
}

# =============================================================================
# UTILITAIRES
# =============================================================================

def get_eol_status(os_name, version):
    """Retourne le statut EOL, la date de fin et les jours restants."""
    
    # Normalisation basique
    os_key = None
    for key in EOL_DB.keys():
        if key.lower() in os_name.lower():
            os_key = key
            break
            
    if not os_key:
        return "UNKNOWN", "N/A", 0
        
    # Recherche de version (correspondance partielle pour simplifier)
    target_date_str = None
    
    # Si la version exacte existe
    if version in EOL_DB[os_key]:
        target_date_str = EOL_DB[os_key][version]
    else:
        # Essai de trouver une version partielle (ex: "Ubuntu 20.04.1" matches "20.04")
        for v_db in EOL_DB[os_key]:
            if version.startswith(v_db):
                target_date_str = EOL_DB[os_key][v_db]
                break
                
    if not target_date_str:
        return "VERSION_UNKNOWN", "N/A", 0
        
    eol_date = datetime.strptime(target_date_str, "%Y-%m-%d")
    today = datetime.now()
    days_left = (eol_date - today).days
    
    if days_left < 0:
        return "EOL", target_date_str, days_left
    elif days_left < 180:
        return "WARNING", target_date_str, days_left
    else:
        return "OK", target_date_str, days_left

def color_print(text, status, end="\n"):
    """Affichage coloré basique."""
    # Codes ANSI (ne marchent pas toujours nativement sur cmd.exe sans config, mais ok sur Terminals modernes)
    colors = {
        "OK": "\033[92m",      # Vert
        "WARNING": "\033[93m", # Jaune
        "EOL": "\033[91m",     # Rouge
        "INFO": "\033[94m",    # Bleu
        "RESET": "\033[0m"
    }
    
    if sys.platform == "win32" and os.getenv("TERM") is None:
        # Fallback simple pour Windows CMD standard si pas de support ANSI détecté
        print(text, end=end)
    else:
        col = colors.get(status, colors["RESET"])
        print(f"{col}{text}{colors['RESET']}", end=end)

# =============================================================================
# SCANNER RÉSEAU
# =============================================================================

def ping_host(ip):
    """Ping une IP et retourne (Actif?, TTL, Hostname)."""
    is_windows = platform.system().lower() == "windows"
    
    cmd = ["ping", "-n", "1", "-w", "1000", ip] if is_windows else ["ping", "-c", "1", "-W", "1", ip]
    
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode == 0:
            # Extraction du TTL
            ttl = -1
            match = re.search(r"TTL=(\d+)", proc.stdout, re.IGNORECASE)
            if match:
                ttl = int(match.group(1))
            else:
                # Sur Linux, c'est parfois "ttl=" en minuscule
                match = re.search(r"ttl=(\d+)", proc.stdout)
                if match:
                    ttl = int(match.group(1))
            
            # Essai résolution nom
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ""
                
            return True, ttl, hostname
    except Exception:
        pass
        
    return False, -1, ""

def guess_os_by_ttl(ttl):
    """Devine l'OS basé sur le TTL initial."""
    if ttl == -1:
        return "Inconnu"
    
    # TTL initiaux classiques : Windows=128, Linux/Unix=64, Network=255
    # La valeur reçue est TTL_Initial - sauts.
    
    if 65 <= ttl <= 128:
        return "Windows"
    elif ttl <= 64:
        return "Linux/Unix"
    elif ttl > 128:
        return "Network Device (Cisco/Etc)"
    else:
        return "Inconnu"

def scan_network(network_cidr, max_threads=50):
    """Scanne une plage réseau."""
    print(f"[*] Démarrage du scan sur {network_cidr} ...")
    
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as e:
        print(f"[!] Erreur de format réseau : {e}")
        return []

    hosts_found = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in net.hosts()}
        
        total = len(futures)
        done = 0
        
        for future in futures:
            ip = futures[future]
            try:
                is_up, ttl, hostname = future.result()
                if is_up:
                    os_guess = guess_os_by_ttl(ttl)
                    hosts_found.append({
                        "IP": ip,
                        "Hostname": hostname,
                        "TTL": ttl,
                        "OS_Guess": os_guess
                    })
                    status_line = f"[+] {ip:15} | TTL={ttl:<3} | OS={os_guess:10} | {hostname}"
                    color_print(status_line, "OK")
            except Exception as e:
                print(f"Error scanning {ip}: {e}")
            
            # Barebones progress
            done += 1
            # print(f"\rProgress: {done}/{total}", end="")
            
    print(f"\n[*] Scan terminé. {len(hosts_found)} hôtes actifs trouvés.")
    return hosts_found

# =============================================================================
# CSV & EOL PROCESSOR
# =============================================================================

def process_csv(input_file, output_file):
    """Lit un CSV (Hardware,OS,Version) et ajoute les infos EOL."""
    print(f"[*] Analyse du fichier {input_file}...")
    
    results = []
    headers = []
    
    try:
        with open(input_file, mode='r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)
            
            # Essayer de trouver les colonnes
            try:
                idx_comp = -1
                idx_os = -1
                idx_ver = -1
                
                # Détection simple des colonnes
                for i, h in enumerate(headers):
                    h_lower = h.lower()
                    if "comp" in h_lower or "nom" in h_lower or "server" in h_lower or "host" in h_lower:
                        idx_comp = i
                    elif "os" in h_lower or "syst" in h_lower:
                        idx_os = i
                    elif "ver" in h_lower:
                        idx_ver = i
                
                if idx_os == -1 or idx_ver == -1:
                    print("[!] Impossible de trouver les colonnes 'OS' et 'Version' dans le CSV.")
                    print(f"Colonnes trouvées : {headers}")
                    return
                
                for row in reader:
                    comp_name = row[idx_comp] if idx_comp != -1 else "Unknown"
                    os_name = row[idx_os]
                    version = row[idx_ver]
                    
                    status, eol_date, days = get_eol_status(os_name, version)
                    
                    row_data = {
                        "Component": comp_name,
                        "OS": os_name,
                        "Version": version,
                        "Status": status,
                        "EOL_Date": eol_date,
                        "Days_Left": days
                    }
                    results.append(row_data)
                    
                    # Affichage console
                    msg = f"{comp_name:15} | {os_name} {version} -> {status} ({days} jours restants)"
                    color_print(msg, status)
                    
            except Exception as e:
                print(f"[!] Erreur lecture CSV: {e}")
                return

        # Export Rapport
        if output_file:
            with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                new_headers = ["Component", "OS", "Version", "Status", "EOL_Date", "Days_Left"]
                writer.writerow(new_headers)
                for r in results:
                    writer.writerow([
                        r["Component"], 
                        r["OS"], 
                        r["Version"], 
                        r["Status"], 
                        r["EOL_Date"], 
                        r["Days_Left"]
                    ])
            print(f"[*] Rapport généré : {output_file}")
            
    except FileNotFoundError:
        print(f"[!] Fichier introuvable : {input_file}")

# =============================================================================
# LISTER INFOS OS
# =============================================================================

def list_os_eol(os_filter=None):
    """Affiche la base de données EOL connue."""
    print(f"\n{'OS':<15} | {'Version':<10} | {'Date EOL':<12} | {'Statut'}")
    print("-" * 50)
    
    for os_fam, versions in EOL_DB.items():
        if os_filter and os_filter.lower() not in os_fam.lower():
            continue
            
        for ver, date_str in versions.items():
            status, _, days = get_eol_status(os_fam, ver)
            color_print(f"{os_fam:<15} | {ver:<10} | {date_str:<12} | {status} ({days}j)", status)

# =============================================================================
# INTERACTIVE MODE
# =============================================================================

def interactive_mode():
    """Mode interactif pour lancer les différentes fonctions."""
    print("\n=== Mode Interactif ===")
    
    # 1. Scan Réseau
    print("\n[1] Scan Réseau")
    do_scan = input("Voulez-vous lancer un scan réseau ? (o/N) : ").lower().strip()
    if do_scan == 'o':
        default_net = "192.168.1.0/24"
        network = input(f"Entrez la plage IP [Défaut: {default_net}] : ").strip()
        if not network:
            network = default_net
        
        output_scan = input("Fichier de sortie scan (optionnel, Entrée pour ignorer) : ").strip()
        
        results = scan_network(network)
        if output_scan and results:
            try:
                with open(output_scan, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=["IP", "Hostname", "TTL", "OS_Guess"])
                    writer.writeheader()
                    writer.writerows(results)
                print(f"[*] Résultats du scan exportés vers {output_scan}")
            except Exception as e:
                print(f"[!] Erreur écriture fichier: {e}")

    # 2. Vérification CSV
    print("\n[2] Vérification CSV EOL")
    do_csv = input("Voulez-vous vérifier un fichier CSV ? (o/N) : ").lower().strip()
    if do_csv == 'o':
        csv_file = input("Chemin du fichier CSV : ").strip()
        if csv_file:
            output_csv = input("Fichier de rapport CSV (optionnel) : ").strip()
            process_csv(csv_file, output_csv if output_csv else None)
        else:
            print("[!] Aucun fichier spécifié.")

    # 3. Liste EOL
    print("\n[3] Base de données EOL")
    do_list = input("Afficher la base de données EOL ? (o/N) : ").lower().strip()
    if do_list == 'o':
        list_os_eol("all")

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outil de scan réseau et de vérification EOL OS.")
    
    # On garde les arguments pour le mode non-interactif / scripté
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--scan", help="Scanner une plage IP (ex: 192.168.1.0/24)")
    group.add_argument("--check-csv", help="Vérifier un fichier CSV (Requis colonnes: Component, OS, Version)")
    group.add_argument("--list-eol", nargs="?", const="all", help="Lister les dates EOL supportées (optionnel: filtre nom OS)")
    
    parser.add_argument("--out", help="Fichier de sortie pour le rapport CSV")
    
    # Si aucun argument n'est passé, on lance le mode interactif
    if len(sys.argv) == 1:
        print("=== System Inventory & EOL Scanner ===")
        interactive_mode()
        sys.exit(0)

    args = parser.parse_args()
    
    print("=== System Inventory & EOL Scanner ===")
    
    if args.scan:
        results = scan_network(args.scan)
        if args.out:
            # Export scan results
            try:
                with open(args.out, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=["IP", "Hostname", "TTL", "OS_Guess"])
                    writer.writeheader()
                    writer.writerows(results)
                print(f"[*] Résultats du scan exportés vers {args.out}")
            except Exception as e:
                print(f"[!] Erreur écriture fichier: {e}")
                
    elif args.check_csv:
        process_csv(args.check_csv, args.out)
        
    elif args.list_eol:
        filter_val = None if args.list_eol == "all" else args.list_eol
        list_os_eol(filter_val)
        
    else:
        parser.print_help()
