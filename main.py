#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script Principal d'Orchestration (main.py)

Ce script sert de point d'entrée unique pour lancer les différents modules du projet :
1. Audit & Scan Réseau (modules/audit.py)
2. Sauvegarde WMS (modules/backup_wms.py)
3. Diagnostic Serveurs (modules/diagnostic.py)

Il utilise 'subprocess' pour exécuter chaque module dans son propre processus,
garantissant ainsi une isolation propre et évitant les conflits d'importation ou de contexte.
"""

import sys
import os
import subprocess
import time

def clear_screen():
    """Efface l'écran de la console."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Affiche l'en-tête du menu."""
    print("===================================================")
    print("                 NTL_SYSTOOLBOX                    ")
    print("===================================================")

def run_module(module_path):
    """
    Exécute un module Python via subprocess.
    :param module_path: Chemin relatif vers le script du module.
    """
    # Construction du chemin absolu pour éviter les ambiguïtés
    base_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(base_dir, module_path)
    
    if not os.path.exists(script_path):
        print(f"[ERREUR] Le module est introuvable : {script_path}")
        input("Appuyez sur Entrée pour continuer...")
        return

    print(f"\n[*] Lancement du module : {module_path}")
    print("---------------------------------------------------\n")
    
    try:
        # Ajout du dossier racine au PYTHONPATH pour permettre les imports (ex: from utils import ...)
        env = os.environ.copy()
        env["PYTHONPATH"] = base_dir + os.pathsep + env.get("PYTHONPATH", "")

        # Lancement du script avec le même interpréteur Python que celui en cours
        subprocess.run([sys.executable, script_path], check=False, env=env)
    except KeyboardInterrupt:

        print("\n[!] Interruption utilisateur.")
    except Exception as e:
        print(f"\n[!] Erreur lors de l'exécution : {e}")
    
    print("\n---------------------------------------------------")
    input("Module terminé. Appuyez sur Entrée pour revenir au menu...")

def main_menu():
    """Boucle principale du menu."""
    while True:
        clear_screen()
        print_header()
        print("Veuillez sélectionner une action :\n")
        print("  1. Audit Système & Scan Réseau (Audit/EOL)")
        print("  2. Sauvegarde WMS (Backup MariaDB)")
        print("  3. Diagnostic (Infra Check)")
        print("  4. Quitter")
        print("\n===================================================")
        
        choice = input("Votre choix [1-4] : ").strip()
        
        if choice == '1':
            run_module(os.path.join("modules", "audit.py"))
        elif choice == '2':
            run_module(os.path.join("modules", "backup_wms.py"))
        elif choice == '3':
            run_module(os.path.join("modules", "diagnostic.py"))
        elif choice == '4':
            print("\nFermeture de l'application. Au revoir !")
            break
        else:
            print("\n[!] Choix invalide, veuillez réessayer.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nNTL_SystoolBox For sure !")
        sys.exit(0)
