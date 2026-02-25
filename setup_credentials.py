#!/usr/bin/env python3
"""
Setup script to create encrypted credentials file for diagnostic module.
Run this script to securely store your SSH and Windows credentials.
"""

import getpass
from utils.credentials import CredentialsManager

def main():
    print("=" * 60)
    print("  Diagnostic Module - Credentials Setup")
    print("=" * 60)
    print("\nThis script will encrypt and save your credentials.")
    print("You can leave any field empty to skip.\n")
    
    # Collect SSH credentials
    print("[SSH Credentials - For Linux Servers]")
    ssh_user = input("SSH Username (leave empty to skip): ").strip() or None
    ssh_pass = None
    if ssh_user:
        ssh_pass = getpass.getpass("SSH Password: ") or None
    
    # Collect Windows credentials
    print("\n[Windows Credentials - For Windows Servers]")
    win_user = input("Windows Username (leave empty to skip): ").strip() or None
    win_pass = None
    if win_user:
        win_pass = getpass.getpass("Windows Password: ") or None
    
    # Save credentials
    print("\n" + "-" * 60)
    if ssh_user or win_user:
        success = CredentialsManager.save_to_file(
            ssh_user=ssh_user,
            ssh_pass=ssh_pass,
            win_user=win_user,
            win_pass=win_pass
        )
        
        if success:
            print("\n✓ Credentials saved successfully!")
            print("\nIMPORTANT:")
            print("  - Keep '.credentials.key' and '.credentials' files secure")
            print("  - These files are in .gitignore and won't be committed")
            print("  - To update credentials, run this script again")
        else:
            print("\n✗ Failed to save credentials")
    else:
        print("\nNo credentials provided. Exiting.")

if __name__ == "__main__":
    main()
