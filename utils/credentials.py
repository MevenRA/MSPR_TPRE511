import os
import json
from cryptography.fernet import Fernet

class CredentialsManager:
    """Manages credentials from environment variables or encrypted file."""
    
    CREDENTIALS_FILE = ".credentials"
    KEY_FILE = ".credentials.key"
    
    # Environment variable names
    ENV_SSH_USER = "DIAG_SSH_USER"
    ENV_SSH_PASS = "DIAG_SSH_PASS"
    ENV_WIN_USER = "DIAG_WIN_USER"
    ENV_WIN_PASS = "DIAG_WIN_PASS"
    
    @classmethod
    def get_credentials(cls):
        """
        Retrieves credentials from environment variables or encrypted file.
        Priority: Environment Variables -> Encrypted File -> None
        
        Returns:
            dict: {
                'ssh_user': str or None,
                'ssh_pass': str or None,
                'win_user': str or None,
                'win_pass': str or None
            }
        """
        creds = {
            'ssh_user': None,
            'ssh_pass': None,
            'win_user': None,
            'win_pass': None
        }
        
        # 1. Check environment variables first (highest priority)
        creds['ssh_user'] = os.getenv(cls.ENV_SSH_USER)
        creds['ssh_pass'] = os.getenv(cls.ENV_SSH_PASS)
        creds['win_user'] = os.getenv(cls.ENV_WIN_USER)
        creds['win_pass'] = os.getenv(cls.ENV_WIN_PASS)
        
        # 2. If any credential is missing, try encrypted file
        if not all(creds.values()):
            file_creds = cls._load_from_file()
            if file_creds:
                # Fill in missing credentials from file
                for key in creds:
                    if not creds[key] and key in file_creds:
                        creds[key] = file_creds[key]
        
        return creds
    
    @classmethod
    def _load_from_file(cls):
        """Loads and decrypts credentials from file."""
        try:
            if not os.path.exists(cls.CREDENTIALS_FILE) or not os.path.exists(cls.KEY_FILE):
                return None
            
            # Load encryption key
            with open(cls.KEY_FILE, 'rb') as f:
                key = f.read()
            
            # Load and decrypt credentials
            with open(cls.CREDENTIALS_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            creds = json.loads(decrypted_data.decode())
            
            return creds
        except Exception as e:
            print(f"[WARNING] Could not load credentials from file: {e}")
            return None
    
    @classmethod
    def save_to_file(cls, ssh_user=None, ssh_pass=None, win_user=None, win_pass=None):
        """Encrypts and saves credentials to file."""
        try:
            # Generate or load encryption key
            if os.path.exists(cls.KEY_FILE):
                with open(cls.KEY_FILE, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(cls.KEY_FILE, 'wb') as f:
                    f.write(key)
                print(f"[INFO] Generated new encryption key: {cls.KEY_FILE}")
            
            # Prepare credentials dictionary
            creds = {
                'ssh_user': ssh_user,
                'ssh_pass': ssh_pass,
                'win_user': win_user,
                'win_pass': win_pass
            }
            
            # Encrypt and save
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(json.dumps(creds).encode())
            
            with open(cls.CREDENTIALS_FILE, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"[INFO] Credentials encrypted and saved to: {cls.CREDENTIALS_FILE}")
            return True
        except Exception as e:
            print(f"[ERROR] Could not save credentials: {e}")
            return False

def get_credentials():
    """Convenience function to get credentials."""
    return CredentialsManager.get_credentials()
