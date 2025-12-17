import platform
import psutil
import os
import pymysql
from utils.output import write_json

# Codes de retour
STATUS_OK = 0
STATUS_WARNING = 1
STATUS_CRITICAL = 2


def check_mysql(host):
    """
    Vérifie si la base MySQL est accessible
    """
    try:
        connection = pymysql.connect(
            host=host,
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            connect_timeout=3
        )
        connection.close()
        return True
    except Exception:
        return False


def run_diagnostic():
    details = {}
    status = "OK"
    exit_code = STATUS_OK

    # --- Informations système ---
    details["os"] = platform.system()
    details["os_version"] = platform.version()
    details["uptime_seconds"] = int(psutil.boot_time())

    cpu_percent = psutil.cpu_percent(interval=1)
    details["cpu_percent"] = cpu_percent

    memory = psutil.virtual_memory()
    details["memory_percent"] = memory.percent

    disk = psutil.disk_usage("/")
    details["disk_percent"] = disk.percent

    # --- Analyse simple des seuils ---
    if cpu_percent > 85 or memory.percent > 85 or disk.percent > 90:
        status = "WARNING"
        exit_code = STATUS_WARNING

    # --- Vérification MySQL (service critique WMS) ---
    mysql_host = "192.168.10.21"
    mysql_ok = check_mysql(mysql_host)
    details["mysql_accessible"] = mysql_ok

    if not mysql_ok:
        status = "CRITICAL"
        exit_code = STATUS_CRITICAL

    # --- Résultat final ---
    result = {
        "module": "diagnostic",
        "status": status,
        "details": details
    }

    # Sortie utilisateur
    print(f"[Diagnostic] Statut global : {status}")

    # Export JSON
    write_json("diagnostic.json", result)

    return exit_code
