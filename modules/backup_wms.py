
import os
import sys
import json
import csv
import time
import hashlib
import datetime
import subprocess
from pathlib import Path
import shutil


# --- Exit codes (exploitables supervision) ---
EXIT_OK = 0
EXIT_CONFIG_MISSING = 10
EXIT_TOOLS_MISSING = 20
EXIT_CMD_FAILED = 30
EXIT_INTEGRITY_FAILED = 40


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def now_timestamp_local() -> str:
    # format horodatage simple et stable
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def check_required_env(required: dict) -> list[str]:
    return [k for k, v in required.items() if not v]


def backup_wms():
    """
    Module Sauvegarde WMS (MariaDB)
    - Dump SQL complet de la base via mariadb-dump
    - Export CSV (vrai CSV virgules) d'une table critique via mariadb + conversion TSV->CSV
    - Rapport JSON horodaté (traçabilité)
    - Intégrité : taille + SHA256
    - Codes retour exploitables
    """

    # --- Répertoires de sortie ---
    # (chemins relatifs -> dépend du dossier de lancement)
    BACKUP_DIR = Path("outputs/backups")
    REPORT_DIR = Path("outputs/reports")

    # --- Lecture des variables d'environnement ---
    db_host = os.getenv("WMS_DB_HOST")
    db_port = os.getenv("WMS_DB_PORT", "3306")
    db_name = os.getenv("WMS_DB_NAME")
    db_user = os.getenv("WMS_DB_USER")
    db_password = os.getenv("WMS_DB_PASSWORD")

    table_name = os.getenv("WMS_TABLE", "orders")  # table critique (par défaut: orders)

    required_vars = {
        "WMS_DB_HOST": db_host,
        "WMS_DB_NAME": db_name,
        "WMS_DB_USER": db_user,
        "WMS_DB_PASSWORD": db_password,
    }

    missing = check_required_env(required_vars)
    if missing:
        msg = f"Variables d'environnement manquantes : {', '.join(missing)}"
        print(f"[ERREUR] {msg}")
        return EXIT_CONFIG_MISSING, {"status": "error", "error": "missing_env", "missing": missing}

    # --- Vérification des outils MariaDB ---
    if not shutil.which("mariadb-dump"):
        msg = "mariadb-dump n'est pas installé ou non accessible dans le PATH"
        print(f"[ERREUR] {msg}")
        return EXIT_TOOLS_MISSING, {"status": "error", "error": "missing_tool", "tool": "mariadb-dump"}

    if not shutil.which("mariadb"):
        msg = "client mariadb non installé ou non accessible dans le PATH"
        print(f"[ERREUR] {msg}")
        return EXIT_TOOLS_MISSING, {"status": "error", "error": "missing_tool", "tool": "mariadb"}

    # --- Préparation ---
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = now_timestamp_local()

    sql_file = BACKUP_DIR / f"wms_backup_{ts}.sql"
    csv_file = BACKUP_DIR / f"wms_{table_name}_{ts}.csv"
    json_report = REPORT_DIR / f"backup_wms_{ts}.json"

    # Variables d'environnement pour MariaDB (évite le mot de passe en clair dans la commande)
    # Les clients MariaDB/MySQL supportent MYSQL_PWD.
    env = os.environ.copy()
    env["MYSQL_PWD"] = db_password

    started_at = datetime.datetime.now().isoformat()
    t0 = time.time()

    report = {
        "module": "backup_wms",
        "status": "running",
        "started_at": started_at,
        "db": {
            "host": db_host,
            "port": db_port,
            "name": db_name,
            "user": db_user
        },
        "exported_table": table_name,
        "artifacts": [],
        "messages": []
    }

    try:
        # --- 1) Dump complet SQL ---
        dump_cmd = [
            "mariadb-dump",
            "--single-transaction",
            "--routines",
            "--triggers",
            "--events",
            "-h", db_host,
            "-P", str(db_port),
            "-u", db_user,
            db_name
        ]

        with open(sql_file, "w", encoding="utf-8") as f:
            proc = subprocess.run(
                dump_cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                env=env,
                check=True
            )

        # --- 2) Export table (TSV) puis conversion -> CSV ---
        # --batch : format tabulé
        # --raw   : moins d'échappement
        # On conserve les noms de colonnes : première ligne = header
        export_cmd = [
            "mariadb",
            "-h", db_host,
            "-P", str(db_port),
            "-u", db_user,
            "--batch",
            "--raw",
            "-e", f"SELECT * FROM {table_name};",
            db_name
        ]

        proc2 = subprocess.run(
            export_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        lines = proc2.stdout.splitlines()
        if not lines:
            raise RuntimeError(f"Export table '{table_name}' vide (aucune sortie)")

        header = lines[0].split("\t")
        rows = [ln.split("\t") for ln in lines[1:]]

        # Conversion \N (NULL) -> vide (optionnel, mais pratique)
        def norm(v: str) -> str:
            return "" if v == r"\N" else v

        with open(csv_file, "w", encoding="utf-8", newline="") as fcsv:
            writer = csv.writer(fcsv, delimiter=",", quoting=csv.QUOTE_MINIMAL)
            writer.writerow([norm(c) for c in header])
            for r in rows:
                writer.writerow([norm(c) for c in r])

        # --- 3) Vérification intégrité (taille + hash) ---
        for p in (sql_file, csv_file):
            if not p.exists() or p.stat().st_size <= 0:
                raise RuntimeError(f"Fichier invalide ou vide : {p.name}")

            report["artifacts"].append({
                "path": str(p),
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p)
            })

        # --- Fin / Rapport ---
        ended_at = datetime.datetime.now().isoformat()
        report["status"] = "ok"
        report["ended_at"] = ended_at
        report["duration_seconds"] = round(time.time() - t0, 3)

        write_json(json_report, report)

        print("[OK] Sauvegarde WMS réussie")
        print(f"     - Dump SQL  : {sql_file}")
        print(f"     - Export CSV: {csv_file}")
        print(f"     - Rapport   : {json_report}")

        return EXIT_OK, report

    except subprocess.CalledProcessError as e:
        err = e.stderr.decode(errors="ignore") if isinstance(e.stderr, (bytes, bytearray)) else str(e.stderr)
        report["status"] = "error"
        report["error"] = "command_failed"
        report["details"] = err.strip()
        report["ended_at"] = datetime.datetime.now().isoformat()
        report["duration_seconds"] = round(time.time() - t0, 3)

        write_json(json_report, report)

        print("[ERREUR] Échec d'une commande MariaDB")
        if err:
            print(err)

        return EXIT_CMD_FAILED, report

    except Exception as e:
        report["status"] = "error"
        report["error"] = "unexpected"
        report["details"] = str(e)
        report["ended_at"] = datetime.datetime.now().isoformat()
        report["duration_seconds"] = round(time.time() - t0, 3)

        write_json(json_report, report)

        print(f"[ERREUR] Exception inattendue : {e}")
        return EXIT_INTEGRITY_FAILED, report


if __name__ == "__main__":
    code, _report = backup_wms()
    raise SystemExit(code)

