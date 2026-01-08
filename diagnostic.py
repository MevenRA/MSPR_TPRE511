import platform
import psutil
import time
import os
import pymysql
import socket
from utils.logger import setup_logger, write_json_report
from utils.config import ConfigLoader

logger = setup_logger("diagnostic")

class SystemDiagnostic:
    @staticmethod
    def get_system_metrics():
        """Collects CPU, RAM, Disks and Uptime metrics."""
        cpu_usage = psutil.cpu_percent(interval=1)
        
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        # Collect usage for all mounted physical partitions
        disks_info = []
        try:
            partitions = psutil.disk_partitions()
            for partition in partitions:
                # Skip pseudo filesystems/CD-ROMs if necessary, but checking all read-write is safer
                if 'cdrom' in partition.opts or partition.fstype == '':
                    continue
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks_info.append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "percent": usage.percent,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2)
                    })
                except PermissionError:
                    continue
        except Exception as e:
            logger.error(f"Error reading disks: {e}")

        # Fallback if no disks found (unlikely)
        if not disks_info:
            try:
                # Fallback to root
                usage = psutil.disk_usage('/')
                disks_info.append({
                    "device": "root",
                    "mountpoint": "/",
                    "percent": usage.percent
                })
            except:
                pass

        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)

        return {
            "cpu_percent": cpu_usage,
            "memory_percent": memory_usage,
            "disks": disks_info,
            "uptime_seconds": uptime_seconds,
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version()
        }

    @staticmethod
    def check_thresholds(metrics: dict):
        """Compares metrics against configured thresholds."""
        thresholds = ConfigLoader.get("thresholds")
        alerts = []
        status = "OK"

        if metrics["cpu_percent"] > thresholds.get("cpu_critical", 90):
            alerts.append("CRITICAL: CPU usage high")
            status = "CRITICAL"
        elif metrics["cpu_percent"] > thresholds.get("cpu_warning", 80):
            if status != "CRITICAL": status = "WARNING"
            alerts.append("WARNING: CPU usage high")

        if metrics["memory_percent"] > thresholds.get("ram_critical", 90):
            status = "CRITICAL"
            alerts.append("CRITICAL: RAM usage high")
        elif metrics["memory_percent"] > thresholds.get("ram_warning", 80):
            if status != "CRITICAL": status = "WARNING"
            alerts.append("WARNING: RAM usage high")

        # Check all disks
        disk_crit = thresholds.get("disk_critical", 90)
        disk_warn = thresholds.get("disk_warning", 80)
        
        for disk in metrics.get("disks", []):
            d_name = disk['mountpoint']
            if disk["percent"] > disk_crit:
                status = "CRITICAL"
                alerts.append(f"CRITICAL: Disk {d_name} usage high ({disk['percent']}%)")
            elif disk["percent"] > disk_warn:
                if status != "CRITICAL": status = "WARNING"
                alerts.append(f"WARNING: Disk {d_name} usage high ({disk['percent']}%)")

        return status, alerts

class ServiceDiagnostic:
    @staticmethod
    def check_mysql():
        """Checks MySQL connectivity using config credentials."""
        db_conf = ConfigLoader.get("database")
        try:
            conn = pymysql.connect(
                host=db_conf.get("host"),
                user=db_conf.get("user"),
                password=db_conf.get("password"),
                database=db_conf.get("db_name"),
                connect_timeout=3
            )
            conn.close()
            return True, "MySQL is accessible"
        except Exception as e:
            return False, f"MySQL unreachable: {str(e)}"

    @staticmethod
    def check_ad_dns():
        """Checks AD/DNS availability via TCP connect."""
        ad_conf = ConfigLoader.get("ad_server")
        host = ad_conf.get("host")
        # Standard AD ports: 389 (LDAP) or 53 (DNS)
        # Checking DNS port 53 as proxy for AD/DNS service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, 53))
            sock.close()
            if result == 0:
                return True, f"AD/DNS at {host} is reachable on port 53"
            else:
                return False, f"AD/DNS at {host} unreachable on port 53"
        except Exception as e:
            return False, f"Error checking AD/DNS: {str(e)}"

def run_diagnostic():
    """Main function to run all diagnostics."""
    logger.info("Starting System Diagnostic...")
    
    # 1. System Metrics
    metrics = SystemDiagnostic.get_system_metrics()
    sys_status, sys_alerts = SystemDiagnostic.check_thresholds(metrics)
    
    # 2. Service Checks
    mysql_ok, mysql_msg = ServiceDiagnostic.check_mysql()
    ad_ok, ad_msg = ServiceDiagnostic.check_ad_dns()

    # Determine Global Status
    global_status = sys_status
    if not mysql_ok or not ad_ok:
        global_status = "CRITICAL"

    report = {
        "status": global_status,
        "system_metrics": metrics,
        "system_alerts": sys_alerts,
        "services": {
            "mysql": {"available": mysql_ok, "message": mysql_msg},
            "ad_dns": {"available": ad_ok, "message": ad_msg}
        }
    }

    # Output
    logger.info(f"Diagnostic Complete. Status: {global_status}")
    if sys_alerts:
        logger.warning(f"Alerts: {sys_alerts}")
    
    report_path = write_json_report("diagnostic_report.json", report)
    print(f"\n[Diagnostic] Status: {global_status}")
    print(f"[Diagnostic] Report saved to: {report_path}")
    print(f"[Diagnostic] System: {metrics['cpu_percent']}% CPU, {metrics['memory_percent']}% RAM")
    for d in metrics.get('disks', []):
        print(f"             Disk ({d['mountpoint']}): {d['percent']}% Used ({d['free_gb']}GB Free)")
    print(f"[Diagnostic] Services: MySQL={'OK' if mysql_ok else 'FAIL'}, AD/DNS={'OK' if ad_ok else 'FAIL'}")

    return global_status

if __name__ == "__main__":
    import time
    run_diagnostic()
