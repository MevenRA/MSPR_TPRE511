import platform
import psutil
import time
import os
import pymysql
import socket
import ipaddress
import json
import getpass
from utils.logger import setup_logger, write_json_report
from utils.config import ConfigLoader

logger = setup_logger("diagnostic")

class ServiceDiagnostic:
    @staticmethod
    def check_mysql(host, user=None, password=None, db_name=None):
        """Checks MySQL connectivity using provided credentials or simple port check."""
        
        # If no user provided, check TCP port 3306
        if not user:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, 3306))
                sock.close()
                if result == 0:
                    return True, f"MySQL at {host} is reachable (Port 3306 Open)"
                else:
                    return False, f"MySQL at {host} unreachable on port 3306"
            except Exception as e:
                return False, f"Error checking MySQL port: {str(e)}"

        # If user provided, try authentication
        db_conf = ConfigLoader.get("database")
        _db = db_name or db_conf.get("db_name")

        try:
            conn = pymysql.connect(
                host=host,
                user=user,
                password=password,
                database=_db,
                connect_timeout=3
            )
            conn.close()
            return True, f"MySQL at {host} is accessible (Authenticated as {user})"
        except Exception as e:
            return False, f"MySQL at {host} auth failed: {str(e)}"

    @staticmethod
    def check_ad_dns(host):
        """Checks AD/DNS availability via TCP connect to port 53 (DNS) and 389 (LDAP)."""
        results = []
        is_ok = False
        
        # Check DNS (53)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            res = sock.connect_ex((host, 53))
            sock.close()
            if res == 0:
                results.append("DNS(53): OK")
                is_ok = True
            else:
                results.append("DNS(53): Fail")
        except:
            results.append("DNS(53): Err")

        # Check LDAP (389)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            res = sock.connect_ex((host, 389))
            sock.close()
            if res == 0:
                results.append("LDAP(389): OK")
                is_ok = True
            else:
                results.append("LDAP(389): Fail")
        except:
            results.append("LDAP(389): Err")

        msg = f"AD/DNS {host}: " + ", ".join(results)
        return is_ok, msg

class LocalSystemDiagnostic:
    @staticmethod
    def get_metrics():
        """Collects local system metrics."""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        uptime = int(time.time() - psutil.boot_time())
        
        disks = []
        for p in psutil.disk_partitions():
            if 'cdrom' in p.opts or p.fstype == '': continue
            try:
                u = psutil.disk_usage(p.mountpoint)
                disks.append(f"{p.mountpoint} {u.percent}%")
            except: pass
            
        return {
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disks": disks,
            "uptime_seconds": uptime,
            "os": platform.system()
        }

def expand_ip_range(ip_range_str):
    """Parses a string like '192.168.1.10-20' or '192.168.1.5, 192.168.1.6'."""
    ips = []
    if not ip_range_str:
        return []
    
    parts = [p.strip() for p in ip_range_str.split(',')]
    for part in parts:
        if '-' in part:
            # Range format: 192.168.1.10-20
            try:
                base_ip, end_quad = part.rsplit('.', 1)[0], part.rsplit('.', 1)[1].split('-')[1]
                start_quad = part.rsplit('.', 1)[1].split('-')[0]
                for i in range(int(start_quad), int(end_quad) + 1):
                    ips.append(f"{base_ip}.{i}")
            except:
                logger.error(f"Invalid range format: {part}")
        else:
            # Single IP
            ips.append(part)
    return ips

def check_server_availability(ip):
    """Checks if a server is online by probing common ports."""
    # Ports: SSH(22), DNS(53), HTTP(80), RPC(135), HTTPS(443), RDP(3389)
    common_ports = {
        22: "Linux/SSH",
        135: "Windows/RPC",
        3389: "Windows/RDP",
        80: "HTTP",
        443: "HTTPS",
        53: "DNS"
    }
    
    open_ports = []
    detected_os = "Unknown"
    
    for port, label in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(f"{label}({port})")
                if port == 22: detected_os = "Likely Linux"
                if port in [135, 3389]: detected_os = "Likely Windows"
        except:
            pass
            
    if open_ports:
        return True, "Online", detected_os, ", ".join(open_ports)
    else:
        return False, "Offline", "Unknown", "No open ports found"

def run_diagnostic():
    """Main interactive diagnostic function."""
    print("\n--- Diagnostic Module Initialization (Simplified) ---")
    
    # 1. AD/DNS Configuration
    ad_servers = []
    try:
        num_ad = input("How many AD/DNS servers do you want to diagnose? (default 0): ").strip()
        num_ad = int(num_ad) if num_ad else 0
        for i in range(num_ad):
            ip = input(f"Enter IP for AD/DNS server #{i+1}: ").strip()
            if ip: ad_servers.append(ip)
    except ValueError:
        print("Invalid number entered.")

    # 2. MySQL Configuration
    mysql_server = None
    mysql_user = None
    mysql_pass = None

    mysql_ip = input("Enter MySQL Database IP (leave empty to skip): ").strip()
    if mysql_ip:
        mysql_server = mysql_ip
        mysql_user_input = input("MySQL User for auth check (leave empty for Port 3306 check only): ").strip()
        if mysql_user_input:
            mysql_user = mysql_user_input
            mysql_pass = getpass.getpass("MySQL Password: ")

    # 3. Server Range Configuration
    check_ips = []
    ip_input = input("Enter IP range to scan (e.g., 192.168.1.10-15 or 192.168.1.5, 192.168.1.6): ").strip()
    if ip_input:
        check_ips = expand_ip_range(ip_input)

    print("\n--- Starting Diagnostic ---")
    
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ad_dns_checks": [],
        "mysql_check": {},
        "server_scans": []
    }

    # Execute AD Checks
    print("\n[1/3] Checking AD/DNS Servers...")
    if not ad_servers:
        print("Skipped.")
    for ip in ad_servers:
        ok, msg = ServiceDiagnostic.check_ad_dns(ip)
        status = "OK" if ok else "CRITICAL"
        print(f" -> {ip}: {status} - {msg}")
        report_data["ad_dns_checks"].append({"ip": ip, "status": status, "message": msg})

    # Execute MySQL Check
    print("\n[2/3] Checking MySQL Server...")
    if mysql_server:
        ok, msg = ServiceDiagnostic.check_mysql(mysql_server, user=mysql_user, password=mysql_pass)
        status = "OK" if ok else "CRITICAL"
        print(f" -> {mysql_server}: {status} - {msg}")
        report_data["mysql_check"] = {"ip": mysql_server, "status": status, "message": msg}
    else:
        print("Skipped.")

    # Execute Server Scans
    print(f"\n[3/3] Scanning {len(check_ips)} Servers...")
    for ip in check_ips:
        print(f" -> Scanning {ip}...", end=" ")
        
        is_online, status_txt, os_guess, ports = check_server_availability(ip)
        
        status = "OK" if is_online else "CRITICAL"
        color_status = status_txt
        
        print(f"{color_status} [{os_guess}] - Ports: {ports}")
        
        report_data["server_scans"].append({
            "ip": ip,
            "status": status,
            "os_detected": os_guess,
            "details": ports
        })

    # Save Report
    report_path = write_json_report("diagnostic_report.json", report_data)
    print(f"\n[Diagnostic] Completed. Report saved to: {report_path}")
    return "DONE"

if __name__ == "__main__":
    run_diagnostic()
