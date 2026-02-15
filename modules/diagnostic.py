import platform
import psutil
import time
import os
import pymysql
import socket
import ipaddress
import json
import getpass
import subprocess
from utils.logger import setup_logger, write_json_report
from utils.config import ConfigLoader
from utils.credentials import get_credentials

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("[WARNING] paramiko not installed. SSH metrics collection will be disabled.")

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

def get_remote_metrics_ssh(ip, username, password):
    """Collects metrics from a remote Linux server via SSH."""
    if not PARAMIKO_AVAILABLE:
        return None, "paramiko not installed"
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=5)
        
        metrics = {}
        
        # Get OS version
        stdin, stdout, stderr = client.exec_command('cat /etc/os-release | grep PRETTY_NAME')
        os_line = stdout.read().decode().strip()
        metrics['os_version'] = os_line.split('=')[1].strip('"') if '=' in os_line else 'Linux'
        
        # Get uptime (in seconds)
        stdin, stdout, stderr = client.exec_command('cat /proc/uptime')
        uptime_line = stdout.read().decode().strip()
        uptime_sec = int(float(uptime_line.split()[0]))
        metrics['uptime_seconds'] = uptime_sec
        
        # Get CPU usage (approximate)
        stdin, stdout, stderr = client.exec_command('top -bn1 | grep "Cpu(s)" | awk \'{print $2}\' | cut -d"%" -f1')
        cpu_str = stdout.read().decode().strip()
        metrics['cpu_percent'] = float(cpu_str) if cpu_str else 0.0
        
        # Get memory usage
        stdin, stdout, stderr = client.exec_command('free | grep Mem | awk \'{print ($3/$2) * 100.0}\'')
        mem_str = stdout.read().decode().strip()
        metrics['memory_percent'] = float(mem_str) if mem_str else 0.0
        
        # Get disk usage
        stdin, stdout, stderr = client.exec_command('df -h / | tail -1 | awk \'{print $5}\' | cut -d"%" -f1')
        disk_str = stdout.read().decode().strip()
        metrics['disk_percent'] = float(disk_str) if disk_str else 0.0
        
        client.close()
        return metrics, None
    except Exception as e:
        return None, str(e)

def get_remote_metrics_powershell(ip, username, password):
    """Collects metrics from a remote Windows server via PowerShell Invoke-Command."""
    try:
        metrics = {}
        
        # Use Invoke-Command for proper WinRM remoting
        # This approach handles credentials and WinRM sessions correctly
        ps_script = f"""
$SecPassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ('{username}', $SecPassword)

try {{
    $result = Invoke-Command -ComputerName {ip} -Credential $Cred -ScriptBlock {{
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cpu = Get-CimInstance -ClassName Win32_Processor
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
        
        [PSCustomObject]@{{
            os_version = $os.Caption
            uptime_seconds = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
            cpu_percent = if ($cpu.LoadPercentage) {{ ($cpu.LoadPercentage | Measure-Object -Average).Average }} else {{ 0 }}
            memory_percent = if ($os.TotalVisibleMemorySize -gt 0) {{
                (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100
            }} else {{ 0 }}
            disk_percent = if ($disk.Size -gt 0) {{
                (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100
            }} else {{ 0 }}
        }}
    }} -ErrorAction Stop
    
    $result | ConvertTo-Json -Compress
}} catch {{
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}}
"""
        
        # Execute PowerShell command
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode != 0:
            # Extract clean error message instead of dumping entire script
            error_msg = "WinRM connection failed"
            
            if result.stdout and "ERROR:" in result.stdout:
                # Get custom error message from script
                error_msg = result.stdout.split("ERROR:")[-1].strip()
            elif result.stderr:
                # Extract last meaningful line from stderr
                lines = [l.strip() for l in result.stderr.split('\n') if l.strip() and not l.startswith('$')]
                for line in reversed(lines):
                    if any(keyword in line for keyword in ['cannot', 'failed', 'error', 'impossible', 'denied']):
                        error_msg = line[:100]  # Limit length
                        break
                else:
                    if lines:
                        error_msg = lines[-1][:100]
            
            return None, error_msg
        
        # Parse JSON output
        import json
        data = json.loads(result.stdout.strip())
        
        metrics['os_version'] = data.get('os_version', 'Windows')
        metrics['uptime_seconds'] = int(data.get('uptime_seconds', 0))
        metrics['cpu_percent'] = float(data.get('cpu_percent', 0))
        metrics['memory_percent'] = float(data.get('memory_percent', 0))
        metrics['disk_percent'] = float(data.get('disk_percent', 0))
        
        return metrics, None
        
    except json.JSONDecodeError as e:
        return None, f"Failed to parse response"
    except Exception as e:
        return None, f"PowerShell error: {str(e)[:50]}"

def check_server_availability(ip, ssh_user=None, ssh_pass=None, win_user=None, win_pass=None):
    """Checks if a server is online and collects detailed metrics if credentials are provided."""
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
    
    if not open_ports:
        return False, "Offline", "Unknown", "No open ports found", {}
    
    # Attempt to get detailed metrics if credentials are provided
    metrics = {}
    
    if detected_os == "Likely Linux" and ssh_user and ssh_pass:
        remote_metrics, error = get_remote_metrics_ssh(ip, ssh_user, ssh_pass)
        if remote_metrics:
            metrics = remote_metrics
            detected_os = remote_metrics.get('os_version', 'Linux')
        elif error:
            logger.debug(f"SSH metrics collection failed for {ip}: {error}")
    
    elif detected_os == "Likely Windows" and win_user and win_pass:
        remote_metrics, error = get_remote_metrics_powershell(ip, win_user, win_pass)
        if remote_metrics:
            metrics = remote_metrics
            detected_os = remote_metrics.get('os_version', 'Windows')
        elif error:
            logger.debug(f"Windows metrics collection failed for {ip}: {error}")
    
    # Fallback: If OS is Unknown but credentials provided, try both methods
    elif detected_os == "Unknown" and (ssh_user or win_user):
        # Try SSH first
        if ssh_user and ssh_pass:
            remote_metrics, error = get_remote_metrics_ssh(ip, ssh_user, ssh_pass)
            if remote_metrics:
                metrics = remote_metrics
                detected_os = remote_metrics.get('os_version', 'Linux')
            elif error:
                logger.debug(f"SSH attempt on {ip} failed: {error}")
        
        # If SSH failed or not provided, try PowerShell
        if not metrics and win_user and win_pass:
            remote_metrics, error = get_remote_metrics_powershell(ip, win_user, win_pass)
            if remote_metrics:
                metrics = remote_metrics
                detected_os = remote_metrics.get('os_version', 'Windows')
            elif error:
                logger.debug(f"PowerShell attempt on {ip} failed: {error}")
    
    return True, "Online", detected_os, ", ".join(open_ports), metrics

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
    ssh_user = None
    ssh_pass = None
    win_user = None
    win_pass = None
    
    ip_input = input("Enter IP range to scan (e.g., 192.168.1.10-15 or 192.168.1.5, 192.168.1.6): ").strip()
    if ip_input:
        check_ips = expand_ip_range(ip_input)
        
        # Ask for credentials if scanning servers
        if check_ips:
            collect_creds = input("Collect detailed metrics (CPU/RAM/Disk)? Requires credentials. (y/n, default n): ").strip().lower()
            if collect_creds == 'y':
                # Load credentials from environment or encrypted file first
                stored_creds = get_credentials()
                
                # Use stored credentials or prompt for missing ones
                ssh_user = stored_creds.get('ssh_user')
                ssh_pass = stored_creds.get('ssh_pass')
                win_user = stored_creds.get('win_user')
                win_pass = stored_creds.get('win_pass')
                
                # Only prompt for credentials that weren't found
                if not ssh_user:
                    ssh_user = input("SSH Username (for Linux servers, leave empty to skip): ").strip() or None
                else:
                    print(f"SSH Username: {ssh_user} (from stored credentials)")
                    
                if ssh_user and not ssh_pass:
                    ssh_pass = getpass.getpass("SSH Password: ")
                elif ssh_user:
                    print("SSH Password: ******* (from stored credentials)")
                
                if not win_user:
                    win_user = input("Windows Username (for Windows servers, leave empty to skip): ").strip() or None
                else:
                    print(f"Windows Username: {win_user} (from stored credentials)")
                    
                if win_user and not win_pass:
                    win_pass = getpass.getpass("Windows Password: ")
                elif win_user:
                    print("Windows Password: ******* (from stored credentials)")

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
        
        is_online, status_txt, os_guess, ports, metrics = check_server_availability(
            ip, ssh_user=ssh_user, ssh_pass=ssh_pass, win_user=win_user, win_pass=win_pass
        )
        
        status = "OK" if is_online else "CRITICAL"
        color_status = status_txt
        
        # Display metrics if available
        if metrics:
            cpu = metrics.get('cpu_percent', 'N/A')
            ram = metrics.get('memory_percent', 'N/A')
            disk = metrics.get('disk_percent', 'N/A')
            uptime = metrics.get('uptime_seconds', 'N/A')
            print(f"{color_status} [{os_guess}] - CPU: {cpu}%, RAM: {ram}%, Disk: {disk}%, Uptime: {uptime}s")
        else:
            print(f"{color_status} [{os_guess}] - Ports: {ports}")
            if ssh_user or win_user:
                print(f"    └─ Metrics collection failed (check logs for details)")
        
        scan_entry = {
            "ip": ip,
            "status": status,
            "os_detected": os_guess,
            "details": ports
        }
        
        if metrics:
            scan_entry["metrics"] = metrics
        
        report_data["server_scans"].append(scan_entry)

    # Save Report
    report_path = write_json_report("diagnostic_report.json", report_data, subdirectory="diagnostic")
    print(f"\n[Diagnostic] Completed. Report saved to: {report_path}")
    return "DONE"

if __name__ == "__main__":
    run_diagnostic()
