import subprocess
import shutil
import sys
import os
import re
import tempfile
from datetime import datetime
from collections import Counter
import smtplib
from email.mime.text import MIMEText

# Configuration
EMAIL = "admin@example.com"
LOG_FILE = "/var/log/port_scan.log"
THRESHOLD = 5  # Number of failed SSH attempts before blocking
BLOCKED_IPS = "/var/log/blocked_ips.log"

def check_requirements():
    """Check if required tools are installed."""
    commands = ['ss', 'iptables', 'mail']
    for cmd in commands:
        if not shutil.which(cmd):
            print(f"Error: {cmd} is not installed.")
            sys.exit(1)

def scan_ports():
    """Scan TCP ports and log results."""
    with open(LOG_FILE, 'w') as f:
        f.write("Scanning TCP ports...\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("------------------------\n")
        
        # Try ss first, fallback to netstat
        try:
            if shutil.which('ss'):
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if 'LISTEN' in line:
                        f.write(line + '\n')
            else:
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if 'LISTEN' in line:
                        f.write(line + '\n')
        except subprocess.CalledProcessError as e:
            print(f"Error scanning ports: {e}")
            return

    # Email the results
    try:
        with open(LOG_FILE, 'r') as f:
            log_content = f.read()
        
        msg = MIMEText(log_content)
        msg['Subject'] = f"TCP Port Scan Results - {os.uname().nodename}"
        msg['From'] = EMAIL
        msg['To'] = EMAIL

        with smtplib.SMTP('localhost') as s:
            s.send_message(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

def block_ssh_attackers():
    """Parse auth.log and block suspicious IPs."""
    print("Checking for failed SSH attempts...")
    
    # Create temporary file for processing
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
        try:
            # Read and process auth.log
            ip_counts = Counter()
            with open('/var/log/auth.log', 'r') as f:
                for line in f:
                    if "Failed password" in line:
                        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if match:
                            ip = match.group(1)
                            ip_counts[ip] += 1
            
            # Write counts to temp file
            for ip, count in ip_counts.items():
                temp_file.write(f"{count} {ip}\n")
        
        except FileNotFoundError:
            print("Error: auth.log not found")
            return
        
        temp_file_path = temp_file.name

    # Process each IP
    try:
        with open(temp_file_path, 'r') as f, open(BLOCKED_IPS, 'a+') as blocked_ips:
            # Read existing blocked IPs
            blocked_ips.seek(0)
            existing_blocked = set(line.strip() for line in blocked_ips)
            
            for line in f:
                count, ip = line.strip().split()
                count = int(count)
                
                if count >= THRESHOLD and ip not in existing_blocked:
                    print(f"Blocking IP: {ip} (Attempts: {count})")
                    try:
                        # Add iptables rule to drop traffic from this IP
                        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                        blocked_ips.write(f"{ip}\n")
                        with open(LOG_FILE, 'a') as log:
                            log.write(f"Blocked IP {ip} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    except subprocess.CalledProcessError as e:
                        print(f"Error blocking IP {ip}: {e}")
    
    finally:
        # Clean up
        os.unlink(temp_file_path)

def main():
    """Main execution."""
    check_requirements()
    scan_ports()
    block_ssh_attackers()
    print(f"Script completed. Results emailed to {EMAIL} and logged to {LOG_FILE}")

if __name__ == "__main__":
    main()