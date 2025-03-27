import os
import re
import json
import subprocess
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Only monitor this specific file
WATCH_FILE = os.path.abspath("test_file.py")


print("🔍 Security scanner is running...")

# Colors for output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

scan_results = []

def log_issue(issue_type, details):
    """Log security issues to a list."""
    scan_results.append({
        "type": issue_type,
        "file": WATCH_FILE,
        "details": details
    })

def save_report():
    """Save scan results in the Hackathon folder."""
    project_dir = os.getcwd()  
    hackathon_folder = os.path.join(project_dir, "Hackathon")  
    json_path = os.path.join(hackathon_folder, "scan_report.json")

    os.makedirs(hackathon_folder, exist_ok=True)  

    with open(json_path, "w") as f:
        json.dump(scan_results, f, indent=4)
    
    print(f"📜 Security scan report saved at: {json_path}")

def check_file_permissions():
    """Check and fix weak permissions for test_file.py."""
    try:
        mode = oct(os.stat(WATCH_FILE).st_mode)[-3:]
        if mode in ["777", "666"]:  
            os.chmod(WATCH_FILE, 0o600)  
            log_issue("Weak Permissions Fixed", "Permissions changed to 600")
            print(f"{RED}⚠️ Weak permissions detected and fixed for {WATCH_FILE}{RESET}")
    except Exception:
        pass

def scan_file_for_vulnerabilities():
    """Scan test_file.py for security vulnerabilities and secrets."""
    print(f"🔍 Checking: {WATCH_FILE}")  
    try:
        with open(WATCH_FILE, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
    except Exception as e:
        print(f"{RED}Error reading {WATCH_FILE}: {e}{RESET}")
        return

    vulnerabilities = []
    
    # Detect dangerous os.system() calls
    for line_num, line in enumerate(lines, start=1):
        if "os.system(" in line:
            vulnerabilities.append(f"🚨 Potential Command Injection at line {line_num}: {line.strip()}")
            log_issue("Command Injection", line.strip())

    # Secret and malware scanning
    suspicious_patterns = [
        (r"(?i)AWS_ACCESS_KEY_ID\s*=\s*['\"]?[A-Z0-9]{20}['\"]?", "AWS Key"),
        (r"(?i)AWS_SECRET_ACCESS_KEY\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "AWS Secret Key"),
        (r"(?i)API_KEY\s*=\s*['\"][A-Za-z0-9]{32,}['\"]", "API Key"),
        (r"(?i)TOKEN\s*=\s*['\"][A-Za-z0-9\-_]{30,}['\"]", "Access Token"),
        (r"(?i)(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PWD)\s*=\s*['\"][^'\"]{6,}['\"]", "Database Password"),
        (r"(?i)(SECRET_KEY|JWT_SECRET|FLASK_SECRET)\s*=\s*['\"][A-Za-z0-9@#%^&*!]{8,}['\"]", "Secret Key"),
        (r"exec\(base64\.b64decode\(", "Encoded Malware"),
        (r"os\.system\(['\"](rm|curl|wget|nc)\s", "Suspicious System Call"),
    ]

    for pattern, issue in suspicious_patterns:
        for line_num, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                vulnerabilities.append(f"🔑 {issue} at line {line_num}: {line.strip()}")
                log_issue(issue, line.strip())

    if vulnerabilities:
        print(f"{RED}⚠️ Vulnerabilities Found:{RESET}")
        for v in vulnerabilities:
            print(f"   {v}")
    else:
        print(f"{GREEN}✅ No vulnerabilities found in {WATCH_FILE}!{RESET}")

def run_bandit_scan():
    """Run Bandit security scan on test_file.py."""
    print(f"🔍 Running Bandit on {WATCH_FILE}...")

    try:
        result = subprocess.run(
            ["/usr/bin/bandit", WATCH_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print(result.stdout)
        log_issue("Bandit Security Scan", result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"❌ Bandit error:\n{e.stderr}")  

def run_semgrep_scan():
    """Run Semgrep scan on test_file.py."""
    print(f"🔍 Running Semgrep on {WATCH_FILE}...")
    result = subprocess.run(["semgrep", "--config", "auto", WATCH_FILE], capture_output=True, text=True)
    print(result.stdout)
    log_issue("Semgrep Security Scan", result.stdout)

class SecurityEventHandler(FileSystemEventHandler):
    """Handles changes to test_file.py by triggering a security scan."""
    
    def on_modified(self, event):
        if event.src_path == WATCH_FILE:  
            print(f"\n{YELLOW}⚡ test_file.py modified, scanning...{RESET}")
            check_file_permissions()
            scan_file_for_vulnerabilities()
            run_bandit_scan()
            run_semgrep_scan()
            save_report()

def start_watchdog():
    print(f"📁 Watching file: {WATCH_FILE}") 
    """Start monitoring test_file.py for changes."""
    observer = Observer()
    event_handler = SecurityEventHandler()
    file_dir = os.path.dirname(WATCH_FILE)

    observer.schedule(event_handler, file_dir, recursive=False)  

    print(f"{YELLOW}👀 Watching test_file.py for changes...{RESET}")

    observer.start()
    try:
        while True:
            time.sleep(10)  
    except KeyboardInterrupt:
        observer.stop()
        print("\n🛑 Stopping watchdog...")

    observer.join()

if __name__ == "__main__":
    # Run initial scan
    print("🔄 Running initial security scan...")
    scan_file_for_vulnerabilities()
    check_file_permissions()
    run_bandit_scan()
    run_semgrep_scan()
    save_report()
    
    # Start monitoring test_file.py only
    start_watchdog()
