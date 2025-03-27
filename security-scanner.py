import os
import re
import json
import subprocess
import time

# Paths to scan (Modify as needed)
SCAN_DIR = "/test_file.py"

print("🔍 Security scanner is running...")

# Colors for output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Store scan results
scan_results = []

def log_issue(issue_type, file_path, details):
    """Log security issues to a list."""
    scan_results.append({
        "type": issue_type,
        "file": file_path,
        "details": details
    })

def save_report():
    """Save scan results to the Hackathon folder within the project directory."""
    project_dir = os.getcwd()  # Get current directory
    hackathon_folder = os.path.join(project_dir, "Hackathon")  
    json_path = os.path.join(hackathon_folder, "scan_report.json")

    with open(json_path, "w") as f:
        json.dump(scan_results, f, indent=4)
    
    print(f"📜 Security scan report saved at: {json_path}")


def check_file_permissions():
    """Check and fix files with weak permissions (world-writable)."""
    print(f"{YELLOW}🔍 Scanning for weak file permissions...{RESET}")
    weak_files = []
    
    for root, _, files in os.walk(SCAN_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                mode = oct(os.stat(file_path).st_mode)[-3:]
                if mode in ["777", "666"]:  # World-writable
                    weak_files.append(file_path)
                    os.chmod(file_path, 0o600)  # Fix permissions
                    log_issue("Weak Permissions Fixed", file_path, "Permissions changed to 600")
            except Exception:
                pass

    if weak_files:
        print(f"{RED}⚠️ Weak file permissions detected and fixed:{RESET}")
        for f in weak_files:
            print(f"   {f}")
    else:
        print(f"{GREEN}✅ No weak file permissions found!{RESET}")

def scan_file_for_vulnerabilities(file_path):
    """Scan Python files for security vulnerabilities and secrets."""
    print(f"🔍 Checking: {file_path}")  
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
    except Exception as e:
        print(f"{RED}Error reading {file_path}: {e}{RESET}")
        return

    vulnerabilities = []
    
    # Detecting dangerous os.system() calls
    for line_num, line in enumerate(lines, start=1):
        if "os.system(" in line:
            vulnerabilities.append(f"🚨 Potential Command Injection at line {line_num}: {line.strip()}")
            log_issue("Command Injection", file_path, line.strip())

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
                log_issue(issue, file_path, line.strip())

    if vulnerabilities:
        print(f"{RED}⚠️ Vulnerabilities Found in {file_path}:{RESET}")
        for v in vulnerabilities:
            print(f"   {v}")
    else:
        print(f"{GREEN}✅ No vulnerabilities found in {file_path}!{RESET}")

def scan_directory_for_python_vulnerabilities():
    """Scan all Python files in the directory."""
    print(f"{YELLOW}🔍 Scanning Python files for vulnerabilities...{RESET}")
    for root, _, files in os.walk(SCAN_DIR):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                scan_file_for_vulnerabilities(file_path)

def run_bandit_scan(file_path):
    """Run Bandit security scan on a specific Python file inside the container."""
    print(f"🔍 Running Bandit on {file_path}...")

    try:
        result = subprocess.run(
            ["/usr/bin/bandit", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print(result.stdout)
        log_issue("Bandit Security Scan", file_path, result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"❌ Bandit error:\n{e.stderr}")  

def run_semgrep_scan(file_path):
    """Run Semgrep scan on a specific file."""
    print(f"🔍 Running Semgrep on {file_path}...")
    result = subprocess.run(["semgrep", "--config", "auto", file_path], capture_output=True, text=True)
    print(result.stdout)
    log_issue("Semgrep Security Scan", file_path, result.stdout)

test_file = "/test_file.py"


if __name__ == "__main__":
    while True:
        print("🔄 Running automated security scan...")
        scan_file_for_vulnerabilities(SCAN_DIR)
        check_file_permissions()
        scan_directory_for_python_vulnerabilities()
        run_bandit_scan(test_file)
        run_semgrep_scan(test_file)
        save_report()
        
        print("✅ Scan complete! Next scan in 1 hour.")
        time.sleep(10)  # Wait 1 hour before running again


# Save the security report
save_report()
