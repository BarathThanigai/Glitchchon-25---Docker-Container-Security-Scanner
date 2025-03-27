# Glitchchon-25---Docker-Container-Security-Scanner
Our project is an automated security scanner designed to continuously monitor Python projects for vulnerabilities, weak file permissions, and potential security risks. It integrates multiple security tools, including Bandit and Semgrep, to detect command injection, hardcoded secrets (API keys, passwords), and misconfigurations.


README
------

This text file is for the ease of the user to scan container files using our security-scanner. 
This file contains multiple commands that will complete the process of scanning.

Use the following commands based on your use:-

* docker cp C:\Hackathon\test_file.py sample_container:/test_file.py
Replace "test_file.py" with your required file for scanning
"sample_container" is your container name

* docker cp C:\Hackathon\security-scanner.py sample_container:/security-scanner.py
Run this command after getting your file inside the container. Make sure the security-scanner.py is also within the container

* docker exec -it sample_container bash
Use this command to start executing files within the container. Make sure NOT to run the vulnerable files, only run security-scanner.py as shown in the next point.

* python3 security-scanner.py
Use this command to start executing and scanning the "test_file"/or"your_file_name".

* exit
After the scanning is done, exit the container run mode. THe "root<id>" should be replaced by "PS C:\WINDOWS\system32>"

* docker cp <container_id>:/Folder_name/scan_report.json C:\Folder_name\
If you require the log file of the scan/report, enter this command AFTER you have exited the container run mode. Then, head to the folder where you have stored security-scanner.py, and check the "scan_report.json" file. If it works, it should print on powershell - "Successfully copied 21kB to C:\Hackathon\". FIle size of the report can vary.

* Ctrl+C
The security-scanner.py runs on time intervals that can be changed within the program file itself, around the end of the file. 
The program line should say "time.sleep(your_desired_time_in_seconds)". By default, the scanning is kept at 10 minutes time interval.
To end the checking, enter the command.

NOTES
-----
* Do NOT run malicious software/or programs that could harm the os within the container.
* Remember to replace all the default file names with your file name for it to work.
* If encountering permission issues, run Powershell as Administrator and try again.
