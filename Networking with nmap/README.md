Task 1: Basic Network Scanning with Nmap

 Overview

This task demonstrates the use of Nmap, a powerful network scanning tool, to identify open ports and running services on a local machine. The objective is to gain practical experience in network reconnaissance, a foundational skill in cybersecurity and system administration.



 Scan Procedure

Tool Used: 
Nmap version 7.97 (Windows build)

Scan Command Executed:
```sh
nmap localhost > nmap_scan_results.txt
```
This command initiates a TCP scan against the local machine (`localhost`), redirecting the output to a text file for documentation and analysis.



 Results

The scan identified the following open ports and associated services:

| Port     | State | Service       | Description                                              |
|----------|-------|---------------|----------------------------------------------------------|
| 135/tcp  | open  | msrpc         | Microsoft RPC, essential for Windows network operations. |
| 445/tcp  | open  | microsoft-ds  | Microsoft Directory Services, used for SMB file sharing. |
| 3306/tcp | open  | mysql         | MySQL database server, handles database connections.     |



Analysis & Significance

- **135/tcp (msrpc):**  
  This port is used by Microsoft’s Remote Procedure Call service, which enables communication between Windows applications across a network. While necessary for certain Windows functions, it is a common target for exploits and should be firewalled from untrusted networks.

- **445/tcp (microsoft-ds):**  
  Port 445 is used for Microsoft Directory Services, specifically for SMB (Server Message Block) protocol. This port facilitates file and printer sharing on Windows networks. Exposing this port to the internet is a significant security risk, as it is frequently targeted by malware and ransomware.

- **3306/tcp (mysql):**  
  The default port for MySQL database servers. It should only be accessible to trusted hosts, as unauthorized access could lead to data breaches or loss of data integrity.



Security Recommendations

- Restrict access to these ports using a firewall, allowing only trusted IP addresses.
- Regularly update and patch services to mitigate known vulnerabilities.
- Disable unnecessary services to reduce the attack surface.




Screenshots

Below is a screenshot of the Nmap scan output as seen in the terminal

  ![Nmap Output] -----Task-1 output.png



Files Included

- `nmap_scan_results.txt` – Raw output from the Nmap scan.
- `nmap_output.png` – Screenshot of the scan process and results.
- `README.md` – This documentation file.



 Conclusion

This exercise provided hands-on experience with Nmap, reinforcing the importance of regular network scanning and service enumeration in maintaining a secure computing environment.



