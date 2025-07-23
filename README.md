# OIBSIP


The Nmap scan was performed on the local subnet using a TCP SYN scan with aggressive timing, targeting the full 192.168.1.0/24 range. The results showed multiple live hosts across the network, each responding on specific ports. Common services detected included SSH on port 22, HTTP on port 80, and HTTPS on port 443. These open ports suggest active systems providing remote access, web interfaces, or secure communications.
The purpose of the scan was to identify which devices are reachable and what services they expose. This information is useful for evaluating network visibility and detecting potential vulnerabilities. No abnormal ports or unexpected services were found during the scan, indicating a relatively stable and predictable network topology.
Based on the outcome, further inspection using version detection or vulnerability scanning may be conducted to assess the configuration and security posture of each detected host.





-Task1 - Nmap Scan

- Scan Command Used

```bash
nmap -sS -Pn -T4 192.168.1.0/24
