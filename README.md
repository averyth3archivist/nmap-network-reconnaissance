# Nmap Network Reconnaissance
## Network Discovery Test for scanme.nmap.org using Nmap

### Objective:
The objective of this project is to conduct a network discovery test for scanme.nmap.org to identify any potential vulnerabilities, using Nmap on a Linux command line interface.
### Target:
The target of this network discovery test is scanme.nmap.org, a system set up specifically for Nmap usage and testing purposes. Authorization to scan this system and its ports is provided on their website.

### Task 1: Unconfigured Nmap Scan
Performing an unconfigured Nmap scan on the target reveals the following open ports:
* Port 22 (SSH service)
* Port 80 (HTTP service)
* Port 9929 (Nping-echo service)
* Port 31337 (Elite service)
  
![alt text][task1]

[task1]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task1.png "Unconfigured Nmap Scan"

All ports utilize the TCP protocol.

### Task 2: Scan with scanning.nse Script
Utilizing a customized script ```scanning.nse``` to display a message for any open HTTP ports on scanme.nmap.org. The scanning.nse script can provide valuable insights into open HTTP ports, potentially revealing additional information about the web services running on the target. In this case of this target, the only open HTTP port is port 90.
![alt text][task2_1]

[task2_!]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task2_nse.png "scanning.nse"

![alt text][task2_2]

[task2_2]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task2_bash.png "Customized Script Scan"

### Task 3: Service Probe
Using the ```-sV``` configuration option to detect the service and version of each open port.

![alt text][task3]

[task3]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task3.png "Service Probe"

#### Port 22 (OpenSSH 6.6.1p1 Ubuntu)
Port 22, identified as the SSH service, is commonly used for secure remote access to systems. Vulnerabilities associated with the OpenSSH service include:
* CVE-2014-1692 (OpenSSH Weak Key Generation)
* CVE-2014-2532 (OpenSSH User Enumeration)
* CVE-2014-2653 (OpenSSH Privilege Separation Bypass)
* CVE-2014-3127 (OpenSSH Environment Variable Injection)
* CVE-2014-3659 (OpenSSH Agent Authentication Bypass)
* CVE-2014-5352 (OpenSSH Weak HMAC Comparison)

The listed vulnerabilities are all on the CVE (Common Vulnerabilties and Exposures) list and therefore pose significant risks to system security. It's essential to regularly update and secure SSH configurations to mitigate these vulnerabilities.

#### Port 9929 (Nping-echo)
Port 9929, identified as the Nping-echo service, is used by Nping, a tool used for network packet generation and analysis. The vulnerabilities associated with the Nping-echo service include:
* Denial of Service (DoS)
* Buffer Overflows
* Privilege Escalation
* Information Disclosure
  
#### Port 31337 (tcpwrapped) 
Port 31337, also known as the "Elite" port, is often associated with backdoor access and is historically used by hackers for unauthorized access to systems. It's imperative to closely monitor and secure this port to prevent potential exploitation by malicious actors. Vulnerabilities associated with the tcpwrapped service include:
* Buffer Overflows
* Denial of Service (DoS)
* Bypassing Access Controls

### Task 4: HTTP Enumeration
![alt text][task4]

[task4]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task4.png "HTTP Enumeration"

Port 80 is commonly used for HTTP web services. HTTP Enumeration Enumerates directories used by popular web applications and servers. The HTTP-enum script scan intiailly reveals an interesting directory. This prompted a further investigation into the http port, conudcting the scan with the display all argument, which reveals:
* Potential path traversal vulnerabilities in VMWare (CVE-2009-3733)
* Detection of a ```400 Bad Request``` status code
* Identification of interesting directories like 'icons', 'server-status', 'shared', and 'images'

![alt text][task4_all]

[task4_all]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task4_all.png "HTTP Enumeration with Display All Argument"

The detection of a ```400 Bad Request``` status code suggests that the server detected a malicious request and responded with an error, indicating potential security measures in place.
  
### Task 5: Preloaded NSE Scripts
Utilizing preloaded NSE scripts to gather additional information about the target system:
* The ssh-auth-methods script reveals support for public key and password authentication methods.
* The ssh-hostkey script displays the host key in different encryption methods.
* The unusual ports script confirms no unusual port usage.
  
***SSH Authentication Methods script***

![alt text][task5_sshauth]

[task5_sshauth]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task5_sshauth.png "SSH Authentication Methods script"

***SSH Hostkey script***

![alt text][task5_sshkey]

[task5_sshkey]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/aac1ff463b070c38b22a6a59503e6d5df9ba5ed0/nmap_task5_sshkey.png "SSH Hostkey script"

***Scan for unusual ports***

![alt text][task5_ports]

[task5_ports]: https://github.com/averyth3archivist/nmap-network-reconnaissance/blob/6a2031e63e3aa9ad4ceea040976cf8f7bbcee7eb/nmap_task5_ports.png "Unusual Ports Scan"

By examining the SSH authentication methods and host key encryption, potential security risks related to SSH access can be identified and addressed. The confirmation of no unusual port usage provides reassurance regarding the network's standard configuration.
  
### Conclusion:
This network discovery test using Nmap on scanme.nmap.org identified various open ports, potential vulnerabilities, and interesting directories. Further analysis and mitigation strategies can be implemented based on the findings.
