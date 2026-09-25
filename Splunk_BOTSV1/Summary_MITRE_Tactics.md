# **Summary**

## **Scenario 1**

### **Mapping with the MITRE framework**


**1. RECONNAISSANCE**


The attacker firstly did the vulnerability scanning to the web server, imreallynotbatman.com, with '40.80.148.42' gathering the information of CMS as joomla using Acuentix Web Vulnerability Scanner.



**2. RESOURCE DEVELOPMENT**


The attacker tied '23.22.63.114' IP to their domains that are pre-staged to attack Wayne Enterprises and  used dynamic dns services like jumpingcrab.com resolving to their IP, '23.22.63.114'. They also prepared their IP, '40.80.148.42', for attacking Wayne Enterprises.



**3. INITIAL ACCESS**


The attacker attempted brute force attack to the web server using '23.22.63.114' IP and from this, they got the admin password for the joomla CMS. 


They got the access to the CMS with the password using '40.80.148.42' IP.



**4. EXECUTION, PERSISTENCE and 'COMMAND AND CONTROL'**


They uploaded the web shell, 'agent.php', successfully and got the web shell access as a persistence mechanism. From this, attacker executed commands using the web shell and dropped the malware, 3791.exe, using that shell access and got the reverse shell to their C2 with the help of malware to gain persistence and C2 tactics.



**5. IMPACT** 

The Wayne Enterprise had the confidential, integrity and reputational impact from this incident. 
The attacker got access to the web server, forced the system to write, save, and execute arbitrary code via the persistence shells and do the web defacement impacting confidential, integrity and reputational ones.


## **Scenario 2**

### **Mapping with the MITRE framework**

**1. Initial Access**

Replication Through Removable Media	USB key - MIRANDA_PRI was inserted with malicious .dotm


**2. Execution**

User Execution -	Bob opened Miranda_Tate_unveiled.dotm in WINWORD.EXE

Command and Scripting Interpreter -	Obfuscated VBScript from the dotm file was executed via cmd.exe and PowerShell	Script spawned 


**3. Stealth**

Obfuscated Files or Information -	VBScript obfuscated with variable junk and encoding

Masquerading- Match Legitimate Name	Malware named osk.exe (on-screen keyboard) and fake 404 status	HTTP response that returned 404 but file downloaded successfully

Timestomp:	File creation time changed to 1602-05-15


**4. Discovery**

File and Directory Discovery - The ransomware	scanned C:\Users\bob.smith.* and the fileshare on the file server for files to encrypt


**5. Collection**

Data from Local System - The ransomware	Accessed files on remote file share


**6. Command and Control**

Application Layer Protocol -	C2 via HTTP to 37.187.37.150

Dynamic Resolution - Domain Generation Algorithm	for the IP '37.187.37.150'.

Data Obfuscation - Steganography	mhtr.jpg contained cryptor code

Ingress Tool Transfer	- Downloaded mhtr.jpg (ransomware cryptor)


**7. Impact**

Data Encrypted for Impact	- 257 PDFs encrypted on the file server and 406 .txt files on Bob's profile
