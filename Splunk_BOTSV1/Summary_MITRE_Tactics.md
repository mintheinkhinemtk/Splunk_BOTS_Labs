# **Summary**


#### **Mapping with the MITRE framework**

Tactic	Technique	Evidence

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
