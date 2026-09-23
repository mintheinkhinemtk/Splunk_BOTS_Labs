# **Summary**




## **Series 1xx**


Insider Attack from Amber Turing (Internal Data Theft and sold to the competitor). 

Installed Tor browser to have an unauthorized connection to sell the confidential information.




## **Series 2xx**


**Reconnaissance**
 
`45.77.65.211` did the vulnerability scan with w3af to `www.brewertalk.com` that had public IP, `52.42.208.228`


**Initial Access**

The attacker got the initial access from the Error-based SQLI attack to the updatexml function on the uri path, `/member.php`, of the web server.


**Credential Access**

Got MyBB hashes of the users and the session cookie and CSRF token of the MyBB admin. 


**Persistence** and **Privilege Escalation**

Created another unauothorized admin-level account, kIagerfield using the CSRF token key of the admin as a persistence mechanism and used it for internal spearphishing attack as well.




## **Series 3xx**


**Initial Access**

Ransomware delivered via USB vendor 058f


**Defense Evasion (Stealth and Defense Impairment)**

The ransomware with perl5.18 masqueraded as a legitimate JVM spawn.


**Impact**

The ransomware encrypted the data impacting the organization's confidentiality, integrity and availability.


**Command & Control** and **Resource Development**

Beaconing to `eidk.duckdns.org` and `eidk.hopto.org` developed by the attacker.


**Exfilitration**

Data was exfiltrated from Mallory's device to `5.39.93.112` with the bittorrent protocol.




## **Series 4xx**


**Resource Development**

Their servers had the SSL certification of C=US.


**Initial Access**

The password-protected invoice.zip email was sent to the origanization and the extracted file, invoice.doc, was run.


**Execution** and **Defense Evasion (Stealth and Defense Impair)** and **Persistence**

The weaponized macro in the document invoice.doc ran other powershell commands as the scheduled base64/UTF-16LE PS -EncodedCommand to get C2 beaconing and ftp commands to download the malicious file with .hwp extension.


AMSI bypass (amsiInitFailed=true) in the encoded powershell commands for defense evasion.

The schtasks "Updater" created daily beaconings to their C2 servers using https.


**Exfiltration**

Data exfiltration to `160.153.91.7` using FTP.




## **Series 5xx**


Data Investigation in the web logs on the store to find the product checkouts abused by the fraudster creating multiple user accounts.


That's it. Thank you........
