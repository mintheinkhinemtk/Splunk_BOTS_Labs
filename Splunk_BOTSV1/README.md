# Splunk BOTSV1 CTF Walkthrough

**Platform:** Splunk BOTS Version 1 (2015)  

You can sign up for an account and take the challenge at https://bots.splunk.com

**This walkthrough documents the analytical reasoning for each stage**

## Scenario 1 - Web Defacement

### **Q101**

What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

#### **Approach**

Vulnerability scanners generate high-frequency requests with automated behaviour. As the domain was scanned for web application vulnerabilities and the suricata IDS would alert for a high-frequency scanning, the information could be found in stream:http and suricata logs. 


```
index=botsv1 imreallynotbatman.com | stats count by sourcetype | eventstats sum(count) as perc | eval percentage=round(count*100/perc,2)| fields - perc | sort - count
```


<img width="1875" height="612" alt="image" src="https://github.com/user-attachments/assets/1ba19ff9-2082-4045-a329-3d806f2ea24a" />



```
index=botsv1 imreallynotbatman.com sourcetype=suricata
| stats count by src_ip
| sort -count
```

<img width="1877" height="533" alt="image" src="https://github.com/user-attachments/assets/2807e110-ce0f-4d02-a501-15c0f3ed876f" />

As an external IP, 40.80.148.42, had the highest volume in the search results, it appeared to be the attacker's IP that did the vulnerability scan. The information could be analyzed again in stream:http sourcetype as it was the main log source.


```
index=botsv1 imreallynotbatman.com sourcetype=stream:http
| stats count by src_ip, dest_ip
| sort -count
```


<img width="1892" height="536" alt="image" src="https://github.com/user-attachments/assets/763dc7e2-9c63-4f90-9b0c-8fdcca1bed5c" />

40.80.148.42 consistently appeared as the highest volume across both sourcetypes.

Cross-validating against Suricata IDS Signatures was done to confirm the scanning behaviour

```
index=botsv1 imreallynotbatman.com sourcetype=suricata src="40.80.148.42"
| stats values(src), values(signature)
```

<img width="1848" height="818" alt="image" src="https://github.com/user-attachments/assets/1beb8998-2a29-4d2e-86c5-be44a5f1901c" />


The log sources related to source IP, 40.80.148.42, matched multiple suricata scanning signatures, confirming 40.80.148.42 was the attacker's IP. 

 
**Answer: 40.80.148.42**



### **Q102**

What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

#### **Approach**

The http requests would have the information about the vulnerability scanner name 
because the attacker did the  vulnerability scan using http protocol and the requests and therefore, it could be found in 'stream:http'.

After doing deep analysis and reading the logs, the name was found in 'src_headers'.

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http" src_ip="40.80.148.42"
| stats values(src_ip) values(src_headers)
```

<img width="1882" height="731" alt="image" src="https://github.com/user-attachments/assets/9f36540e-cb6d-4c82-8d58-21fbe302eee5" />



**Answer: Acunetix**

### **Q103**

What content management system is imreallynotbatman.com likely using?

#### **Approach**

To know the CMS that the domain was using, it's important to know that the vulnerability scanner could have found the CMS name with the help of http status code '200', 'success', as it would probe for the CMS directories and the attacker could confirm this by seeing the status code.

Because of this, the web server's IP was needed and after doing log analysis, the web server's IP was identified as '192.168.250.70'.

```
index=botsv1 src =40.80.148.42 imreallynotbatman (dest="192.168.250.70") sourcetype=stream:http status=200
|stats count by uri
|eventstats sum(count) as total by uri
|eval percentage = round(count*100/total,2)
|fields - total
|sort -count
```

<img width="1881" height="835" alt="image" src="https://github.com/user-attachments/assets/561b3ffa-d70e-4080-a8f1-92f3570de6cb" />

'joomla' could be seen across multiple uri paths and as we all know, joomla is one of the most widely used CMS.


<img width="1152" height="467" alt="image" src="https://github.com/user-attachments/assets/2081817b-0570-40a8-a734-c6b06e02930a" />


**Answer: joomla**


### **Q104**

What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

#### **Approach**

It is important to know that the web server should not initiate outbound connections to random domains and there must be no user browsing the internet on the web server because of the security policy in order to prevent access to malicious domains.

However, firewalls should not block every initiated outbound connections from the web server blindly as there will be the times that the web server has to initiate the outbound to the legitimate external APIs or other related connections.

Therefore, from my hypothesis and the above theory, attackers could have got the reverse shell access as the initiated outbound connections from the web server would not be blocked by the firewall as not to disrupt the business process.

It was needed to find the external IP that was initiated by the web server, imreallynotbatman.com. Before that, the IP Address of the web server was needed and it's 192.168.250.70 from the above questions.

The information would be searched in suricata, stream:http and fortigate utm logs as they would have the connection and file information.




```
index=botsv1 sourcetype=suricata  src_ip="192.168.250.70" status="200"
|stats count by status, src_ip, dest_ip
```


<img width="1875" height="553" alt="image" src="https://github.com/user-attachments/assets/ad01e015-7a0c-48d2-a340-489a09931eaf" />


Suricata showed that destination IPs connected from the web server. The IP, '108.161.187.134', was investigated first.


```
index=botsv1 sourcetype=suricata  src_ip="192.168.250.70" dest_ip="108.161.187.134" status="200"
|stats count by status, http.hostname, src_ip, dest_ip
```

<img width="1872" height="398" alt="image" src="https://github.com/user-attachments/assets/88ed0299-58fa-41c8-acbb-626467347511" />



Except the two External IPs, 40.80.148.42 and 23.22.63.114, others were excluded as 192.168.2.50 being an internal IP and 106.161.187.134 one of the joomla update sites.

After doing log analysis, an interesting file in the log related to '23.22.63.114' IP was found in suricata logs.


```
index=botsv1 sourcetype=suricata  src_ip="192.168.250.70" dest_ip="23.22.63.114" status="200"
|stats count by http.hostname, http.url, src_ip, dest_ip
```


<img width="1880" height="508" alt="image" src="https://github.com/user-attachments/assets/45cac322-dfad-44e3-b5a5-b85de6026b72" />


Let's investigate in stream:http and fortigate_utm source to confirm the information.


```
index=botsv1 sourcetype=stream:http  src_ip="192.168.250.70" dest_ip="23.22.63.114"
|stats count by src_headers, src_port, src_ip, dest_port, dest_ip
```

<img width="1866" height="581" alt="image" src="https://github.com/user-attachments/assets/3015f11f-6c23-4488-9572-74a23263b460" />

The suspicious domain and the file were found out.


'Fortigate' UTM has the 'Malicious Websites' Category if they regard an external site as malicious

```
index=botsv1 sourcetype=fgt_utm 192.168.250.70 NOT dest=192.168.250.70 category="Malicious Websites" action="allowed"
|stats count by dest
```

<img width="1868" height="402" alt="image" src="https://github.com/user-attachments/assets/6df5f200-f1d5-4d86-9f5b-a58093bd5e91" />



```
index=botsv1 sourcetype=fgt_utm  src="192.168.250.70" dest="23.22.63.114"
| stats count by _time, src, src_port, dest, dest_port, url, action
```

<img width="1863" height="667" alt="image" src="https://github.com/user-attachments/assets/64102718-a35d-4596-a9d9-6155f24be17d" />

As the information found was consistent across the three sourcetypes, the malicious file was confirmed.

**Answer: poisonivy-is-coming-for-you-batman.jpeg**


### **Q105**

This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

We could still find the FQDN information in 'stream:dns' though we found this in the previous question.

#### **Approach**

To know the FQDN of the attacker, it's essential to understand how DNS queries and responses work as DNS resolves domain names to IPs.

The web server would need to know the IP of the domain first before connecting to it. As the connection was made, there must be an answer for the IP.

A DNS transaction has two main parts, the domain name asked for (name{} or query{}) and the IP Address returned by the server.


```
index=botsv1 sourcetype=stream:dns answer="23.22.63.114"
| stats values(name{})
```

<img width="1880" height="397" alt="image" src="https://github.com/user-attachments/assets/b3ec8f57-bbbd-4f36-a7a8-4746f7f4e960" />


**Note: Attackers use dynamic dns services like jumpingcrab.com because the domain-to-IP mapping changes dynamically in order to bypass static IP-based blocking.**


**Answer: prankglassinebracket.jumpingcrab.com** 

### **Q106**

What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

#### **Approach**

As the question asks about the pre stage before the attack, the necessary information won't be able to be found in the logs. 

Because of this, OSINT had to be relied on. There were two external IPs related to this attack, 40.80.148.42 and 23.22.63.114

40.80.148.42 was used for vulnerability scanning and 23.22.63.114 was used for the defacement.

Searched them on virustotal and found this

<img width="1360" height="810" alt="image" src="https://github.com/user-attachments/assets/4b70ed51-479e-4614-b520-5215e7ecdb2f" />

23.22.63.114 IP was related to the attacker's domains and thus..

**Answer: 23.22.63.114**

### **There is no Q107**

### **Q108**

What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

#### **Approach**

To identify this, it's essential to know that the http POST method is most commonly used for web login attempts as web forms encapsulate credentials within the http request body rather than the URL and users have to submit credentials via web forms.

Login forms use POST specifically because credentials are not wanted appearing in the URL, browser history, or server logs to hide the credentials from others as a confidential policy

To confirm this, the http methods were listed.


```
index=botsv1 imreallynotbatman dest="192.168.250.70" sourcetype=stream:http 
|stats count by http_method
|sort -count
```

<img width="1877" height="682" alt="image" src="https://github.com/user-attachments/assets/0d8709d2-c42e-4f87-8379-fd3a851e4bd9" />


The http POST requests were the most commonly occurred as expected.


'form_data' field has every username and password input by the users in http post request and thus, attacker's attempted credentials could be found in that. '_time' field was put to know the periodic flow of the brute force attack.


Content-Type from the client being the attacker, must be 'application/x-www-form-urlencoded' as this is the standard encoding for login forms.


**Note: Content-Type tells the server how the form data is encoded.**


```
index=botsv1 imreallynotbatman dest="192.168.250.70" sourcetype=stream:http http_method=POST form_data=*username*passwd*  cs_content_type="application/x-www-form-urlencoded" | table  _time, url, form_data
```

<img width="1872" height="847" alt="image" src="https://github.com/user-attachments/assets/eaf4f0bd-f799-414e-bd25-71810313cdb6" />



Finding the src_ip that did the brute force attack


```
index=botsv1 imreallynotbatman dest="192.168.250.70" sourcetype=stream:http http_method=POST form_data=*username*passwd*  cs_content_type="application/x-www-form-urlencoded" | stats  count by  src_ip
```

<img width="1876" height="400" alt="image" src="https://github.com/user-attachments/assets/9433c644-c8ee-45d3-8160-9e0975cc855d" />


As '23.22.63.114' had the highest counts for the http POST requests, it had been identified as the one that did the brute forcing.

**Answer: 23.22.63.114**


### **Q109**

What is the name of the executable uploaded by Po1s0n1vy? 


#### **Approach**

As the executable was uploaded, it was confirmed that the information must be found in the http POST request and responses.

As the file was uploaded, the content-type must be 'multipart/form-data' and the content-diposition must have the files that the attacker uploaded and the http response code must be '200' to know the successful action.


**Note: content-type declares the file type and content-disposition does how to handle the file**


As content-disposition has the 'filename' field for every file that attacker put it in their headers.

The intended data could be search using the keyword 'content-disposition' OR 'filename'.



```
index=botsv1 sourcetype=stream:http dest="192.168.250.70" http_method=POST  "content_disposition"
| stats count by part_filename{}
```


<img width="1873" height="442" alt="image" src="https://github.com/user-attachments/assets/86577bc0-efc4-4ee6-835b-76feba0dfe1f" />


Seeing in the raw log to know the detailed information..

<img width="1918" height="168" alt="image" src="https://github.com/user-attachments/assets/359c3abd-e67e-44cc-87e0-306c2a3d2d23" />


<img width="1247" height="701" alt="image" src="https://github.com/user-attachments/assets/7dc9fed4-97a7-4d4e-9e38-97b05ca10e03" />


The executable file '3791.exe' and a web shell disgused as 'agent.php' were successfully uploaded with the status response code '200' from the Microsoft web server and the attacker's IP that uploaded the files was shown as '40.80.148.42' as well.

**Answer: 3791.exe**



