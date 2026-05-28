# Splunk BOTSV1 CTF Walkthrough

**Platform:** Splunk BOTS Version 1 (2015)  

You can sign up for an account and take the challenge at https://bots.splunk.com

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

As an external IP, 40.80.148.42, had the highest volume in the search results, it might be the attacker's IP that did the vulnerability scan. The information could be analyzed again in stream:http sourcetype as it was the main log source.


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

After doing deep analysis and reading logs, the name was found in 'src_headers'.

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http" src_ip="40.80.148.42"
| stats values(src_ip) values(src_headers)
```

<img width="1882" height="731" alt="image" src="https://github.com/user-attachments/assets/9f36540e-cb6d-4c82-8d58-21fbe302eee5" />



Answer: Acunetix

### **Q103**

What content management system is imreallynotbatman.com likely using?

We need to aim for the destination web server, imreallynotbatman.com and its http status response, '200'.

After doing log analysis, we found that the web server's IP is '192.168.250.70'.

```
index=botsv1 src =40.80.148.42 imreallynotbatman (dest="192.168.250.70") sourcetype=stream:http status=200
|stats count by uri
|eventstats sum(count) as total by uri
|eval percentage = round(count*100/total,2)
|fields - total
|sort -count
```

<img width="1881" height="835" alt="image" src="https://github.com/user-attachments/assets/561b3ffa-d70e-4080-a8f1-92f3570de6cb" />

We can see 'joomla' across multiple uri paths.


<img width="1152" height="467" alt="image" src="https://github.com/user-attachments/assets/2081817b-0570-40a8-a734-c6b06e02930a" />


Answer: joomla


### **Q104**

What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

We would need to first know that the web server connection must be only outbound without any initiated inbound connections to think about how the file that defaced the website got into the server.

Attacker would probably have got the reverse-shell and therefore, we need to find the external IP that was initiated by our web server. 

We need to search the information in suricata and fortigate utm logs as they will have the connection and file information.


Don't forget that we have two external IPs in the above questions in stream:http.


```
index=botsv1 sourcetype=suricata  src_ip="192.168.250.70" status="200"
|stats count by status, src_ip, dest_ip
```


<img width="1875" height="553" alt="image" src="https://github.com/user-attachments/assets/ad01e015-7a0c-48d2-a340-489a09931eaf" />


Check 108.161.187.134.

```
index=botsv1 sourcetype=suricata  src_ip="192.168.250.70" dest_ip="108.161.187.134" status="200"
|stats count by status, http.hostname, src_ip, dest_ip
```

<img width="1872" height="398" alt="image" src="https://github.com/user-attachments/assets/88ed0299-58fa-41c8-acbb-626467347511" />



We will exclude others as 192.168.2.50 is an internal IP and 106.161.187.134 is the one of joomla update site.

After doing log analysis, we found an interesting file in the log related to '23.22.63.114' IP.


```
index=botsv1 sourcetype=suricata  src_ip="192.168.250.70" dest_ip="23.22.63.114" status="200"
|stats count by http.hostname, http.url, src_ip, dest_ip
```


<img width="1880" height="508" alt="image" src="https://github.com/user-attachments/assets/45cac322-dfad-44e3-b5a5-b85de6026b72" />


Let's dig about this in stream:http and fortigate_utm source to confirm the information.


```
index=botsv1 sourcetype=stream:http  src="192.168.250.70" dest_ip="23.22.63.114"
|stats count by src_headers
```


<img width="1877" height="468" alt="image" src="https://github.com/user-attachments/assets/db497c66-79bd-4342-ba2a-3f82de163e31" />



'Fortigate' UTM has the 'Malicious Websites' Category if they regard an external site as malicious

```
index=botsv1 sourcetype=fgt_utm 192.168.250.70 NOT dest=192.168.250.70 category="Malicious Websites"
|stats count by dest
```

<img width="1871" height="398" alt="image" src="https://github.com/user-attachments/assets/5c46a8f1-1f2f-40b4-b574-15daacdcb33c" />


```
index=botsv1 sourcetype=fgt_utm  src="192.168.250.70" dest="23.22.63.114"
| stats count by _time, src, src_port, dest, dest_port, url, action
```

<img width="1863" height="667" alt="image" src="https://github.com/user-attachments/assets/64102718-a35d-4596-a9d9-6155f24be17d" />


Answer: poisonivy-is-coming-for-you-batman.jpeg


### **Q105**

This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

We found this from the previous question as well as we can still find the FQDN information in 'stream:dns'.

```
index=botsv1 sourcetype=stream:dns answer="23.22.63.114"
| stats values(name{})
```

<img width="1880" height="397" alt="image" src="https://github.com/user-attachments/assets/b3ec8f57-bbbd-4f36-a7a8-4746f7f4e960" />


Answer: prankglassinebracket.jumpingcrab.com


### **Q106**

What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?




