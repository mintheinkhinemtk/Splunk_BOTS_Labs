# **Splunk BOTSV1 CTF Walkthrough**

**Platform:** Splunk BOTS Version 1 (2015)  

You can sign up for an account and take the challenge at https://bots.splunk.com

**This walkthrough documents the analytical reasoning for each stage**

## **Scenario 1 - Web Defacement**

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


```
index=botsv1 sourcetype=stream:http "install_package" "agent.php"
| table _time, src_ip, dest_ip, uri, http_user_agent status
```


<img width="1881" height="515" alt="image" src="https://github.com/user-attachments/assets/d82b8807-4014-4435-85ea-0f228211154c" />



The executable file '3791.exe' and a web shell disgused as 'agent.php' were successfully uploaded with the status response code '200' from the Microsoft web server and the attacker's IP that uploaded the files was shown as '40.80.148.42' as well. 

**Note: Status code 303 for the file 'agent.php' meant the post request was successful and the server was now redirecting the attacker to the dash board page of joomla CMS to see the results."**


**Answer: 3791.exe**



### **Q110** 

What is the MD5 hash of the executable uploaded?

#### **Approach**

As it had been already known that the web server system was Microsoft, the information would be found in Microsoft Sysmon Logs.



**Note: Crucially, Sysmon is configured to calculate the hashes of the executable files at the exact moment the process starts. As  EventCode '1' represents process creation, the code gives you the full context of 'Who ran it, what the command line was, and what its unique signature (MD5/SHA256) are.**


As I wanted to find the MD5 hash of 3791.exe, the search was filtered using the 'CommandLine' field that had '3791.exe' run.

```
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1  CommandLine="3791.exe" | stats  count by host Image MD5
```


<img width="1872" height="405" alt="image" src="https://github.com/user-attachments/assets/4a4f7ac6-1493-46d6-ba6a-fec882d7ea42" />


**Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0**



### **Q111**

GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.


#### **Approach**

As the IPs that attacked the web server are '40.80.148.42' and '23.22.63.114', I tried to search them in VirusTotal first and found the file with a name containing 'screensaver' that showed it being used for spear phishing attacks.


<img width="1581" height="845" alt="image" src="https://github.com/user-attachments/assets/f4abcf27-93bb-4a6f-8b98-4e9de86d99aa" />


 **Filename: 'MirandaTateScreensaver.scr.exe'**

 I found search the SHA256 hash of the file in 'hybrid-anaysis.com'.

 <img width="1292" height="646" alt="image" src="https://github.com/user-attachments/assets/b4bc1637-600b-4f03-9eba-e28bcf52c273" />


**Answer: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8**



### **Q112**

What special hex code is associated with the customized malware discussed in question 111?


#### **Approach**

As the hex code is associated with the customized malware, I tried searching about that using its hash in the comment sections of that malware in VirusTotal


<img width="1792" height="498" alt="image" src="https://github.com/user-attachments/assets/fbea492e-31ad-45d0-898e-857dc33eccc9" />


The person who did the comment is Ryan Kovar, who is a person related to Splunk. Try searching for who he is.


After that, I tried to decode the hexcode to strings using cyberchef, The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis at 'https://gchq.github.io/CyberChef/'.

<img width="1905" height="565" alt="image" src="https://github.com/user-attachments/assets/93f81c20-d807-43aa-9b47-5f65fcec4c28" />


**Answer: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21**



**There is no Q113**

### **Q114**

What was the first brute force password used?

#### **Approach**

As found in 'Q108', I knew the source IP that did the brute force attack was '23.22.63.114'.


```
index=botsv1 imreallynotbatman dest="192.168.250.70" sourcetype=stream:http http_method=POST form_data=*username*passwd*  cs_content_type="application/x-www-form-urlencoded"  src_ip="23.22.63.114" 
|table  _time, form_data
|sort +_time
|head 10
```

Sorting the time to get the first attempt gave me the answer.

<img width="1862" height="850" alt="image" src="https://github.com/user-attachments/assets/c4399f66-4977-4c4b-a127-bbe97a06852f" />


**Answer: 12345678**



### **Q115**

One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?


#### **Approach**

I tried to filter the passwords that had only six characters using rex command in SPL that does regular expression.


```
index=botsv1 imreallynotbatman dest="192.168.250.70" sourcetype=stream:http http_method=POST
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=*
| eval passlength = len(userpassword)
| table userpassword, passlength
| where passlength = 6

```

<img width="1885" height="836" alt="image" src="https://github.com/user-attachments/assets/4ca22d6f-b824-4651-868f-7499b657375e" />


There was a coldplay.csv file in the dataset and I found it.

We can also get a list of coldplay songs from wikipedia and put them in a custom csv file created and filter to get the six-word songs using Excel Commands if you are doing the challenge with the dataset installed from the official Splunk dataset for BOTSV1 github link and setting up the lab manually.


```
|inputlookup coldplay.csv
```


<img width="1898" height="843" alt="image" src="https://github.com/user-attachments/assets/3e790248-e75e-434d-90d3-09906eb0ede9" />



inputlookup: read as an event generating command from a file in splunk
outputlookup: write to a file and used as a streaming command
lookup: read as a streaming command from a file to add fields or manipulate raw fields

Changing the names of songs to the lowercase.

```
|inputlookup coldplay.csv 
|eval song = lower(song)
|outputlookup coldplay.csv 
```


<img width="1853" height="827" alt="image" src="https://github.com/user-attachments/assets/ea1d2135-c384-450b-a38b-3ce5e530fb5e" />



Matching a 6 character song from the lookup csv file against the passwords extracted from the search results


```
index=botsv1 imreallynotbatman dest="192.168.250.70" sourcetype=stream:http http_method=POST 
| rex field=form_data "passwd=(?<userpassword>\w+)" 
| search userpassword=* 
| eval passlength = len(userpassword) 
| where passlength = 6 
| table userpassword, passlength 
| eval password = lower(userpassword) 
| lookup coldplay.csv song as password OUTPUTNEW song  
| search song=* | table song
```

<img width="1875" height="631" alt="image" src="https://github.com/user-attachments/assets/bb971fe5-e627-471d-9295-5884802f5d3d" />



**Answer: yellow**



### **Q116**

What was the correct password for admin access to the content management system running "imreallynotbatman.com"?


**Approach**

As the source ip that did the brute force attack was known as '23.22.63.114' from the 'Q108', it was needed to confirm the brute force attack being successful and which IP logging in with the succeeded password. As per question, the admin access was focused to find its password.


```
index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats count values(src) by userpassword
| sort -count
```


I used values() function to the 'src' fields to see the unique source IP values related to 'userpassword' field.

<img width="1878" height="852" alt="image" src="https://github.com/user-attachments/assets/03a6f25c-26e6-4249-9008-4ebe77add8a8" />


Both '40.80.148.42' and '23.22.63.114' were found as the same count number '1' for the password 'batman'. That meant that the brute force attack was successful with the password 'batman' with the IP '23.22.63.114' and the '40.80.148.42' IP was used for logging in to the joomla CMS. The 'uri' field was confirmed to know whether the successful authentication granted access the attacker to the administrator portal."


```
index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 src=40.80.148.42
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=*
| table _time uri userpassword status
```


<img width="1877" height="471" alt="image" src="https://github.com/user-attachments/assets/97b7db66-704d-472e-82fa-0b9d12b648c8" />


**Note: Status code 303 meant the server successfully processed the credential payload and it was redirecting the attacker to the admin dash board page of joomla CMS."**


As the 'uri' field showed the admin panel for joomla CMS and status code was 303 which meant success, it was confirmed that correct password for the admin account was...

**Answer:batman**



### **Q117**

What was the average password length used in the password brute forcing attempt?


#### **Approach**

The average password length is all of the total password lengths divided by the counts of password attempts. 
In Splunk, avg() function can be used with stats for aggregation.



```
index=botsv1 sourcetype=stream:http http_method=POST
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=*
| eval mylen=len(userpassword)
| stats avg(mylen) as avg_len_http
| eval avg_len_http=round(avg_len_http,0)
```


<img width="1871" height="536" alt="image" src="https://github.com/user-attachments/assets/ed28fc5f-cc2f-4fc3-a075-8ddc0e52aa46" />


**Answer: 6**


### **Q118**

How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? 


#### **Approach**

As I knew about that the IPs, '23.22.63.114' was used for brute force attack and '40.80.148.42' was used for the credential access, the time difference in seconds between these timestamps of these two events could be found. The password was 'batman'.

First, I list again the results


```
index=botsv1 sourcetype=stream:http 
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=batman
| table _time userpassword src
```


<img width="1867" height="522" alt="image" src="https://github.com/user-attachments/assets/f8ad9656-c633-43c4-98e2-b5913b0dae3b" />


As expected, the two events were found.


The transaction command in Splunk groups multiple separate log entries into one single mega event based on shared identifiers.

Calculation: it automatically creates a new field called duration.

duration = timestamp of last event - timestamp of first event

A transaction is defined by the common value or values specified. 

Thus, I aimed for the 'userpassword' field created from the rex command.


```
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=batman
| transaction userpassword
| eval duration = round(duration,2)
| table duration
```


<img width="1867" height="526" alt="image" src="https://github.com/user-attachments/assets/15278b00-b96b-40a9-b3b1-d97124faf041" />



**Answer: 92.17**



### **Q119**

How many unique passwords were attempted in the brute force attempt?


#### **Approach**

dc() function in Splunk outputs unique counts of the values. As there were 413 events related to brute force attacks having one for the successful login and the others were attempts, using dc() output the unique values reducing the duplication.

```
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=*
| stats dc(userpassword)
```


<img width="1872" height="471" alt="image" src="https://github.com/user-attachments/assets/c2a64c13-7b95-44ee-9d3c-30db183a05f8" />


**Answer: 412**


 ## **Summary**


#### **Mapping with the MITRE framework**


**1. RECONNAISSANCE**


The attacker firstly did the vulnerability scanning to the web server, imreallynotbatman.com, with '40.80.148.42' gathering the information of CMS as joomla using Acuentix Web Vulnerability Scanner.



**2. RESOURCE DEVELOPMENT**


The attacker tied '23.22.63.114' IP to their domains that are pre-staged to attack Wayne Enterprises and  used dynamic dns services like jumpingcrab.com resolving to their IP, '23.22.63.114'. They also prepared their IP, '40.80.148.42', for attacking Wayne Enterprises.



**3. INITIAL ACCESS**


The attacker attempted brute force attack to the web server using '23.22.63.114' IP and from this, they got the admin password for the joomla CMS. 


They got the access to the CMS with the password using '40.80.148.42' IP.



**4. EXECUTION, PERSISTENCE and 'COMMAND AND CONTROL'**


They uploaded the web shell, 'agent.php', successfully and got the web shell access as a persistence mechanism. From this, attacker executed commands using web shell and dropped the malware, 3791.exe, using that shell access and got the reverse shell to their C2 with the help of malware to gain persistence and C2 tactics.



**5. IMPACT** 

The Wayne Enterprise had the confidential, integrity and reputational impact from this incident. 
The attacker got access to the web server, forced the system to write, save, and execute arbitrary code via the persistence shells and do the web defacement impacting confidential, integrity and reputational ones.



## **Scenario 2 - Ransomware**

### **Q200**

What was the most likely IPv4 address of we8105desk on 24AUG2016?


#### **Approach**

DNS logs are related to find them as well in the local environment to resolve workstation names altogether with the organization domain to IP Addresses. 

As explained in the scenario 1, DNS transactions have two main parts, domain name asked for (name{} or query{}) and the IP Address answer for that domain name.

Thus, I tried to investigate in DNS Logs.


```
index=botsv1 "we8105desk" sourcetype="stream:dns"  "name{}"="we8105desk.waynecorpinc.local" 
| stats  count by answer 
```


<img width="1880" height="421" alt="image" src="https://github.com/user-attachments/assets/1f392846-a866-469d-8b03-61603cd9171b" />


**Answer: 192.168.250.100**


### **Q201**

Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.


#### **Approach**

'Suricata' and 'Cerber' were mentioned in the question and thus, I investigated for signature names having 'Cerber' related to the IP of we8105desk in suricata logs.


```
index=botsv1 sourcetype=suricata 192.168.250.100 signature=*Cerber*
| stats count by signature alert.signature_id
```


<img width="1883" height="525" alt="image" src="https://github.com/user-attachments/assets/0a01b9c7-f897-4964-ae81-2a5bcaea8490" />


Signature ID '2816763' with the name having 'Cerber' having the lowest count as '1' could be seen.


**Answer: 2816763**


### **Q202**

What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?


#### **Approach**

DNS Logs were investigated in relation to the victim source IP, '192.168.250.100' as the question asked 'FQDN'. 

Victim's IP was the source since the ransomware attempted to direct him to its domain. The DNS transaction must be from the victim querying for the ransomware's domain. 

I filtered the query type to 'A', Forward DNS, as it maps a domain name to the related IPv4 Address.

Forward DNS — domain → IP (A/AAAA records). 

I wanted to see the forward transaction as the victim exactly did that.

The timeline was really important to know the incident happening time to filter out the unnecessary events to get the result.

Because of this, I used the query in 'Q201' altogether with the timeline to briefly know the incident time. Before this, I tried to get the brief timeline of the 'Cerber' ransomware alerts in the suricata IDS.


```
index=botsv1 sourcetype=suricata 192.168.250.100 signature=*Cerber*
| stats count by _time signature alert.signature_id
```

<img width="1883" height="602" alt="image" src="https://github.com/user-attachments/assets/360830e4-beb7-4c73-8116-a1ce438a9f64" />

The timeline were from `16:49:24 to 17:15:12` on 24th Aug, 2016.


I tried to put the timeline as "since 24th Aug, 2016 at `16:49:00`" into the dns query searching. 


```
index=botsv1 sourcetype="stream:dns" src=192.168.250.100  record_type=A 
| stats  count by _time query{} 
```

<img width="1872" height="846" alt="image" src="https://github.com/user-attachments/assets/7830ba63-c438-4432-9468-d75101166353" />


The queries for the legitimate domains and protocols, isatap, wpad, microsoft.com, waynecorpinc.local, bing.com, windows.com and msftncsi.com were filtered out again. 


**Note: ISATAP stands for Intra-Site Automatic Tunnel Addressing Protocol. It is a network transition technology used to transmit IPv6 packets over an existing IPv4 network infrastructure.**


**Note: WPAD stands for Web Proxy Auto-Discovery Protocol. It is a network protocol used by web browsers and operating systems to automatically detect and apply proxy server settings without manual configuration.**


**Note: msftncsi refers to the domains www.msftncsi.com and dns.msftncsi.com, which are operated by Microsoft for the Network Connectivity Status Indicator (NCSI) feature in Windows. It is the system that Windows uses to verify whether you have an active internet connection or not.**

```
index=botsv1 sourcetype=stream:DNS src=192.168.250.100 record_type=A NOT(query{}=*.microsoft.com OR query{}=*.waynecorpinc.local OR query{}=*.bing.com OR query{}=isatap OR query{}=wpad OR query{}=*.windows.com OR query{}=*.msftncsi.com) 
| table _time query{} src dest
| sort +_time
```


<img width="1877" height="577" alt="image" src="https://github.com/user-attachments/assets/5ea3bca8-b3f0-4f9f-9641-20f43331ed2a" />


Found the domain being 'cerberhhyed5frqa.xmfir0.win'


**Answer: 	cerberhhyed5frqa.xmfir0.win**


### **Q203**

What was the first suspicious domain visited by we8105desk on 24AUG2016?


#### **Approach**

Timeline was included the question and thus I investigated in the dns log source as usual according to the timeline provided as since 24-AUG-2016 `00:00:00` 


```
index=botsv1 sourcetype=stream:DNS src=192.168.250.100 record_type=A NOT (query{}=*.microsoft.com OR query{}=*.waynecorpinc.local OR query{}=*.bing.com OR query{}=isatap OR query{}=wpad OR query{}=*.windows.com OR query{}=*.msftncsi.com) 
| table _time query{} src dest
| sort +_time
```


<img width="1872" height="667" alt="image" src="https://github.com/user-attachments/assets/245676c3-21e4-4af5-a3e6-19470547984c" />


'solidaritedeproximite.org' was founded at `16:48:12` on 2016-08-24.
When it was searched in google...

<img width="1137" height="398" alt="image" src="https://github.com/user-attachments/assets/871627f4-7d9d-4417-9af5-8bcf884f357e" />

Searching in 'whoisrecord'

<img width="1135" height="642" alt="image" src="https://github.com/user-attachments/assets/dc83a58c-4d33-430a-8679-cff1de02e726" />

Registrar is 'OVH, SAS OVH sas' and when it was searched in google, it showed as cloud computing in France.

<img width="677" height="381" alt="image" src="https://github.com/user-attachments/assets/1b35027d-311b-4ba4-8154-8df646d6f347" />

Because of this, I could conclude that the attacker used the cloud computing service to mask his identity and that it is located in France. Another question occurred in my mind as 'why would the victim browse normally to the France domain though even there were security policies in his coporation'.

Concluding this...

**Answer: solidaritedeproximite.org**



### **Q204**

During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?


#### **Approach **

Detailed information related to the executable and script execution in Windows can be found in sysmon logs. Sysmon gathers any command line event if it's configured well.

Process creation means that a process is created from its parent when any executable, file or script is run via the command line. The system will run command line processes automatically in the background when needed and Sysmon will log those events as well. For process creation, Sysmon logs these events under EventCode '1'.


Because of this, I decided to do the investigation in the Sysmon logs concerning Sysmon EventCode '1'.


As the description in the lab mentioned 'Miranda_Tate_unveiled.dotm' from the USB drive that the attacker inserted into the victim's machine, the VB script would have spawned from that template file run with WINWORD.exe.


```
index=botsv1 we8105desk sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "Miranda_Tate_unveiled.dotm" EventCode=1
| table host ParentCommandLine CommandLine ParentImage Image
```

<img width="1893" height="660" alt="image" src="https://github.com/user-attachments/assets/219981fd-0c92-40e7-843e-fee23710ab08" />

I could find the vbs script name as '%APPDATA%\%RANDOM%.vbs' in the 'CommandLine' field.



```
index=botsv1 we8105desk sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "Miranda_Tate_unveiled.dotm" EventCode=1
| where match(CommandLine, "RANDOM%\.vbs")
| eval length=len(CommandLine)
| table _time length CommandLine
```

<img width="1882" height="842" alt="image" src="https://github.com/user-attachments/assets/d9614b3b-8938-4a4f-b337-d12e733ae839" />



**Answer: 4490**


### **Q205**

What is the name of the USB key inserted by Bob Smith?


#### **Approach**

The information related to USB keys can be investigated in Windows Registry Logs.

There is a USBSTOR, a key in the Windows Registry, containing information about USB storage devices that are connected to a computer system and locating at 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'.

USBSTOR refers to the Windows Mass Storage Class Driver (usbstor.sys).


FriendlyName is a registry value under USBSTOR that gives you the human-readable name of the USB device that help me find the name of the USB key inserted.

It's stored at:
'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<device_type>\<serial>\FriendlyName'

I investigated using these kinds of specific information in Windows Registry Logs.



```
index=botsv1 sourcetype="winregistry" USBSTOR friendlyname host="we8105desk"
| fields *
| table host registry_path registry_key_name registry_type registry_value_name registry_value_data
```


<img width="1876" height="431" alt="image" src="https://github.com/user-attachments/assets/5da7d383-7942-42d4-8b8d-f111f48c4b27" />


Found the name as 'MIRANDA_PRI'



### **Q206**

Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?


#### **Approach**

This information could be investigated in stream:smb as the environment used Windows System. 


```
index=botsv1 we8105desk sourcetype="stream:smb" src_ip=192.168.250.100
|stats count by src_ip src_port dest_ip dest_port
```


<img width="1878" height="412" alt="image" src="https://github.com/user-attachments/assets/78e2a703-bd30-4912-8c7a-5f1009fbe5d9" />


As 192.168.250.100 was connecting to 192.168.250.20 and its smb port, 445, with its emphemeral source port, it could be the file server.

I investigated this information in the Windows Sysmon Logs in Splunk to confirm the answer. SMB uses port 445 and Sysmon Event ID for network connections is 3.


```
index=botsv1 we8105desk sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=3 SourceIp="192.168.250.100" DestinationPort=445
| table SourceIp SourcePort DestinationIp dest DestinationPort
```


<img width="1882" height="767" alt="image" src="https://github.com/user-attachments/assets/bdf28d06-22dd-440f-a71f-71b17a329965" />


I got the server name: we9041srv


The data related to fileshare could be found in Windows Registry Logs.


```
index=botsv1 sourcetype=WinRegistry host=we8105desk fileshare
| stats count by host registry_type registry_key_name registry_path
```

<img width="1875" height="472" alt="image" src="https://github.com/user-attachments/assets/33e3e8d6-3100-403e-beb0-cbbdfb20f361" />


<img width="1875" height="466" alt="image" src="https://github.com/user-attachments/assets/a0ca11c6-4fd2-4d3c-96c0-c203e0825f25" />


Registry path had the IP '192.168.250.20' in the registry path for the file shares from Bob Smith's machine and it showed that the server name was we9041srv. I could conclude the IP as...


Answer: 192.168.250.20 


### **Q207**

How many distinct PDFs did the ransomware encrypt on the remote file server?


#### **Approach**

As I had known that the remote file server hostname is 'we9041srv', I could filter the scope related to the server name in WinEvent Logs because the logs could provide the evidence according to the file share access from the ransomware of Bob Smith's Machine and whether the access was granted and its associated requested permissions (Read, Write, Delete and so on) with the event ID '5145'.


These kinds of logs are associated with Windows security.


Attackers could have deleted the original files after encrypting the PDF files and because of this, I tried to filter the search with 'DELETE' access and 'success' action for the PDF files on the server.


```
index=botsv1  we9041srv sourcetype="wineventlog:security" *.PDF Account_Name="bob.smith" host=we9041srv Accesses=DELETE
| stats count by Relative_Target_Name
```


<img width="1882" height="701" alt="image" src="https://github.com/user-attachments/assets/1130d58b-8355-4286-b483-c18b1cd8cd6f" />


**Answer: 257**



### **Q208**

The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?


#### **Approach**

The question asks about the ParentProcessId of the initial launch of 121214.tmp, but not its parent process. I firstly needed to know its initial launcher as the question ask the ParentProcessId of that initial process that launched 121214.tmp.



```
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" Image="*121214.tmp" host=we8105desk EventCode=1
| table _time ParentImage Image ParentProcessId ProcessId
```


<img width="1881" height="516" alt="image" src="https://github.com/user-attachments/assets/e64774be-aea5-445b-a21e-e5b0cff9f4f9" />


I knew the parent process id being 1476 and the process 'C:\Windows\SysWOW64\cmd.exe'. Using this information, I filtered the search to the scope of just that id and the process as the child.


```
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (ProcessId=1476 AND Image="C:\\Windows\\SysWOW64\\cmd.exe") | stats count by  CommandLine ProcessId ParentProcessId ParentCommandLine
```

<img width="1878" height="453" alt="image" src="https://github.com/user-attachments/assets/383c7608-54fd-4b88-8778-ca2ab8e61e30" />


As Wscript.exe was in the CommandLine and its ParentId was shown, the Parent process was Wscritp.exe and its Id being '3968'.

**Answer: 3968**


### **Q209**

The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?


#### **Approach**

The name of the ransomware execution file given by the attacker still had not found and since, I tried to look for its name.

Due to the file 'Miranda_Tate_unveiled.dotm' from the description, I investigated using that file name to look for the ransomware that could be downloaded from its C2 from running the vb script spawned from the dotm file.


```
index=botsv1 we8105desk sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "Miranda_Tate_unveiled.dotm" 
| table _time host Image EventID
```


<img width="1882" height="440" alt="image" src="https://github.com/user-attachments/assets/c0ad1c72-ce3c-4103-8c95-a97fd73a2930" />



I found out that the EventID and an executable file as 2 that records when a process explicitly modifies a file’s creation timestamp, and 'osk.exe' at the time: 2016-08-24 `17:04:32`.

Including CommandLine Events..

```
index=botsv1 we8105desk sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "Miranda_Tate_unveiled.dotm" 
| table _time host Image ParentProcessId ParentCommandLine ProcessId CommandLine
| sort -_time
```


<img width="1895" height="855" alt="image" src="https://github.com/user-attachments/assets/fa1157a7-9429-425d-948e-57f364704b6e" />


The time of 'osk.exe' was after 'Miranda_Tate_unveiled.dotm' being run.

Searched again more explicitly using this information.


```
index=botsv1 we8105desk sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "Miranda_Tate_unveiled.dotm" Image=*osk.exe
| table _time host Image TargetFilename
```

<img width="1877" height="362" alt="image" src="https://github.com/user-attachments/assets/31a9f4c4-dd4a-4058-9f5f-66531aa3af49" />

Owning to osk.exe is not a legitimate name and created after the malicious dotm file was run, I could conclude that osk.exe was the ransomware file and it encrypted the dotm file as well from the result of the EventID 2.


Finally, finding all the .txt files encrypted under Both Smith's Windows profile was done.


```
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  host=we8105desk *.txt   Image="C:\\Users\\bob.smith.WAYNECORPINC\\AppData\\Roaming\\{35ACA89F-933F-6A5D-2776-A3589FB99832}\\osk.exe" TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\Desktop\*.txt"| fields *  | stats values(TargetFilename)
```


<img width="1878" height="846" alt="image" src="https://github.com/user-attachments/assets/b8aa0938-81a2-4c9d-be91-0457ec536712" />



** Answer: 406**


### **Q210**

The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?



#### **Approach**

From seeing the question, it had been shown that the timeline was before the end of encryption phase and thus, I tried to investigate the answer related to "solidaritedeproximite.org" domain that was the first visited by the victim. 

The malware would have downloaded the ransomware cryptor code from that domain as there were only two suspicious domain found, "solidaritedeproximite.org", the first domain the malware visited and "cerberhhyed5frqa.xmfir0.win", the one it visited at the end of encryption phase.


```
index=botsv1 sourcetype=stream:DNS src=192.168.250.100 "solidaritedeproximite.org"
| table _time  src dest query{} name{} answer
| sort +_time
```


<img width="1870" height="488" alt="image" src="https://github.com/user-attachments/assets/3f9b2648-b47b-49ea-991d-d83622d85a70" />


I found its IP as '37.37.187.37.150'.


I tried searching in Sysmon log to find any other information related to the file that contains the Cerber ransomware cryptor code as it was downloaded from that domain.


```
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" host=we8105desk EventCode=3 SourceHostname="we8105desk.waynecorpinc.local"  37.187.37.150  dest_ip="37.187.37.150" | stats  values(SourceHostname) values(DestinationHostname) values(Image)
```


<img width="1871" height="362" alt="image" src="https://github.com/user-attachments/assets/f15be0e5-cf9e-424c-a8b8-8efa6b1c33f9" />


SourceHostname,we8105desk.waynecorpinc.local, connected to the	DestinationHostname, dedie73.olfsoft.net having the same IP '37.187.37.150' using 'C:\Windows\SysWOW64\wscript.exe'.

**Note: Domain Generation Algorithm was clearly used**

Finally, the data was investigated in 'stream:http' as it would show the downloaded file.


```
index=botsv1 src=192.168.250.100  sourcetype="stream:http" dest="37.187.37.150"   | stats  count by http_method url status
```

<img width="1867" height="332" alt="image" src="https://github.com/user-attachments/assets/3c79426e-3189-4253-ade0-cbcf2e36deb6" />

Finally found the only one file downloaded.

Though status was '404', the file 'mhtr.jpg'was downloaded successfully. Attacker used the status code of '404' to hide the successful behaviour of the download. 


**Answer: mhtr.jpg**



### **Q211**

Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?


#### **Approach**

As the ransomware's encryptor file that had the Cerber ransomware cryptor code was in .jpg extension, the attacker buried the code in the jpg file. This technique is known as 'steganography'.


**Answer: steganography**
