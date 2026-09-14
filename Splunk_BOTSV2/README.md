# **Splunk BOTSV2 Walkthrough**

**Platform**: Splunk BOTS Version 2 (2017)

I took the questions from `https://samsclass.info/50/proj/botsv2.htm`

**This walkthrough documents the analytical reasoning for each stage**

## **Series 1xx**


### **Q100**

Amber Turing was hoping for Frothly (her beer company) to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited? Answer example: google.com 


#### **Approach**

The IP Addresses for Amber Turing and the visited website were needed to be known. 

The first point must be Amber Turing as she was the visitor. 

```
index=botsv2 "amber" sourcetype="pan:traffic" (80 OR 443)
```

<img width="1905" height="611" alt="image" src="https://github.com/user-attachments/assets/d985c4ab-b358-432a-a02d-f02474c73602" />


<img width="748" height="665" alt="image" src="https://github.com/user-attachments/assets/79372b9e-845a-443a-ac6b-510ed39d65bd" />


Amber's private and public IPs were 10.0.2.101 and 71.39.18.125 found in Palo Alto Traffic Logs.

The private IP was used in web logs to find the destination website visited.

I used the "beer" keyword in the search to find the beer site thinking there could be websites named beer.


```
index=botsv2 sourcetype="stream:http" src_ip="10.0.2.101" dest_port=80
| regex site="beer"
| stats count by site
```

<img width="1873" height="391" alt="image" src="https://github.com/user-attachments/assets/02d7202b-3eb6-4021-a93d-44bdc43c3f1d" />


**Answer: `www.berkbeer.com`**

### **Q101**

Amber found the executive contact information and sent him an email. What is the CEO's name? Provide the first and last name.


#### **Approach**

I could use the 'berkbeer' domain name and found the work email for Amber Turing in the smtp logs. 

I made the time sorting to start from the lowest value in order to see the first email sent to the CEO.

```
index=botsv2 sourcetype="stream:smtp" "aturing@froth.ly" "berkbeer"
| sort +_time
```

<img width="1891" height="383" alt="image" src="https://github.com/user-attachments/assets/d3c0897d-b8c0-4e43-9307-1964efa334f9" />


<img width="931" height="432" alt="image" src="https://github.com/user-attachments/assets/7b967c7f-0a90-49c6-87ee-90401074a084" />


Found the CEO's email as  mberk@berkbeer.com and the name was found in the reply from that email.

**Answer: Martin Berk**


### **Q102**

After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?


#### **Approach**


In the email replied from mberk@berkbeer.com, Bernhard was mentioned. 

I found his email as hbernhard@berkbeer.com in the following logs from the previous query and the content sent from Amber was encoded in base64. 

It could be that Amber encoded her content in base64 for the malicious reasons.


<img width="613" height="382" alt="image" src="https://github.com/user-attachments/assets/de3793ff-0c5e-44d2-8f79-afc2346b7934" />

<img width="928" height="632" alt="image" src="https://github.com/user-attachments/assets/0bf0380a-c458-4825-ade7-211630ba6abc" />


**Answer: hbernhard@berkbeer.com**


### **Q103**

What is the name of the file attachment that Amber sent to a contact at the competitor? 


#### **Approach**


<img width="532" height="112" alt="image" src="https://github.com/user-attachments/assets/c1992e52-7ef0-4cd2-877f-184416a29e5d" />


**Answer: Saccharomyces_cerevisiae_patent.docx**


### **Q104**

What is Amber's personal email address?


#### **Approach**


That was a little tricky. I tried to find that in the smtp logs and found nothing but as mentioned in the Q102, the content were encoded in base64 in the email sent from Amber to hbernhard@berkbeer.com. 

After decoding this in cyberchef, the private message was found and there was Amber's personal email.


<img width="937" height="697" alt="image" src="https://github.com/user-attachments/assets/4545fa43-a9dd-4b2d-9642-5c0d89de5267" />


**Answer: ambersthebest@yeastiebeastie.com**


### **Q105**

What version of TOR did Amber install to obfuscate her web browsing? 

#### **Approach**


I would need to find the installed TOR browser in Amber's machine. The information must be in Windows Sysmon logs and she had to certainly download the file before the installation. 


```
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "amber" "tor"
|stats count by Image EventCode
```

<img width="1883" height="546" alt="image" src="https://github.com/user-attachments/assets/0fe9fcf7-ff39-4d92-aca4-f7ef4b9722fd" />

The file was 'C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe'


**Answer: 7.0.4**


## **Series 2xx**


### **Q200**

What is the public IPv4 address of the server running www.brewertalk.com?


#### **Approach**

It's a web server and because of this, the information was easily found in http web logs.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80
| stats count by dest_ip
```

<img width="1882" height="407" alt="image" src="https://github.com/user-attachments/assets/ec6d8849-f791-4138-81cd-9090035cc734" />


There were both private and public IPs for that but I excluded '172.31.4.249' as it's a private one.

**Answer: 52.42.208.228**


### **Q201**

Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.


#### **Approach**


A web vulnerability scan would make lots of automated requests. I aimed for the IP that made the most requests and after seeing its logs to see the content, the attack attempts were found.


```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80
| stats count by src_ip
| sort -count
```


**Answer: 45.77.65.211**


### **Q202**

The IP address from question 201 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php


#### **Approach**


Firstly, I needed to investigate user agents to know which software the attacker used for finding out the attack flow as mapping the http methods used and the target uri to them.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"
|stats count by http_user_agent
```

<img width="1868" height="551" alt="image" src="https://github.com/user-attachments/assets/ddd1453b-be10-4425-85f7-dbb5bb9d45c0" />


One got 'w3af.org' in the user agent. w3af is an open-source web application security scanner and the attacker forgot to sanitize the domain in its crafted user agent. From this, I knew which tool they used. 

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; w3af.org)"  
| stats  count by uri_path
| sort -count
```

<img width="1881" height="652" alt="image" src="https://github.com/user-attachments/assets/b977cc6a-d994-4f3f-b7ed-8e86f0604bc2" />


```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; w3af.org)" uri_path="/member.php" | stats  count by http_method
```

<img width="1893" height="363" alt="image" src="https://github.com/user-attachments/assets/71393ba6-ece2-4804-a8cc-2f521460ba02" />


/member.php had the most requests with the http POST method.

I searched with another useragent to see more information.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36" http_method=POST
| stats count by  uri_path
```

<img width="1887" height="397" alt="image" src="https://github.com/user-attachments/assets/d5b4339d-cec8-474b-8b12-1352c2193d45" />


/member.php had only the http POST requests from them using this user agent.

After analyzing the logs, I found the sql injection attempts and the targeted uri_path was '/member.php' requested with the http POST method. 

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36" http_method=POST uri_path="/member.php"
| stats count by  form_data
```

<img width="1887" height="780" alt="image" src="https://github.com/user-attachments/assets/09a9ad43-fac9-4128-8bd8-81f4759cae57" />



**Answer: /member.php**


### **Q203**

What SQL function is being abused on the uri path from question 202?


#### **Approach**

The field 'form_data' had the sql injection attempts as they were under in http requests and it could be seen in Q202. I analyzed this again to see the function used.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80 src_ip="45.77.65.211" "uri_path"="/member.php" "sql"
| stats count by form_data
```


<img width="1892" height="790" alt="image" src="https://github.com/user-attachments/assets/022236fa-a218-4db7-b461-7357745a41cb" />


It was found that updatexml function was being abused. 

`Note: updatexml is abused by sqli tools to see the error-based data extraction. 
MySQL throws a verbose error if the XPath expression is invalid.
SQLI tools put the arbitrary values to xpath_expression argument to see the error which contains the results.
The function syntax is updatexml(xml_target, xpath_expr, new_value).`


**Answer: updatexml**


### **Q204**

What is Frank Ester's password salt value on www.brewertalk.com? 


#### **Approach**


`Note: salt values are added to the passwords before the whole hashes are computed in order to make the precomputed attacks like 'rainbow table' fail. `


In a database, there will be every computed hash and its salt value. The question asked that. 


From Q202, I used the two user agents. I explicitly used this one, "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36", as it was related to the SQLI attacks. 


I tried to search the http response for the attack to frank ester's account first for seeing his related information.


```
index=botsv2 dest_port=80 src_ip="45.77.65.211"  sourcetype="stream:http" site="www.brewertalk.com"  "frank" "uri_path"="/member.php"
```

<img width="1506" height="421" alt="image" src="https://github.com/user-attachments/assets/c4ccbb18-1d03-40fb-b5cd-bdbe28708a96" />


The name 'frank' could be seen in the MyBB error and the 'ORDER BY UID LIMIT 0,1' was the first row from the database table sorted by the 'UID' column.


The attacker would have seen the salt value in the http response when they attacked with sqli methods. Seeing the logs from the oldest to the newest using the 'reverse' function...


```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80 src_ip="45.77.65.211" "uri_path"="/member.php" "salt"  http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"
| reverse
| table dest_content
```


<img width="1877" height="690" alt="image" src="https://github.com/user-attachments/assets/fa93e6be-aef1-47f9-8d98-34e42e7d4c18" />


<img width="1766" height="372" alt="image" src="https://github.com/user-attachments/assets/535de9ca-d333-49b5-bc1d-bbdafcbcac56" />

<img width="1691" height="523" alt="image" src="https://github.com/user-attachments/assets/2aab5c5e-107a-4619-8ac5-f089e0a08882" />


Saw the length of the salt first and its value subsequently related to the frank's row, ''ORDER BY UID LIMIT 0,1'.

`Note: In these attacks, attackers check the length first to see the actual length before dumping the value as XPATHE error value from updatexml gets truncated at 32 characters.`


**Answer: gGsxysZL**

