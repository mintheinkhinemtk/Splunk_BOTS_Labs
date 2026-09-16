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


### **Q205**

What is user btun's password on brewertalk.com?


#### **Approach**

`Note: salt values are added to the passwords before the whole hashes are computed in order to make the precomputed attacks like 'rainbow table' fail. `

In a database, there will be every computed hash and the salt value.

MyBB's format is md5(md5($salt)+md5($pass)). I would need btun's salt and the whole computed hash stored in MyBB.

let's find btun's row and salt first.

```
index=botsv2 dest_port=80 src_ip="45.77.65.211"  sourcetype="stream:http" site="www.brewertalk.com"  "btun" "uri_path"="/member.php"
```

<img width="1902" height="673" alt="image" src="https://github.com/user-attachments/assets/55611f15-babe-4e90-bc92-99b91f686872" />


<img width="1485" height="245" alt="image" src="https://github.com/user-attachments/assets/cb355700-c9e9-4ec6-8600-f70f2c8ab340" />


Got the row of btun. Salt value was still needed.

```
index=botsv2 dest_port=80 src_ip="45.77.65.211" "uri_path"="/member.php" "salt" sourcetype="stream:http" site="www.brewertalk.com"   http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36" "ORDER BY UID LIMIT 2,1"
| reverse
```

<img width="1892" height="785" alt="image" src="https://github.com/user-attachments/assets/6f8de4cc-be94-4bad-9937-b7c04bd3f263" />


<img width="1522" height="257" alt="image" src="https://github.com/user-attachments/assets/98d46a2a-185d-41ae-9f57-08d3af67f00a" />

I could now find the whole computed hash of the password and its salt value using the row and the salt.

Using reverse to get the events from the oldest to the newest...

```
index=botsv2 dest_port=80 src_ip="45.77.65.211" sourcetype="stream:http" site="www.brewertalk.com" "/member.php"  "SELECT password FROM mybb_users ORDER BY UID LIMIT 2,1"
| reverse
```

<img width="1910" height="646" alt="image" src="https://github.com/user-attachments/assets/b2314fb7-2635-4617-a279-ce66c0ec94b4" />


<img width="1546" height="323" alt="image" src="https://github.com/user-attachments/assets/5cd6f912-14a3-4a3b-949b-7342f2068960" />

Attacker got the character count as 32.

<img width="1458" height="282" alt="image" src="https://github.com/user-attachments/assets/0b3df68d-200e-4efd-920d-2cb2c35eedfe" />

The length of password was 32 but the subtracted string was only 31 character long. 


<img width="1433" height="273" alt="image" src="https://github.com/user-attachments/assets/423a6cb3-d6c0-419b-8886-5b1cae5e50ca" />


The final character was extracted.

So, the total password hash value was 'f91904c1dd2723d5911eeba409cc0d14' and it's a md5 hash as it is exactly 32 characters long.

Running the hashcat command in my Linux VM to crack the md5hash of MyBB `hashcat -m 2811 -a 0 'f91904c1dd2723d5911eeba409cc0d14':'tlX7cQPE' ~/rockyou/rockyou.txt` ...

<img width="1850" height="752" alt="image" src="https://github.com/user-attachments/assets/d3d4a232-67f3-4f9b-8a76-5f426ef2fa3f" />


<img width="1051" height="802" alt="image" src="https://github.com/user-attachments/assets/862c5c89-0983-458d-840e-ebe8fdcf9029" />


Got the password for btun as '123456'.


**Answer: 123456**


### **Q206**

What are the characters displayed by the XSS probe? Answer guidance: Submit answer in the native language or character set.


#### **Approach**

Basic xss probes mostly contain <script>alert("x")</script> tags and thus, I tried to find with that keyword first.


```
index=botsv2 sourcetype="stream:http"   "<script>alert(*"
```

<img width="1887" height="658" alt="image" src="https://github.com/user-attachments/assets/9ba6d2d6-b0e3-4d12-b29f-0e1ec0e79c85" />


<img width="1472" height="490" alt="image" src="https://github.com/user-attachments/assets/bc4e9c44-6f49-42d0-ac35-a59f0b07c454" />


**Answer: 대동**


### **Q207**

What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of a XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.


#### **Approach**

Firstly, I needed to aim for the XSS payload that got the cookie.

```
index=botsv2  sourcetype="stream:http" kevin "<script>"
```

<img width="1905" height="678" alt="image" src="https://github.com/user-attachments/assets/fc578646-e5c1-4922-a2a3-3ea11170e654" />


<img width="1551" height="422" alt="image" src="https://github.com/user-attachments/assets/9fd20022-12df-4483-b4f0-1a5b8ecab69a" />

Malicious xss payload script put by the attacker.

```var postdata= "my_post_key="+my_post_key+"&username=kIagerfield&password=beer_lulz&confirm_password=beer_lulz&email=kIagerfield@froth.ly&usergroup=4&additionalgroups[]=4&displaygroup=4"```

The adversary injected the payload at the 'utid' parameter as the stored xss mechanism stealing the token, 'my_post_key' of the admin, Kevin, and created another user account 'kIagerfield' and the password 'beer_lulz' with the email 'kIagerfield@froth.ly' using that key and the admin privileges (usergroup=4) in MyBB under Kevin's session.



<img width="1592" height="82" alt="image" src="https://github.com/user-attachments/assets/ad72d672-7090-44c5-a941-7c72b49c4ba3" />

<img width="1691" height="46" alt="image" src="https://github.com/user-attachments/assets/b0344ce6-33e4-467d-b82f-34f36243f7a0" />

<img width="1526" height="93" alt="image" src="https://github.com/user-attachments/assets/b3803e09-ea4c-4b24-82d2-2af8aefe992f" />


```
<div id="logo"><h1><span class="invisible">MyBB Admin CP</span></h1></div>
<div id="welcome"><span class="logged_in_as">Logged in as <a href="index.php?module=user-users&amp;action=edit&amp;uid=17" class="username">kevin</a></span> | <a href="http://www.brewertalk.com" target="_blank" class="forum">View Forum</a> | <a href="index.php?action=logout&amp;my_post_key=1bc3eab741900ab25c98eee86bf20feb" class="logout">Log Out</a></div>
<div id="menu">
```

HTML Code from these three screenshots showing kevin was an admin for MyBB and his post key as '1bc3eab741900ab25c98eee86bf20feb'.

```
index=botsv2 sourcetype="stream:http" "kevin"    src_ip="10.0.2.109" dest_ip="52.42.208.228"
```


<img width="1860" height="832" alt="image" src="https://github.com/user-attachments/assets/96246c88-f5d9-4624-817b-6108659d9ff6" />


As the question mentioned the cookie had only digits and thus, lastvisit would make more sense.


The cookie was sent to the attacker's server. Attacker got the admin session cookie and Kevin's username and password.


**Answer: 1502408189**


### **Q208**

The brewertalk.com web site employed Cross Site Request Forgery (CSRF) techniques. What was the value of the anti-CSRF token that was stolen from Kevin Lagerfield's computer and used to help create an unauthorized admin user on brewertalk.com?


#### **Approach**


`Note: Anti-CSRF tokens are usually hidden form elements set. If a form is submitted without the anti-CSRF token, the backend code of the website rejects the transaction to prevent malicious sources from attackers and they are temporary, random values linked to a user's current session `


Attacker's script had stolen my_post_key in its script and uploaded to brewertalk.com to create a new user with the admin privilege under Kevin's session.

That was the anti-CSRF token of Kevin. 


Actually, attacker injected their XSS payload script to use the value in my_post_key that was the temporary anti-CSRF token as a user session for Kevin to create another admin level account controlled by them.


As the token would be hidden, I searched with 'hidden' in the raw log to confirm my theory. 


```
index=botsv2  sourcetype="stream:http" kevin "<script>"
```


<img width="1918" height="588" alt="image" src="https://github.com/user-attachments/assets/74ccb1d8-e887-417f-8996-6a974e14499a" />

I had got that anti-CSRF token from Q207.

**Answer: 1bc3eab741900ab25c98eee86bf20feb**


### **Q209**

What brewertalk.com username was maliciously created by a spearphishing attack?


#### **Approach**


In Q207, it was seen that the username 'kIagerfield' was created.


**Answer: kIagerfield**


## **Series 3xx**


### **Q300**

According to Frothly's records, what is the likely MAC address of Mallory's corporate MacBook? Answer guidance: Her corporate MacBook has the hostname MACLORY-AIR13. 

I skipped this as there was no Splunk Enterprise Security for me in the lab I did to use 'Asset Centre'.


### **Q301**

What episode of Game of Thrones is Mallory excited to watch? Answer guidance: Submit the HBO title of the episode.


#### **Approach**


The abbreviation for Game of Thrones is 'GOT'. I got the hostname from Q300. Tried keyword guessing.

```
index=botsv2 host="MACLORY-AIR13" "GOT"
| stats count by columns.target_path
```

<img width="1905" height="655" alt="image" src="https://github.com/user-attachments/assets/42a2e372-ecdf-4d70-b033-d3f6fe8144be" />

Got the episode number and season as GoT.S07E02. 

After searching on google, its HBQ title is...

**Answer: Stormborn**


### **Q302**

BOTS2 302: What is Mallory Krauesen's phone number? Answer guidance: ddd-ddd-dddd where d=[0-9]. No country code.


This requires the asset center and the dashboard.


### **Q303**

Enterprise Security contains a threat list notable event for MACLORY-AIR13 and suspect IP address 5.39.93.112. What is the name of the threatlist (i.e. Threat Group) that is triggering the notable?


This requires the asset center and the dashboard.


### **Q304**


Considering the threatlist you found in the question above, and related data, what protocol often used for file transfer is actually responsible for the generated traffic? 


#### **Approach**


Using the IP Address from Q303...


```
index=botsv2 "5.39.93.112"
```

<img width="851" height="752" alt="image" src="https://github.com/user-attachments/assets/64e83e53-b716-44b5-81d7-c9b49e7190df" />



<img width="897" height="753" alt="image" src="https://github.com/user-attachments/assets/234d70ad-fae5-4352-8880-203b26b31a05" />


10.0.4.4 was connecting to 5.39.93.112. 71.39.18.125 was the src_NAT_public IP for the organization and the protocol used was bittorrent.


 "mkraeusen" and "10.0.4.4" were the src_user and the src_ip.


 **Answer: bittorrent**



### **Q305**

Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. At what hour, minute, and second does this actually happen? Answer guidance: Provide the time in PDT. Use the 24h format `HH:MM:SS`, using leading zeroes if needed. Do not use Splunk's _time (index time).


#### **Approach**

Using reverse command to get the oldest events first for seeing the first time the encryption happened at.

```
index=botsv2 "*.pptx" host="MACLORY-AIR13"
|reverse
```

<img width="1386" height="741" alt="image" src="https://github.com/user-attachments/assets/4775161d-08b0-4df2-99cd-f3128045302c" />


The second event had the ctime, 1503093022, that stands for the status change time and the target_path had the file with the extension .crypt meaning the file was changed to the encrypted state at that time.

 
 Frothly_marketing_campaign_Q317.pptx.crypt was the file.


This is an unix epoch format. Convert this at 'https://www.epochconverter.com/'. 

UTC = `21:50:22`. PDT = `14:50:22`


**Answer: `14:50:22`**


### **Q306**

How many seconds elapsed between the time the ransomware executable was written to disk on MACLORY-AIR13 and the first local file encryption? Answer guidance: Use the index times (_time) instead of other timestamps in the events.


#### **Approach**


Needed to know the two events, the first local file encryption and the ransomware executable written to disk on MACLORY-AIR13.


Using reverse to see the oldest events first.

```
index=botsv2 host="MACLORY-AIR13"  "*.crypt" 
| reverse
```


<img width="1502" height="742" alt="image" src="https://github.com/user-attachments/assets/8642e0fa-7639-413a-ab0e-08a3d2ac625a" />


The encryption Unix command, `find /Users/ -not -iname "README!.txt" -print -exec zip -0 -P TPq3NrjTLn2fSBZIxklL6ZRM5 {}.crypt {} \; -exec rm {} \; -exec touch -mt 201002130000 {}.crypt \;
`, was run at 08/18/17 `21:50:43` UTC.


<img width="1367" height="745" alt="image" src="https://github.com/user-attachments/assets/2163575f-32dc-47c4-8dd5-d5b2da673ddf" />


At the same time, the first file encrypted was  "/Users/mallorykraeusen/Desktop/.DS_Store.crypt".

I needed to find the time the ransomware executable was written at.


Going back to the timeframe within 5 mins before that event happened to find the app written as the encrypted command from it was run at the same time as the first file encrypted.


Mac executable file extension is '*.app'.

```
index=botsv2 host="MACLORY-AIR13" "*.app" action="added" 
| reverse
```


<img width="1897" height="776" alt="image" src="https://github.com/user-attachments/assets/02b35ca2-b565-4283-aa55-79ff2dc44e9c" />


<img width="1292" height="650" alt="image" src="https://github.com/user-attachments/assets/fde5ebd4-bb9b-4a88-a649-6d1e20722632" />


Found the malicious file with suspicious name under User Downloads folder. 

/Users/mallorykraeusen/Downloads/Office 2016 Patcher.app at Fri Aug 18 `21:48:31` 2017 UTC.

There is no patcher app from Office and the directory being Downloads meant the victim machine got that ransomware executable in that folder at that time.

Subtracting the time gave the 132 seconds (2:12 mins).

**Answer:  132**



