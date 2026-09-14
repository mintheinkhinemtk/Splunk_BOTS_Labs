# **Splunk BOTSV2 Walkthrough**

**Platform**: Splunk BOTS Version 2 (2017)

I took the questions from https://samsclass.info/50/proj/botsv2.htm

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
