# Splunk BOTSV1 CTF Walkthrough

This BOTS CTF walkthrough is based upon the Version 1 (2015) event. You can sign up for an account and take the challenge at https://bots.splunk.com

## Scenario 1 - Web Defacement

Q101

What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

To see which sourcetypes are contained in the index named botsv1,

```
|metadata type=sourcetypes index=botsv1
```

<img width="1887" height="848" alt="image" src="https://github.com/user-attachments/assets/ccd1020e-8707-4d13-924d-8fce6d88651d" />

The question has the information of the scanned domain, imreallynotbatman.com

```
index=botsv1 imreallynotbatman.com | stats count by sourcetype | eventstats sum(count) as perc | eval percentage=round(count*100/perc,2)| fields - perc | sort - count
```


<img width="1875" height="612" alt="image" src="https://github.com/user-attachments/assets/1ba19ff9-2082-4045-a329-3d806f2ea24a" />

We see that there are suricata and stream:http sourcetypes.

Firstly, we will see the events related to stream:http as all of the http sources are contained in that stream:http.

Secondly, we will check the suricata sourcetype events to validate the IP from that stream:http scanning our server or not.

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http" 
| stats count by src, sourcetype
| sort -count
```

<img width="1870" height="523" alt="image" src="https://github.com/user-attachments/assets/36eec8f8-60ad-4a44-b408-b0724727f13f" />


```
index=botsv1 imreallynotbatman.com sourcetype=suricata 
| stats count by src
| sort -count
```

<img width="1863" height="577" alt="image" src="https://github.com/user-attachments/assets/f64fa243-e182-450a-baaf-5230becf74ba" />

source IP, 40.80.148.42, has the most count in the data.

```
index=botsv1 imreallynotbatman.com sourcetype=suricata src="40.80.148.42"
| stats values(src), values(signature)
```

<img width="1848" height="818" alt="image" src="https://github.com/user-attachments/assets/1beb8998-2a29-4d2e-86c5-be44a5f1901c" />


```
index=botsv1 imreallynotbatman.com sourcetype=suricata src="23.22.63.114"
| stats values(src), values(signature)
```

<img width="1873" height="440" alt="image" src="https://github.com/user-attachments/assets/6c7344ce-3407-4c61-a5bb-68682b654f6e" />

The log sources related to source IP, 40.80.148.42, returned signatures but 23.22.63.114 did not. From this, we can conclude that the attacker did a vulnerability scan with 40.80.148.42 IP. 

Answer: 40.80.148.42



