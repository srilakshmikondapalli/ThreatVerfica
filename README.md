## Threat Intel Tool
This threat intel tool provides the reputation information about IOC(indicators of comprimise) from various threat intelligence website using APIs. 
Here threat intelligence platforms include:
1.Apivoid 
2.Alienvault
3.Virustotal 
4.Ibmxforce
### Apivoid:
  Apivoid is a threat intelligence platform which provides rest APIs useful for cyber threat analysis, threat detection and
  threat prevention, reducing and automating the manual work of security analysts. With this APIs you can identify malicious IP addresses, get reputation of a website.
### Alienvault:
  Alienvault is a threat intelligence platform which is used to identify malicious ip addresses and get reputation of a website.
### Virustotal:
  Virustotal is a threat intelligence platform which identifies the malicious ip addresses, malware and url online scanning service
### Ibmxforce:
  Ibmxforce is a threat intelligence platform which identifies the reputation of ip, domain and url
### IOC:
  1. ip_reputation:
       Here ip provided by the user will be validated for submitting the information fetched by the user. validation process includes:
       - checks whether provided contains four octects or not
       - checks whether each octet of ip in the range of 256 or not
       - if ip is valid,checks whether it is private ip or public ip
       - private ips are invalid for ip repuation check
       - once the validation is done, information reagrding ip such as geographical location of an ip, urllists of an ip,malware analysis of an ip will be provided by the 
         appropriate threat intelligence site
  
  2. domain:
     Here required information of specified domain fetched by the user form the user console which is submitted by appropriate threat intelligence sites.
     Here information include geographical location of domain, url lists of domain, malware of domain,passive dns of domain
  
  3. url:
     Here required information of specified url fetched by the user form the user console which is submitted by appropriate threat intelligence sites.
     Here information include geographical location of url, url lists of url, malware of url,passive dns of url.
 ## Requirements:
    You have to install some packages before using this tool
    1. requests
    2. netaddr
    3. tabulate
   #### requests
      requests module allows you to send http requests using python. Http request returns a response object with all response data.
   #### netaddr
      netaddr is a third party package which is used for ip validation.
   #### json
      json is a built-in package abbreviated as java script object notation  which is used for storing and exchanging of data.
   #### tabulate
      tabulate package gives the fetched data in table format. 
   
    
    
     
 



