<div align='center'>

# **Passive Information Gathering**

</div>

## **Table of Contents**

- [**1. Website Recon**](#1-website-recon)
- [**2. Whois Enumeration**](#2-whois-enumeration)
- [**3. Google Hacking**](#3-google-hacking)
- [**4. Netcraft**](#4-netcraft)
- [**5. Recon-ng**](#5-recon-ng)
- [**6. Open-Source Code**](#6-open-source-code)
- [**7. Shodan**](#7-shodan)
- [**8. Security Headers Scanner**](#8-security-headers-scanner)
- [**9. SSL Server Test**](#9-ssl-server-test)
- [**10. Pastebin**](#10-pastebin)
- [**11. User Information Gathering**](#11-user-information-gathering)
    - [**11.1. Email Harvesting**](#111-email-harvesting)
- [**12. Social Media Tools**](#12-social-media-tools)
    - [**12.1. Social-Searcher**](#121-social-searcher)
    - [**12.2. Site-Specific Tools**](#122-site-specific-tools)
- [**13. Information Gathering Frameworks**](#13-information-gathering-frameworks)
    - [**13.1. OSINT Framework**](#131-osint-framework)
    - [**13.2. Maltego**](#132-maltego)

Passive Information Gathering (also known as Open-source Intelligence or OSINT) is the process of collecting openly available information about a target, generally without any direct interaction with that target

## **1. Website Recon**

Target: https://www.megacorpone.com

A quick review of their website reveals that they are a nanotech company.

![](./img/Chapter6/1.png)

The [about](https://www.megacorpone.com/about.html) page reveals email addresses and Twitter accounts of some of their employees

![](./img/Chapter6/4.png)

| Twitter | Email |
| --- | --- |
| [@Joe_Sheer](https://twitter.com/joe_sheer) | joe@megacorpone.com
| [@TomHudsonMCO](https://twitter.com/TomHudsonMCO) | thudson@megacorpone.com
| [@TanyaRiveraMCO](https://twitter.com/TanyaRiveraMCO) | trivera@megacorpone.com
| [@MattSmithMCO](https://twitter.com/MattSmithMCO) | msmith@megacorpone.com

We notice that the company’s email address format follows a pattern of "first initial + last name". However, their CEO’s email address simply uses his first name. This indicates that founders or long-time employees have a different email format than newer hires

Navigate further, we find some more information about the company.

![](./img/Chapter6/2.png)

- We see the year 2019 in the footer, which may indicate that the website was last updated in 2019.
- Information about Social Media

    - [Facebook](https://www.facebook.com/MegaCorp-One-393570024393695)
    - [Twitter](https://twitter.com/joe_sheer)
    - [Linkedin](https://www.linkedin.com/company/18268898)
    - [Github](https://github.com/megacorpone)

The [contact](https://www.megacorpone.com/contact.html) page reveals more information about employees and department

![](./img/Chapter6/3.png)

## **2. Whois Enumeration**

Whois is a TCP service, tool, and a type of database that can provide information about a domain name, such as the name server and registrar. This information is often public since registrars charge a fee for private registration.

```bash
whois megacorpone.com
   Domain Name: MEGACORPONE.COM
   Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.gandi.net
   Registrar URL: http://www.gandi.net
   Updated Date: 2023-06-13T18:08:24Z
   Creation Date: 2013-01-22T23:01:00Z
   Registry Expiry Date: 2024-01-22T23:01:00Z
   Registrar: Gandi SAS
   Registrar IANA ID: 81
   Registrar Abuse Contact Email: abuse@support.gandi.net
   Registrar Abuse Contact Phone: +33.170377661
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: NS1.MEGACORPONE.COM
   Name Server: NS2.MEGACORPONE.COM
   Name Server: NS3.MEGACORPONE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2023-06-14T06:37:07Z <<<
...
...
The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
Domain Name: megacorpone.com
Registry Domain ID: 1775445745_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.gandi.net
Registrar URL: http://www.gandi.net
Updated Date: 2023-06-13T18:08:24Z
Creation Date: 2013-01-22T22:01:00Z
Registrar Registration Expiration Date: 2024-01-22T23:01:00Z
Registrar: GANDI SAS
Registrar IANA ID: 81
Registrar Abuse Contact Email: abuse@support.gandi.net
Registrar Abuse Contact Phone: +33.170377661
Reseller:
Domain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited
Domain Status:
Domain Status:
Domain Status:
Domain Status:
Registry Registrant ID:
Registrant Name: Alan Grofield
Registrant Organization: MegaCorpOne
Registrant Street: 2 Old Mill St
Registrant City: Rachel
Registrant State/Province: Nevada
Registrant Postal Code: 89001
Registrant Country: US
Registrant Phone: +1.9038836342
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Registry Admin ID:
Admin Name: Alan Grofield
Admin Organization: MegaCorpOne
Admin Street: 2 Old Mill St
Admin City: Rachel
Admin State/Province: Nevada
Admin Postal Code: 89001
Admin Country: US
Admin Phone: +1.9038836342
Admin Phone Ext:
Admin Fax:
Admin Fax Ext:
Admin Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Registry Tech ID:
Tech Name: Alan Grofield
Tech Organization: MegaCorpOne
Tech Street: 2 Old Mill St
Tech City: Rachel
Tech State/Province: Nevada
Tech Postal Code: 89001
Tech Country: US
Tech Phone: +1.9038836342
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: 3310f82fb4a8f79ee9a6bfe8d672d87e-1696395@contact.gandi.net
Name Server: NS1.MEGACORPONE.COM
Name Server: NS2.MEGACORPONE.COM
Name Server: NS3.MEGACORPONE.COM
Name Server:
Name Server:
Name Server:
Name Server:
Name Server:
Name Server:
Name Server:
DNSSEC: Unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2023-06-14T06:37:25Z <<<
...
...
```

We have some interesting information:

- The output reveals that Alan Grofield registered the domain name. According to the Megacorp One Contact
page, Alan is the "IT and Security Director".
- The nameserver
    - NS1.MEGACORPONE.COM
    - NS2.MEGACORPONE.COM
    - NS3.MEGACORPONE.COM

`Whois` command can perform reverse lookups

```bash
whois 38.100.193.70

NetRange:       38.0.0.0 - 38.255.255.255
CIDR:           38.0.0.0/8
NetName:        COGENT-A
NetHandle:      NET-38-0-0-0-1
Parent:          ()
NetType:        Direct Allocation
OriginAS:       AS174
Organization:   PSINet, Inc. (PSI)
RegDate:        1991-04-16
Updated:        2018-06-20
Comment:        IP allocations within 38.0.0.0/8 are used for Cogent customer static IP assignments.
Comment:
Comment:        Reassignment information for this block can be found at
Comment:        rwhois.cogentco.com 4321
Ref:            https://rdap.arin.net/registry/ip/38.0.0.0



OrgName:        PSINet, Inc.
OrgId:          PSI
Address:        2450 N Street NW
City:           Washington
StateProv:      DC
PostalCode:     20037
Country:        US
RegDate:
Updated:        2015-06-04
Comment:        rwhois.cogentco.com
Ref:            https://rdap.arin.net/registry/entity/PSI

ReferralServer:  rwhois://rwhois.cogentco.com:4321

OrgNOCHandle: ZC108-ARIN
OrgNOCName:   Cogent Communications
OrgNOCPhone:  +1-877-875-4311
OrgNOCEmail:  noc@cogentco.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/ZC108-ARIN

OrgAbuseHandle: COGEN-ARIN
OrgAbuseName:   Cogent Abuse
OrgAbusePhone:  +1-877-875-4311
OrgAbuseEmail:  abuse@cogentco.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/COGEN-ARIN

OrgTechHandle: IPALL-ARIN
OrgTechName:   IP Allocation
OrgTechPhone:  +1-877-875-4311
OrgTechEmail:  ipalloc@cogentco.com
OrgTechRef:    https://rdap.arin.net/registry/entity/IPALL-ARIN

RTechHandle: PSI-NISC-ARIN
RTechName:   IP Allocation
RTechPhone:  +1-877-875-4311
RTechEmail:  ipalloc@cogentco.com
RTechRef:    https://rdap.arin.net/registry/entity/PSI-NISC-ARIN

...
...
Found a referral to rwhois.cogentco.com:4321.

%rwhois V-1.5:0010b0:00 rwhois.cogentco.com (CGNT rwhoisd 1.0.3)
network:ID:NET4-2664C10018
network:Network-Name:NET4-2664C10018
network:IP-Network:38.100.193.0/24
network:Org-Name:Biznesshosting, Inc.
network:Street-Address:500 Green Road
network:City:Pompano Beach
network:State:FL
network:Country:US
network:Postal-Code:33064
network:Tech-Contact:ZC108-ARIN
network:Updated:2017-12-20 14:14:37
%ok
```

The results of the reverse lookup gives us information on who is hosting the IP addresss

## **3. Google Hacking**

- `site:` - Search for a specific site or domain

![](./img/Chapter6/5.png)

- `filetype:` or `ext:` - Search for a specific file type

We combine operators to locate html files (`filetype:html`) on www.megacorpone.com (`site:megacorpone.com`):

![](./img/Chapter6/6.png)

Exclude HTML pages from the results by adding a minus sign (`-`) before the operator:

![](./img/Chapter6/7.png)

![](./img/Chapter6/8.png)

- `intitle:` - Search for a specific word in the title of a page. For example, `intitle:"index of" "parent directory"` is to find pages that contain "index of" in the title and the words "parent directory" on the page.

![](./img/Chapter6/9.png)

The output refers to directory listing pages that list the file contents of the directories without index pages

Here is a list of common google hacking query

- `cache:` - Returns the cached version of a website
- `inurl:` - Searches for a specific term in the URL
- `allinurl:` - Returns results whose URL contains all the specified characters
- `intext:` - Locates webpages that contain certain characters or strings inside their text
- `inanchor:` - Searches for an exact anchor text used on any links
- `|` - Searches for either one term or another
- `+` - Concatenates words to detect pages using more than one specific key

## **4. Netcraft**

Netcraf is an Internet services company based in England offering a free web portal that performs various information gathering functions

**Gather domain information**

Navigate to https://searchdns.netcraft.com/ and enter the domain name megacorpone.com

![](./img/Chapter6/10.png)

The "Site Report" page provides information about the domain name, including the Background, Network, IP Geolocation, SSL/TLS, Hosting History, Sender Policy Framework, DMARC, Web Trackers, and Site Technology

![](./img/Chapter6/11.png)

![](./img/Chapter6/12.png)

![](./img/Chapter6/13.png)

![](./img/Chapter6/14.png)

![](./img/Chapter6/15.png)

![](./img/Chapter6/16.png)

![](./img/Chapter6/17.png)

![](./img/Chapter6/18.png)

![](./img/Chapter6/19.png)

Look at the Site Technology section, we see that the website may be running Apache on Debian

## **5. Recon-ng**

`recon-ng` is a module-based framework for web-based information gathering. `Recon-ng` displays the results of a module to the terminal but it also stores them in a database

![](./img/Chapter6/20.png)

We can see that there is currently no modules installed. Search for "github" module using `market place search github`

![](./img/Chapter6/21.png)

Some of the modules are marked with an asterisk in the "K" column. These modules require credentials or API keys for third-party providers.

We will look for module `recon/domains-hosts/bing_domain_web`

![](./img/Chapter6/22.png)

This module searches Bing with the "domain" operator and it doesn't require an API key. Let’s install the module with `marketplace install`

![](./img/Chapter6/23.png)

Loading the module and display details with `info`

![](./img/Chapter6/24.png)

The module requires the use of a `source`, which is the target we want to gather information about. We can set the source with `options set SOURCE megacorpone.com` and run the module with `run`

![](./img/Chapter6/25.png)

![](./img/Chapter6/26.png)

Use the `show hosts` command to view stored data

![](./img/Chapter6/27.png)

We will look for module `recon/hosts-hosts/resolve` to resolve the IP addresses of the hosts

![](./img/Chapter6/28.png)

Install the module

![](./img/Chapter6/29.png)

Load the module and display info details

![](./img/Chapter6/30.png)

We will use the default source, which is the hosts stored in the database. Run the module

![](./img/Chapter6/31.png)

The `show hosts` command displays the IP addresses of the hosts.

![](./img/Chapter6/32.png)


## **6. Open-Source Code**

Open-source code is code that is publicly available and can be viewed and modified by anyone. This includes code that is hosted on public repositories such as GitHub and GitLab.

Code stored online can provide a glimpse into the programming languages and frameworks used by an organization. In some rare occasions, developers have even accidentally committed sensitive data and credentials to public repos.

We have found the GitHub [account](https://github.com/megacorpone) of Megacorp One in the previous section. Let's take a look at the code they have stored on GitHub.

![](./img/Chapter6/33.png)

Search for the keyword "users" in this account's repos

![](./img/Chapter6/34.png)

We find an interesting file `xmapp.users` which appears to contain a username and password hash

```
trivera:$apr1$A0vSKwao$GV3sgGAj53j.c3GkS4oUC0
``` 

## **7. Shodan**

Shodan is a search engine that crawls devices connected to the Internet including but not limited to the World Wide Web. This includes the servers that run websites but also devices like routers and IoT devices

Search for `hostname:megacorpone.com`:

![](./img/Chapter6/35.png)

Shodan lists the IPs, services, and banner information.

There are 3 services running SSH on port 22, 3 services running DNS, 2 services running HTTP on port 80, and 1 service running HTTPS on port 443.

![](./img/Chapter6/36.png)

![](./img/Chapter6/37.png)

![](./img/Chapter6/38.png)

![](./img/Chapter6/39.png)

Here is the summary of one of the hosts: https://www.shodan.io/host/149.56.244.87

![](./img/Chapter6/40.png)

We can view the ports, services, and technologies used by the server on this page. Shodan will also reveal if there are any published vulnerabilities for any of the identified services or technologies

## **8. Security Headers Scanner**

[Security Headers](https://securityheaders.com/), will analyze HTTP response headers and provide basic analysis of the target site’s security posture. We can use this to get an idea of an organization’s coding and security practices based on the results

[Here](https://securityheaders.com/?q=www.megacorpone.com&followRedirects=on) is the result of the scan for https://www.megacorpone.com

![](./img/Chapter6/42.png)

The site is missing several defensive headers, such as `Content-Security-Policy` and `X-Frame-Options`

![](./img/Chapter6/43.png)

## **9. SSL Server Test**

[SSL Server Test](https://www.ssllabs.com/ssltest/) analyzes a server’s SSL/TLS configuration and compares it against current best practices. It will also identify some SSL/TLS related vulnerabilities, such as Poodle or Heartbleed.

[Here](https://www.ssllabs.com/ssltest/analyze.html?d=www.megacorpone.com) is the result of the scan for https://www.megacorpone.com

![](./img/Chapter6/44.png)

## **10. Pastebin**

[Pastebin](https://pastebin.com/) is a website where users can store plain text. It is often used by developers to share code snippets or by hackers to share stolen data. Pastebin has a search feature that allows us to search for specific keywords or strings

Let's search for `megacorpone.com`:

![](./img/Chapter6/45.png)

## **11. User Information Gathering**

### **11.1. Email Harvesting**

We will use [theHarvester](https://github.com/laramies/theHarvester), which gathers emails, names, subdomains, IPs, and URLs from multiple public data sources.

```bash
theHarvester -d megacorpone.com -b bing
```

![](./img/Chapter6/46.png)

- `-d`: specifies the domain name
- `-b`: specifies the data source to search

We gets the following information:

- Email addresses
    - agrofield@megacorpone.com
    - first@megacorpone.com
    - jane@megacorpone.com
    - msmith@megacorpone.com
    - sales@megacorpone.com
    - trivera@megacorpone.com
- Host names
    - intranet.megacorpone.com
    - megacorpone.com
    - ns1.megacorpone.com
    - ns2.megacorpone.com
    - siem.megacorpone.com
    - www2.megacorpone.com

## **12. Social Media Tools**

### **12.1. Social-Searcher**

[Social-Searcher](https://www.social-searcher.com/) is a free social media search engine that allows us to search for keywords or hashtags across multiple social media platforms

[Here](https://www.social-searcher.com/social-buzz/?q5=megacorpone.com) is the result of the search for `megacorpone.com`:

![](./img/Chapter6/47.png)

The search results will include information posted by the target organization and what people are saying about it. Among other things, this can help us determine what sort of footprint and coverage an organization has on social media

### **12.2. Site-Specific Tools**

[Twofi](https://github.com/digininja/twofi) scans a user’s Twitter feed and generates a personalized wordlist used for password attacks against that user. While we will not run any attacks during passive information gathering, we can run this tool against any Twitter accounts we have identified to have a wordlist ready
when needed. Twofi requires a valid Twitter API key.

[linkedin2username](https://github.com/initstring/linkedin2username) is a script for generating username lists based on LinkedIn data. It requires valid LinkedIn credentials and depends on a LinkedIn connection to individuals in the target organization. The script will output usernames in several different formats.

```bash
python linkedin2username.py -u <your-username> -c <company-name>
```

Note that the company name will appear in the URL of the company’s LinkedIn page: `https://linkedin.com/company/<company-name>`

![](./img/Chapter6/48.png)

The output will be saved to files under the `li2u-output` directory

![](./img/Chapter6/49.png)

![](./img/Chapter6/50.png)

![](./img/Chapter6/51.png)

![](./img/Chapter6/52.png)

## **13. Information Gathering Frameworks**

### **13.1. OSINT Framework**

The [OSINT Framework](https://osintframework.com/) includes information gathering tools and websites in one central location. Some tools listed in the framework cover more disciplines than information security.

![](./img/Chapter6/53.png)

### **13.2. Maltego**

[Maltego](https://www.maltego.com/) is a commercial information gathering tool that uses a graphical interface to display relationships between entities.

Maltego searches thousands of online data sources, and uses extremely clever "transforms" to convert one piece of information into another. For example, if we are performing a user information gathering campaign, we could submit an email address, and through various automated searches, "transform" that into an associated phone number or street address