# TenaciousDomain
This is a security tool to analyze domains in-depth. This is done by gathering as much information about the domain and its associated assets, and then performing analysis on the collected data to create a visual report highlighting security risks and concerns.

The python script uses a shodan api which you must include in the getOpenPorts function.

**Part 1: Collection**

The tool collects the following information:
- WHOIS record
- DNS records (a, aaaa, ns, mx, soa, txt, spf, dmarc)
- SSL/TLS certificates
- Subdomains (from brute-forcing and certificates)
- Open port info & banners
- Domain/website reputation & rankings (work in progress!)
- Website header (work in progress!)


**Part 2: Analysis - work in progress!**

The tool then performs analysis on the collected information to identify vulnerabilities, exposures, and misconfigurations.


**Part 3: Reporting - work in progress!**

The tool then visually represents the collected information and analysis in a user friendly format.

