# TenaciousDomain
This is a cyber security reconnaissance tool to analyze domains in-depth. This is done by gathering as much information about the domain and its associated assets, and then performing analysis on the collected data to create a visual report highlighting security risks and concerns.

The python script uses a shodan and virustotal api which you should include to get the most value out of the tool, otherwise it will still run but without collecting all data points.

**Part 1: Collection**

The tool collects the following information:
- WHOIS record
- DNS records (a, aaaa, ns, mx, soa, txt, spf, dmarc)
- SSL/TLS certificates
- Subdomains (from brute-forcing and certificates)
- Open port info & banners
- Domain/website reputation & rankings
- Website headers (work in progress!)


**Part 2: Analysis - work in progress!**

The tool then performs analysis on the collected information to identify vulnerabilities, exposures, and misconfigurations.


**Part 3: Reporting**

The tool then visually represents the collected information and analysis in a user friendly format.



# How to use the tool

1. Import all python libraries
2. Add the shodan and virustotal api keys if available:

![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/d2d77b48-36d3-483a-8bad-5336ab9c2a32)

3. Run the script
4. Enter a domain to search for:

![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/9909a9dd-b899-4299-9b07-dbcc75bdf872)

5. View the report:

![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/425443e0-7316-40ee-8c61-b2eae92ec7f6)



# Notes

**Under development:**
- Including website header data points.
- Improving the visual aspect of the report.
- The vulnerability report section.

If you have any questions, suggestions, or feedback, feel free to reach out to me!

Thanks!
