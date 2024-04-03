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
- Website headers


**Part 2: Analysis**

The tool then performs analysis on the collected information to identify vulnerabilities, exposures, and misconfigurations.


**Part 3: Reporting**

The tool then visually represents the collected information and analysis in a user friendly format.



# How to use the tool

1. Import all python libraries
2. Add the shodan and virustotal api keys if available:

![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/d2d77b48-36d3-483a-8bad-5336ab9c2a32)

3. Run the script
4. Enter a domain to search for:

![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/4b1131f5-0dfe-4519-b78c-a7e0afabd50c)


5. View the domain analysis report:
![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/37f92969-7f46-47a3-aa26-3b804ad07487)

6. View the domain vulnerability report:
![image](https://github.com/smh-404/TenaciousDomain/assets/153841753/d59808ff-6ac5-4b2c-9077-63da74a92ee0)




# Notes

**Under development:**
- Improving the visual aspect of the report.

If you have any questions, suggestions, or feedback, feel free to reach out to me!

Thanks!
