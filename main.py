import whois
import dns.resolver
import json
import requests
from crtsh import crtshAPI
from shodan import Shodan


shodanApiKey = ''
virusTotalApiKey = ''

def getInput():
    domain = input("Enter a domain to search:\n")
    domain = domain.strip()
    return domain


def getWhois(domain):
    domainWhois = whois.whois(domain)
    return domainWhois


def getDns(domain):
    aRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'A')
        for row in response:
            if aRecord == "":
                aRecord = row.to_text()
            else:
                aRecord = aRecord + ", " + row.to_text()
    except:
        aRecord = "None"
    aaaaRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'AAAA')
        for row in response:
            if aaaaRecord == "":
                aaaaRecord = row.to_text()
            else:
                aaaaRecord = aaaaRecord + ", " + row.to_text()
    except:
        aaaaRecord = "None"
    nsRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'NS')
        for row in response:
            if nsRecord == "":
                nsRecord = row.to_text()
            else:
                nsRecord = nsRecord + ", " + row.to_text()
    except:
        nsRecord = "None"
    mxRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'MX')
        for row in response:
            if mxRecord == "":
                mxRecord = row.to_text()
            else:
                mxRecord = mxRecord + ", " + row.to_text()
    except:
        mxRecord = "None"
    soaRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'SOA')
        for row in response:
            if soaRecord == "":
                soaRecord = row.to_text()
            else:
                soaRecord = soaRecord + ", " + row.to_text()
    except:
        soaRecord = "None"
    txtRecord = "None"
    spfRecord = "None"
    try:
        response = dns.resolver.resolve(domain, 'TXT')
        for row in response:
            if "v=spf" not in str(row.to_text()):
                if txtRecord == "None":
                    txtRecord = row.to_text()
                else:
                    txtRecord = txtRecord + ", " + row.to_text()
            else:
                if spfRecord == "None":
                    spfRecord = row.to_text()
                else:
                    spfRecord = spfRecord + ", " + row.to_text()
    except:
        txtRecord = "None"
        spfRecord = "None"
    dmarcRecord = ""
    try:
        response = dns.resolver.resolve(("_dmarc." + str(domain)), 'TXT')
        for row in response:
            if dmarcRecord == "":
                dmarcRecord = row.to_text()
            else:
                dmarcRecord = dmarcRecord + ", " + row.to_text()
    except:
        dmarcRecord = "None"

    domainDns = {"aRecord": aRecord, "aaaaRecord": aaaaRecord, "nsRecord": nsRecord, "mxRecord": mxRecord,
                 "soaRecord": soaRecord, "txtRecord": txtRecord, "spfRecord": spfRecord, "dmarcRecord": dmarcRecord}

    return domainDns


def getCert(domain):
    domainCert = json.dumps(crtshAPI().search(domain))
    return domainCert


def getSubdomains(domain, domainCert):
    subdomainListCrt = []
    for row in domainCert:
        if row['common_name'].lower() not in subdomainListCrt and "*" not in row['common_name'] and domain in row['common_name']:
            subdomainListCrt.append(row['common_name'].lower())
        altNames = row['name_value'].split("\n")
        for altName in altNames:
            if altName.lower() not in subdomainListCrt and "*" not in altName and domain in altName:
                subdomainListCrt.append(altName.lower())
    subdomainListBrute = []
    bruteforceList100 = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4"]

    try:
        response = dns.resolver.resolve("easterEgg12345." + domain, 'A')
        # print("Domain is wildcard. Skipping subdomain bruteforce.")
    except:
        # print("Domain is not wildcard. Proceeding with subdomain bruteforce.")
        for subdomainVar in bruteforceList100:
            try:
                response = dns.resolver.resolve(subdomainVar + "." + domain, 'A')
                subdomainListBrute.append(subdomainVar + "." + domain)
            except:
                pass
    subdomainListCombined = subdomainListCrt + subdomainListBrute
    subdomainListCombined = list(set(subdomainListCombined))
    return subdomainListCombined


def getOpenPorts(ip, shodanApiKey):
    api = Shodan(shodanApiKey)
    shodanResponse = api.host(ip)
    return shodanResponse


def queryVT(domain, virusTotalApiKey):
    url = "https://www.virustotal.com/api/v3/domains/" + domain
    headers = {
        "accept": "application/json",
        "x-apikey": virusTotalApiKey
    }
    response = requests.get(url, headers=headers)
    results = response.text
    results = json.loads(str(results))
    return results


def getHeaders(domain):
    url = "http://" + domain
    res = requests.get(url)
    headers = res.headers

    try:
        headerServer = headers['Server']
    except:
        headerServer = ""

    try:
        headerXPoweredBy = headers['X-Powered-By']
    except:
        headerXPoweredBy = ""

    try:
        headerSTS = headers['Strict-Transport-Security']
    except:
        headerSTS = ""

    try:
        headerCSP = headers['Content-Security-Policy']
    except:
        headerCSP = ""

    try:
        headerXFrameOptions = headers['X-Frame-Options']
    except:
        headerXFrameOptions = ""

    try:
        headerXContentTypeOptions = headers['X-Content-Type-Options']
    except:
        headerXContentTypeOptions = ""

    try:
        headerXXSSProtection = headers['X-XSS-Protection']
    except:
        headerXXSSProtection = ""

    try:
        headerReferrerPolicy = headers['Referrer-Policy']
    except:
        headerReferrerPolicy = ""

    return headerServer, headerXPoweredBy, headerSTS, headerCSP, headerXFrameOptions, headerXContentTypeOptions, headerXXSSProtection, headerReferrerPolicy




domain = getInput()
print("Initiating enrichment process for domain", domain, "...")


domainWhois = getWhois(domain)
# print(json.dumps(domainWhois, indent=4, default=str))


domainDns = getDns(domain)
# print(json.dumps(domainDns, indent=4, default=str))


domainCert = getCert(domain)
domainCert = json.loads(domainCert)
# print(json.dumps(domainCert, indent=4, default=str))


subdomainListCombined = getSubdomains(domain, domainCert)
# print(subdomainListCombined)

try:
    tempIP = domainDns['aRecord']
    if "," in str(domainDns['aRecord']):
        tempIP = str(domainDns['aRecord']).split(",")[0]
    shodanIpInfo = getOpenPorts(tempIP, shodanApiKey)
except:
    shodanIpInfo = ""
# print(json.dumps(shodanIpInfo, indent=4, default=str))


try:
    vtResults = queryVT(domain, virusTotalApiKey)
    maliciousStatus = vtResults['data']['attributes']['last_analysis_stats']
    popularityRanks = vtResults['data']['attributes']['popularity_ranks']
    # print("\nMalicious Status:")
    # print(json.dumps(maliciousStatus, indent=4, default=str))
    # print("\nPopularity Ranking:")
    # print(json.dumps(popularityRanks, indent=4, default=str))
except:
    maliciousStatus = ""
    popularityRanks = ""


headerServer, headerXPoweredBy, headerSTS, headerCSP, headerXFrameOptions, headerXContentTypeOptions, headerXXSSProtection, headerReferrerPolicy = getHeaders(domain)



print("Data points collected ...")



############################################
#                                          #
#        Writing output to txt files       #
#                                          #
############################################

file = open("whois.txt", "w")
file.writelines(str(json.dumps(domainWhois, indent=4, default=str)))
file.close()

file = open("dns.txt", "w")
file.writelines(str(json.dumps(domainDns, indent=4, default=str)))
file.close()

file = open("certificates.txt", "w")
file.writelines(str(json.dumps(domainCert, indent=4, default=str)))
file.close()

file = open("subdomains.txt", "w")
file.writelines(str(json.dumps(subdomainListCombined, indent=4, default=str)))
file.close()

file = open("ipInfo.txt", "w")
file.writelines(str(json.dumps(shodanIpInfo, indent=4, default=str)))
file.close()

file = open("maliciousStatus.txt", "w")
file.writelines(str(json.dumps(maliciousStatus, indent=4, default=str)))
file.close()

file = open("popularityRankings.txt", "w")
file.writelines(str(json.dumps(popularityRanks, indent=4, default=str)))
file.close()

# # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # #
#             CREATING REPORT FROM HERE             #
# # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # #

print("Data points parsed ...")

# Extracting WHOIS Information
try:
    domainWhoisDomainName = domainWhois['domain_name']
except:
    domainWhoisDomainName = "None"
try:
    domainWhoisCreationDate = domainWhois['creation_date']
except:
    domainWhoisCreationDate = "None"
try:
    domainWhoisExpiryDate = domainWhois['expiration_date']
except:
    domainWhoisExpiryDate = "None"
try:
    domainWhoisRegistrar = domainWhois['registrar']
except:
    domainWhoisRegistrar = "None"
try:
    domainWhoisName = domainWhois['name']
except:
    domainWhoisName = "None"
try:
    domainWhoisOrg = domainWhois['org']
except:
    domainWhoisOrg = "None"
try:
    domainWhoisEmails = domainWhois['emails']
except:
    domainWhoisEmails = "None"
try:
    domainWhoisCity = domainWhois['city']
except:
    domainWhoisCity = "None"
try:
    domainWhoisAddress = domainWhois['address']
except:
    domainWhoisAddress = "None"

# Extracting Shodan Information
try:
    shodanIpInfoISP = shodanIpInfo['isp']
except:
    shodanIpInfoISP = "None"
try:
    shodanIPInfoCountry = shodanIpInfo['country_name']
except:
    shodanIPInfoCountry = "None"
try:
    shodanIpInfoCity = shodanIpInfo['city']
except:
    shodanIpInfoCity = "None"
try:
    shodanIpInfoOS = shodanIpInfo['os']
except:
    shodanIpInfoOS = "None"
try:
    shodanIpInfoPorts = shodanIpInfo['ports']
except:
    shodanIpInfoPorts = "None"
try:
    shodanIpInfoHostnames = shodanIpInfo['hostnames']
except:
    shodanIpInfoHostnames = "None"
try:
      shodanIpInfoVulns = shodanIpInfo['vulns']
except:
      shodanIpInfoVulns = "None"
try:
    shodanIpInfoTags = shodanIpInfo['tags']
except:
    shodanIpInfoTags = "None"
# Extracting Malicious Status (from VirusTotal)
try:
    maliciousStatusHarmless = maliciousStatus['harmless']
except:
    maliciousStatusHarmless = "n/a"
try:
    maliciousStatusSuspicious = maliciousStatus['suspicious']
except:
    maliciousStatusSuspicious = "n/a"
try:
    maliciousStatusMalicious = maliciousStatus['malicious']
except:
    maliciousStatusMalicious = "n/a"

# Extracting Popularity Rankings (from VirusTotal)
try:
    popularityRanksAlexa = popularityRanks['Alexa']['rank']
except:
    popularityRanksAlexa = "None"
try:
    popularityRanksStatvoo = popularityRanks['Statvoo']['rank']
except:
    popularityRanksStatvoo = "None"


# Extracting SSL/TLS Information
tlsVersions = ""
tlsSigAlg = ""
tlsPublicKeyBits = ""
tlsPublicKeyType = ""
tlsCipherName = ""
tlsCipherBits = ""

try:
    for row in shodanIpInfo['data']:
        if row['port'] == 443:
            # print(row)
            tlsResults = row['ssl']['versions']
            # print(row['ssl']['cipher'])
            tlsSigAlg = row['ssl']['cert']['sig_alg']
            tlsPublicKeyBits = row['ssl']['cert']['pubkey']['bits']
            tlsPublicKeyType = row['ssl']['cert']['pubkey']['type']
            tlsCipherName = row['ssl']['cipher']['name']
            tlsCipherBits = row['ssl']['cipher']['bits']
except:
    print("No port 443 detected")

try:
    for res in tlsResults:
        if "-" not in res:
            if tlsVersions == "":
                tlsVersions = res
            else:
                tlsVersions = tlsVersions + ", " + res
except:
    tlsVersions = ""
# Creating Certificate Table (from transparency logs)
certificatesHtmlTable = ""
for row in domainCert:
    certificatesHtmlTable = certificatesHtmlTable + "<tr><td>" + row['common_name'] + "</td><td>" + row['name_value'] + "</td><td>" + row['not_before'] + "</td><td>" + row['not_after'] + "</td><td>" + row['issuer_name'] + "</td></tr>"
certificatesHtmlTable = '''<table>
  <tr>
    <th>Common Name</th>
    <th>Alternative Names</th>
    <th>Created Date</th>
    <th>Expiry Date</th>
    <th>Issuer</th>
  </tr>''' + certificatesHtmlTable + '</table>'

print("Creating HTML summary report ...")

htmlCss = '''
<style>
* {
  box-sizing: border-box;
}

/* Add a gray background color with some padding */
body {
  font-family: Arial;
  padding: 20px;
  background: #f1f1f1;
}

/* Header/Blog Title */
.header {
  padding: 30px;
  font-size: 40px;
  text-align: center;
  background: white;
}

/* Create two unequal columns that floats next to each other */
/* Left column */
.leftcolumn {   
  float: left;
  width: 75%;
}

/* Right column */
.rightcolumn {
  float: left;
  width: 25%;
  padding-left: 20px;
}

/* Fake image */
.fakeimg {
  background-color: #aaa;
  width: 100%;
  padding: 20px;
}

/* Add a card effect for articles */
.card {
   background-color: white;
   padding: 20px;
   margin-top: 20px;
}

/* Clear floats after the columns */
.row:after {
  content: "";
  display: table;
  clear: both;
}

/* Footer */
.footer {
  padding: 20px;
  text-align: center;
  background: #ddd;
  margin-top: 20px;
}

/* Responsive layout - when the screen is less than 800px wide, make the two columns stack on top of each other instead of next to each other */
@media screen and (max-width: 800px) {
  .leftcolumn, .rightcolumn {   
    width: 100%;
    padding: 0;
  }
}

table {
  border-collapse: collapse;
  border-spacing: 0;
  width: 100%;
  border: 1px solid #ddd;
}

th, td {
  text-align: left;
  padding: 16px;
}

tr:nth-child(even) {
  background-color: #f2f2f2;
}

* {
  box-sizing: border-box;
}

/* Create two equal columns that floats next to each other */
.column {
  float: left;
  width: 50%;
  padding: 10px;
  height: 300px; /* Should be removed. Only for demonstration */
}

/* Clear floats after the columns */
.row:after {
  content: "";
  display: table;
  clear: both;
}

.btn {
  border: none;
  color: white;
  padding: 14px 28px;
  font-size: 16px;
  cursor: pointer;
}

.harmless {background-color: #04AA6D;} /* Green */
.harmless:hover {background-color: #46a049;}

.suspicious {background-color: #ff9800;} /* Orange */
.suspicious:hover {background: #e68a00;}

.malicious {background-color: #f44336;} /* Red */ 
.malicious:hover {background: #da190b;}

</style>
'''

htmlBody = '''
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
''' + htmlCss + f'''
</head>
<body>

<div class="header">
  <h2>Domain Analysis Report</h2>
  <h5>{domain}</h5>
</div>

<div class="row">
  <div class="leftcolumn">
    <div class="card">
      <h2>WHOIS Information</h2>
      <h5>Information related to the registration of the domain:</h5>
      <table>
          <tr>
            <td><b>Domain Name</b></td>
            <td>{domainWhoisDomainName}</td>
          </tr>
          <tr>
            <td><b>Creation Date</b></td>
            <td>{domainWhoisCreationDate}</td>
          </tr>
          <tr>
            <td><b>Expiry Date</b></td>
            <td>{domainWhoisExpiryDate}</td>
          </tr>
          <tr>
            <td><b>Registrar</b></td>
            <td>{domainWhoisRegistrar}</td>
          </tr>
          <tr>
            <td><b>Registrant Name</b></td>
            <td>{str(domainWhoisName).replace("[", "").replace("]", "")}</td>
          </tr>
          <tr>
            <td><b>Registrant Organization</b></td>
            <td>{domainWhoisOrg}</td>
          </tr>
          <tr>
            <td><b>Emails</b></td>
            <td>{domainWhoisEmails}</td>
          </tr>
          <tr>
            <td><b>Registrant City</b></td>
            <td>{str(domainWhoisCity).replace("[", "").replace("]", "")}</td>
          </tr>
          <tr>
            <td><b>Registrant Address</b></td>
            <td>{str(domainWhoisAddress).replace("[", "").replace("]", "")}</td>
          </tr>
        </table>
      </div>

    <div class="card">
      <h2>DNS Information</h2>
      <h5>DNS records configured on the domain:</h5>
      <table>
          <tr>
            <td><b>A Record</b></td>
            <td>{domainDns['aRecord']}</td>
          </tr>
          <tr>
            <td><b>AAAA Record</b></td>
            <td>{domainDns['aaaaRecord']}</td>
          </tr>
          <tr>
            <td><b>Name Servers</b></td>
            <td>{domainDns['nsRecord']}</td>
          </tr>
          <tr>
            <td><b>Mail Servers</b></td>
            <td>{domainDns['mxRecord']}</td>
          </tr>
          <tr>
            <td><b>SOA Record</b></td>
            <td>{domainDns['soaRecord']}</td>
          </tr>
          <tr>
            <td><b>TXT Records</b></td>
            <td>{domainDns['txtRecord']}</td>
          </tr>
          <tr>
            <td><b>SPF Record</b></td>
            <td>{domainDns['spfRecord']}</td>
          </tr>
          <tr>
            <td><b>DMARC Record</b></td>
            <td>{domainDns['dmarcRecord']}</td>
          </tr>
        </table>
      </div>

    <div class="card">
      <h2>IP Information</h2>
      <h5>Information found about the host, location, open ports, and services running on the domain's IP:</h5>
      <table>
          <tr>
            <td><b>IP Address</b></td>
            <td>{domainDns['aRecord']}</td>
          </tr>
          <tr>
            <td><b>ISP</b></td>
            <td>{shodanIpInfoISP}</td>
          </tr>
          <tr>
            <td><b>Country</b></td>
            <td>{shodanIPInfoCountry}</td>
          </tr>
          <tr>
            <td><b>City</b></td>
            <td>{shodanIpInfoCity}</td>
          </tr>
          <tr>
            <td><b>Operating System</b></td>
            <td>{shodanIpInfoOS}</td>
          </tr>
          <tr>
            <td><b>Ports</b></td>
            <td>{str(shodanIpInfoPorts).replace("[", "").replace("]", "")}</td>
          </tr>
          <tr>
            <td><b>Hostnames</b></td>
            <td>{str(shodanIpInfoHostnames).replace("[", "").replace("]", "")}</td>
          </tr>
          <tr>
            <td><b>Vulnerabilities</b></td>
            <td>{str(shodanIpInfoVulns).replace("[", "").replace("]", "")}</td>
          </tr>
          <tr>
            <td><b>Tags</b></td>
            <td>{str(shodanIpInfoTags).replace("[", "").replace("]", "")}</td>
          </tr>
        </table>
      </div>


    <div class="card">
      <div class="row">
        <div class="column">
            <h2>Website Risk Analysis</h2>
            <p>Sandbox analysis to identify the risk classification of the website:</p>
            <button class="btn harmless">Harmless: {maliciousStatusHarmless}</button><br><br>
            <button class="btn suspicious">Suspicious: {maliciousStatusSuspicious}</button><br><br>
            <button class="btn malicious">Malicious: {maliciousStatusMalicious}</button><br><br>
          </div>
          <div class="column">
            <h2>Website Popularity Rankings</h2>
            <p>Search engine indexing and website traffic based rankings of the website:</p>
            <b>Alexa Ranking:</b> {popularityRanksAlexa}<br><br>
            <b>Statvoo Ranking:</b> {popularityRanksStatvoo}
          </div>
        </div>
        <br>
      </div>

    <div class="card">
      <h2>Website Headers</h2>
      <h5>Information found within the website's security headers:</h5>
      <table>
          <tr>
            <td><b>Server</b></td>
            <td>{headerServer}</td>
          </tr>
          <tr>
            <td><b>X-Powered-By</b></td>
            <td>{headerXPoweredBy}</td>
          </tr>
          <tr>
            <td><b>Strict-Transport-Security</b></td>
            <td>{headerSTS}</td>
          </tr>
          <tr>
            <td><b>Content-Security-Policy</b></td>
            <td>{headerCSP}</td>
          </tr>
          <tr>
            <td><b>X-Frame-Options</b></td>
            <td>{headerXFrameOptions}</td>
          </tr>
          <tr>
            <td><b>X-Content-Type-Options</b></td>
            <td>{headerXContentTypeOptions}</td>
          </tr>
          <tr>
            <td><b>X-XSS-Protection</b></td>
            <td>{headerXXSSProtection}</td>
          </tr>
          <tr>
            <td><b>Referrer-Policy</b></td>
            <td>{headerReferrerPolicy}</td>
          </tr>
        </table>
      </div>
    
    
    <div class="card">
      <h2>Active Website SSL/TLS Certificate</h2>
      <h5>Information collected from the active certificate configured on the website at this point in time:</h5>
      <table>

          <tr>
            <td><b>SSL/TLS Version</b></td>
            <td>{tlsVersions}</td>
          </tr>
          <tr>
            <td><b>SSL/TLS Signature Algorithm</b></td>
            <td>{tlsSigAlg}</td>
          </tr>
          <tr>
            <td><b>SSL/TLS Public Key</b></td>
            <td>{tlsPublicKeyType} ({tlsPublicKeyBits} bits)</td>
          </tr>
          <tr>
            <td><b>SSL/TLS Cipher</b></td>
            <td>{tlsCipherName} ({tlsCipherBits} bits)</td>
          </tr>
        </table>
      </div>

    <div class="card">
      <h2>Hosts</h2>
      <h5>All hostnames identified through subdomain bruteforcing and certificate lookups:</h5>
      <ul>{str(subdomainListCombined).replace("['", "<li>").replace("',", "</li>").replace(" '", "<li>").replace("']", "</li>")}</ul>
    </div>


    <div class="card">
      <h2>Certificates</h2>
      <h5>SSL and TLS certificates collected through transparency logs related to the domain:</h5>
      {certificatesHtmlTable}
      </div>



  </div>


  <div class="rightcolumn">
    <div class="card">
      <h2>About This Tool</h2>
      <p>The TenaciousDomain reconnaissance tool consists of a comprehensive collection of data related to the input 
      domain and summarizes findings in a report.<br><br>The full version of this tool provides a vulnerability report
      based on analysis of the collected data points.</p>
    </div>


    <div class="card">
      <h3>Github Link:</h3>
      <p><a href="https://github.com/smh-404/TenaciousDomain">https://github.com/smh-404/TenaciousDomain</a></p>
    </div>
  </div>
</div>


<div class="footer">
  <h2>Created by SMH-404</h2>
</div>

</body>
</html>
'''

file = open("Report.html", "w")
file.writelines(htmlBody)

print("\nReport Created!")
