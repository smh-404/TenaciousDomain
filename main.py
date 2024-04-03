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
    res = requests.get(url, verify=False)
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
    pass

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
    certificatesHtmlTable = certificatesHtmlTable + '<tr><td><div style="overflow-x: hidden">' + row['common_name'] + '</div></td><td><div style="overflow-x: hidden">' + row['name_value'] + '</div></td><td><div style="overflow-x: hidden">' + row['not_before'] + '</div></td><td><div style="overflow-x: hidden">' + row['not_after'] + '</div></td><td><div style="overflow-x: hidden">' + row['issuer_name'] + "</div></td></tr>"
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

th {
  text-align: left;
  padding: 16px;
  word-break: keep-all;
  max-width: 500px;
}

td {
  text-align: left;
  padding: 16px;
  word-break: break-word;
  max-width: 500px;
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
      <h3>Vulnerability Report:</h3>
      <p><a href="./VulnReport.html">Link to Domain Vulnerability Report</a></p>
    </div>
    
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

print("Report Created!")


#####################################################
#                                                   #
#            Identifying Vulnerabilities            #
#                                                   #
#####################################################

print("Searching for vulnerabilities ...")

vulnNoSpf = "None"
vulnNoDmarc = "None"
vulnCve = "None"
vulnPort445 = "None" # https://www.all-about-security.de/identifying-secure-and-unsecured-ports-and-how-to-secure-them/
vulnPort3389 = "None"
vulnPort137 = "None"
vulnPort139 = "None"
vulnPort20 = "None"
vulnPort21 = "None"
vulnPort22 = "None"
vulnPort23 = "None"
vulnPort3306 = "None"
vulnMaliciousWebsite = "None"
vulnSuspiciousWebsite = "None"
vulnWebsiteServerVersionExposed = "None"
vulnWebsiteXPoweredByExposed = "None"
vulnWebsiteNoSTS = "None"
vulnWebsiteNoCSP = "None"
vulnWebsiteNoXFrameOptions = "None"
vulnWebsiteNoXContentType = "None"
vulnWebsiteNoXXSSProtection = "None"
vulnWebsiteNoReferrerPolicy = "None"
vulnSSLv3Usage = "None"
vulnTLSv1Usage = "None"
vulnTLSv1_1Usage = "None"
vulnTLSv1_2Usage = "None"
vulnWeakCipher = "None" # https://ciphersuite.info/cs/?singlepage=true
vulnInsecureCipher = "None" # https://ciphersuite.info/cs/?singlepage=true
vulnWhoisPersonalEmail = "None"

if "v=spf" not in (str(domainDns['spfRecord'])).lower():
    vulnNoSpf = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if "v=dmarc" not in (str(domainDns['dmarcRecord'])).lower():
    vulnNoDmarc = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if 445 in shodanIpInfoPorts:
    vulnPort445 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 3389 in shodanIpInfoPorts:
    vulnPort3389 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 137 in shodanIpInfoPorts:
    vulnPort137 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 139 in shodanIpInfoPorts:
    vulnPort139 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 20 in shodanIpInfoPorts:
    vulnPort20 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 21 in shodanIpInfoPorts:
    vulnPort21 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 22 in shodanIpInfoPorts:
    vulnPort22 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 23 in shodanIpInfoPorts:
    vulnPort23 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if 3306 in shodanIpInfoPorts:
    vulnPort3306 = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if maliciousStatusMalicious > 0:
    vulnMaliciousWebsite = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'
if maliciousStatusSuspicious > 0:
    vulnSuspiciousWebsite = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if shodanIpInfoVulns != "None":
    vulnCve = '<b><FONT COLOR="#ff0000"> ' + str(shodanIpInfoVulns) + '</FONT></b>'

if any(i.isdigit() for i in str(headerServer)):
    vulnWebsiteServerVersionExposed = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if any(i.isdigit() for i in str(headerXPoweredBy)):
    vulnWebsiteXPoweredByExposed = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if headerSTS == "":
    vulnWebsiteNoSTS = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if headerCSP == "":
    vulnWebsiteNoCSP = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if headerXFrameOptions == "":
    vulnWebsiteNoXFrameOptions = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if headerXContentTypeOptions == "":
    vulnWebsiteNoXContentType = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if headerXXSSProtection == "":
    vulnWebsiteNoXXSSProtection = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if headerReferrerPolicy == "":
    vulnWebsiteNoReferrerPolicy = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if "SSLv3" in str(tlsVersions):
    vulnSSLv3Usage = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if "TLSv1," in str(tlsVersions) or "TLSv1" == str(tlsVersions):
    vulnTLSv1Usage = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if "TLSv1.1" in str(tlsVersions):
    vulnTLSv1_1Usage = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

# if "TLSv1.2" in str(tlsVersions):
#     vulnTLSv1_2Usage = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

# Weak & Insecure Cipher List Updated on 3rd April 2024 - https://ciphersuite.info/cs/?singlepage=true
weakCipherList = ["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_DSS_WITH_SEED_CBC_SHA", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_DHE_PSK_WITH_AES_128_CCM", "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_DHE_PSK_WITH_AES_256_CCM", "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_128_CCM", "TLS_DHE_RSA_WITH_AES_128_CCM_8", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CCM", "TLS_DHE_RSA_WITH_AES_256_CCM_8", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_RSA_WITH_SEED_CBC_SHA", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "TLS_KRB5_WITH_IDEA_CBC_SHA", "TLS_PSK_DHE_WITH_AES_128_CCM_8", "TLS_PSK_DHE_WITH_AES_256_CCM_8", "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_PSK_WITH_AES_128_CBC_SHA", "TLS_PSK_WITH_AES_128_CBC_SHA256", "TLS_PSK_WITH_AES_128_CCM", "TLS_PSK_WITH_AES_128_CCM_8", "TLS_PSK_WITH_AES_128_GCM_SHA256", "TLS_PSK_WITH_AES_256_CBC_SHA", "TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS_PSK_WITH_AES_256_CCM", "TLS_PSK_WITH_AES_256_CCM_8", "TLS_PSK_WITH_AES_256_GCM_SHA384", "TLS_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_CCM", "TLS_RSA_WITH_AES_128_CCM_8", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_AES_256_CCM", "TLS_RSA_WITH_AES_256_CCM_8", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "TLS_RSA_WITH_IDEA_CBC_SHA", "TLS_RSA_WITH_SEED_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"]
insecureCipherList = ["TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "TLS_DH_anon_WITH_AES_128_GCM_SHA256", "TLS_DH_anon_WITH_AES_256_CBC_SHA", "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "TLS_DH_anon_WITH_AES_256_GCM_SHA384", "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", "TLS_DH_anon_WITH_DES_CBC_SHA", "TLS_DH_anon_WITH_RC4_128_MD5", "TLS_DH_anon_WITH_SEED_CBC_SHA", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_DSS_WITH_DES_CBC_SHA", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA", "TLS_DHE_PSK_WITH_NULL_SHA", "TLS_DHE_PSK_WITH_NULL_SHA256", "TLS_DHE_PSK_WITH_NULL_SHA384", "TLS_DHE_PSK_WITH_RC4_128_SHA", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_DH_RSA_WITH_DES_CBC_SHA", "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "TLS_ECDH_anon_WITH_NULL_SHA", "TLS_ECDH_anon_WITH_RC4_128_SHA", "TLS_ECDH_ECDSA_WITH_NULL_SHA", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_PSK_WITH_NULL_SHA", "TLS_ECDHE_PSK_WITH_NULL_SHA256", "TLS_ECDHE_PSK_WITH_NULL_SHA384", "TLS_ECDHE_PSK_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_NULL_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDH_RSA_WITH_NULL_SHA", "TLS_ECDH_RSA_WITH_RC4_128_SHA", "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "TLS_KRB5_WITH_DES_CBC_MD5", "TLS_KRB5_WITH_DES_CBC_SHA", "TLS_KRB5_WITH_IDEA_CBC_MD5", "TLS_KRB5_WITH_RC4_128_MD5", "TLS_KRB5_WITH_RC4_128_SHA", "TLS_NULL_WITH_NULL_NULL", "TLS_PSK_WITH_NULL_SHA", "TLS_PSK_WITH_NULL_SHA256", "TLS_PSK_WITH_NULL_SHA384", "TLS_PSK_WITH_RC4_128_SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_PSK_WITH_NULL_SHA", "TLS_RSA_PSK_WITH_NULL_SHA256", "TLS_RSA_PSK_WITH_NULL_SHA384", "TLS_RSA_PSK_WITH_RC4_128_SHA", "TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_WITH_NULL_MD5", "TLS_RSA_WITH_NULL_SHA", "TLS_RSA_WITH_NULL_SHA256", "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA", "TLS_SHA256_SHA256", "TLS_SHA384_SHA384", "TLS_SM4_CCM_SM3", "TLS_SM4_GCM_SM3"]

if (str(tlsCipherName).replace("-", "_")).upper() in weakCipherList:
    vulnWeakCipher = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if (str(tlsCipherName).replace("-", "_")).upper() in insecureCipherList:
    vulnInsecureCipher = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'

if "@gmail" in str(domainWhoisEmails) or "@hotmail" in str(domainWhoisEmails) or "@live" in str(domainWhoisEmails):
    vulnWhoisPersonalEmail = '<b><FONT COLOR="#ff0000">Vulnerable</FONT></b>'


htmlBodyVulns = '''
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
''' + htmlCss + f'''
</head>
<body>

<div class="header">
  <h2>Domain Vulnerability Report</h2>
  <h5>{domain}</h5>
</div>

<div class="row">
  <div class="leftcolumn">
    <div class="card">
      <h2>Vulnerabilities</h2>
      <h5>Vulnerabilities identified across the external attack surface:</h5>
      <table>
        <tr>
            <th><b>Vulnerability Name</b></td>
            <th><b>Category</b></td>
            <th><b>Severity</b></td>
            <th><b>Status</b></td>
          </tr>
          <tr>
            <td>SPF Not Configured</td>
            <td>Email Security</td>
            <td>Critical</td>
            <td>{vulnNoSpf}</td>
          </tr>
          <tr>
            <td>DMARC Not Configured</td>
            <td>Email Security</td>
            <td>High</td>
            <td>{vulnNoDmarc}</td>
          </tr>     
          </tr> 
            <td>Protocol Vulnerabilities on IP</td>
            <td>CVEs</td>
            <td>High</td>
            <td>{vulnCve}</td>
          </tr> 
          <tr>
            <td>SMB Port (445) Open</td>
            <td>Open Ports</td>
            <td>Critical</td>
            <td>{vulnPort445}</td>
          </tr>
          <tr>
            <td>RDP Port (3389) Open</td>
            <td>Open Ports</td>
            <td>Critical</td>
            <td>{vulnPort3389}</td>
          </tr>
          <tr>
            <td>NetBIOS Port (137) Open</td>
            <td>Open Ports</td>
            <td>Medium</td>
            <td>{vulnPort137}</td>
          </tr>   
          <tr>
            <td>NetBIOS Port (139) Open</td>
            <td>Open Ports</td>
            <td>Medium</td>
            <td>{vulnPort139}</td>
          </tr>   
          <tr>
            <td>FTP Port (20) Open</td>
            <td>Open Ports</td>
            <td>Medium</td>
            <td>{vulnPort20}</td>
          </tr>   
          <tr>
            <td>FTP Port (21) Open</td>
            <td>Open Ports</td>
            <td>Medium</td>
            <td>{vulnPort21}</td>
          </tr>  
          <tr>
            <td>SSH Port (22) Open</td>
            <td>Open Ports</td>
            <td>High</td>
            <td>{vulnPort22}</td>
          </tr>  
          <tr>
            <td>Telnet Port (23) Open</td>
            <td>Open Ports</td>
            <td>Medium</td>
            <td>{vulnPort23}</td>
          </tr>  
          <tr>
            <td>MySQL Port (3306) Open</td>
            <td>Open Ports</td>
            <td>Medium</td>
            <td>{vulnPort3306}</td>
          </tr>  
          <tr>
            <td>Website Malicious Indicators</td>
            <td>Website Reputation</td>
            <td>Critical</td>
            <td>{vulnMaliciousWebsite}</td>
          </tr>  
          <tr>
            <td>Website Suspicious Indicators</td>
            <td>Website Reputation</td>
            <td>High</td>
            <td>{vulnSuspiciousWebsite}</td>
          </tr>
          <tr>
            <td>Server Version Exposed</td>
            <td>Website Security</td>
            <td>High</td>
            <td>{vulnWebsiteServerVersionExposed}</td>
          </tr>
          <tr>
            <td>X-Powered-By Version Exposed</td>
            <td>Website Security</td>
            <td>High</td>
            <td>{vulnWebsiteXPoweredByExposed}</td>
          </tr>
          <tr>
            <td>Strict-Transport-Security Not Configured</td>
            <td>Website Security</td>
            <td>Medium</td>
            <td>{vulnWebsiteNoSTS}</td>
          </tr>
          <tr>
            <td>Content-Security-Policy Not Configured</td>
            <td>Website Security</td>
            <td>High</td>
            <td>{vulnWebsiteNoCSP}</td>
          </tr>
          <tr>
            <td>X-Frame-Options Not Configured</td>
            <td>Website Security</td>
            <td>Low</td>
            <td>{vulnWebsiteNoXFrameOptions}</td>
          </tr>
          <tr>
            <td>X-Content-Type Not Configured</td>
            <td>Website Security</td>
            <td>Low</td>
            <td>{vulnWebsiteNoXContentType}</td>
          </tr>
          <tr>
            <td>X-XSS-Protection Not Configured</td>
            <td>Website Security</td>
            <td>Low</td>
            <td>{vulnWebsiteNoXXSSProtection}</td>
          </tr>
          <tr>
            <td>Referrer-Policy Not Configured</td>
            <td>Website Security</td>
            <td>Low</td>
            <td>{vulnWebsiteNoReferrerPolicy}</td>
          </tr>
          <tr>
            <td>Weak SSLv3 Protocol in Use</td>
            <td>Website Security</td>
            <td>Critical</td>
            <td>{vulnSSLv3Usage}</td>
          </tr>
          <tr>
            <td>Weak TLSv1 Protocol in Use</td>
            <td>Website Security</td>
            <td>Medium</td>
            <td>{vulnTLSv1Usage}</td>
          </tr>
          <tr>
            <td>Weak TLSv1.1 Protocol in Use</td>
            <td>Website Security</td>
            <td>Medium</td>
            <td>{vulnTLSv1_1Usage}</td>
          </tr>
          <tr>
            <td>Weak Cipher in Use</td>
            <td>Website Security</td>
            <td>Medium</td>
            <td>{vulnWeakCipher}</td>
          </tr>
          <tr>
            <td>Insecure Cipher in Use</td>
            <td>Website Security</td>
            <td>High</td>
            <td>{vulnInsecureCipher}</td>
          </tr>
          <tr>
            <td>Exposed Personal Email Configured to Domain WHOIS</td>
            <td>Website Security</td>
            <td>Low</td>
            <td>{vulnWhoisPersonalEmail}</td>
          </tr>
        </table>
      </div>
  </div>
   

  <div class="rightcolumn">
  
    
    <div class="card">
      <h3>Domain Analysis Report:</h3>
      <p><a href="./Report.html">Link to Domain Analysis Report</a></p>
    </div>
  
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
</div>

<div class="footer">
  <h2>Created by SMH-404</h2>
</div>

</body>
</html>
'''

file = open("VulnReport.html", "w")
file.writelines(htmlBodyVulns)

print("Vulnerability Report Created!")
