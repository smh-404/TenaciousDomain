import whois
import dns.resolver
import json
from crtsh import crtshAPI
from shodan import Shodan


def getInput():
    domain = input("Enter a domain to search:\n")
    return domain


def getWhois(domain):
    print("\n\nGetting WHOIS information")
    domainWhois = whois.whois(domain)  # 👉️ Get Domain Info
    return domainWhois


def getDns(domain):
    print("\n\nGetting DNS information")

    # Getting the A record (IPv4 address)
    aRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'A')
        for row in response:
            if aRecord == "":
                aRecord = row.to_text()
            else:
                aRecord = aRecord + ", " + row.to_text()
    except:
        aRecord = "not found"

    # Getting the AAAA record (IPv6 address)
    aaaaRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'AAAA')
        for row in response:
            if aaaaRecord == "":
                aaaaRecord = row.to_text()
            else:
                aaaaRecord = aaaaRecord + ", " + row.to_text()
    except:
        aaaaRecord = "not found"

    # Getting the NS record (name servers)
    nsRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'NS')
        for row in response:
            if nsRecord == "":
                nsRecord = row.to_text()
            else:
                nsRecord = nsRecord + ", " + row.to_text()
    except:
        nsRecord = "not found"

    # Getting the MX record (mail servers)
    mxRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'MX')
        for row in response:
            if mxRecord == "":
                mxRecord = row.to_text()
            else:
                mxRecord = mxRecord + ", " + row.to_text()
    except:
        mxRecord = "not found"

    # Getting the SOA record (Start of Authority)
    soaRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'SOA')
        for row in response:
            if soaRecord == "":
                soaRecord = row.to_text()
            else:
                soaRecord = soaRecord + ", " + row.to_text()
    except:
        soaRecord = "not found"

    # Getting the TXT and SPF record (DNS-zone text and Sender Policy Framework)
    txtRecord = ""
    spfRecord = ""
    try:
        response = dns.resolver.resolve(domain, 'TXT')
        for row in response:
            if "v=spf" not in str(row.to_text()):
                if txtRecord == "":
                    txtRecord = row.to_text()
                else:
                    txtRecord = txtRecord + ", " + row.to_text()
            else:
                if spfRecord == "":
                    spfRecord = row.to_text()
                else:
                    spfRecord = spfRecord + ", " + row.to_text()
    except:
        txtRecord = "not found"
        spfRecord = "not found"

    # Getting the DMARC record (Domain-based Message Authentication, Reporting & Conformance)
    dmarcRecord = ""
    try:
        response = dns.resolver.resolve(("_dmarc." + str(domain)), 'TXT')
        for row in response:
            if dmarcRecord == "":
                dmarcRecord = row.to_text()
            else:
                dmarcRecord = dmarcRecord + ", " + row.to_text()
    except:
        dmarcRecord = "not found"

    domainDns = {"aRecord": aRecord, "aaaaRecord": aaaaRecord, "nsRecord": nsRecord, "mxRecord": mxRecord,
                 "soaRecord": soaRecord, "txtRecord": txtRecord, "spfRecord": spfRecord, "dmarcRecord": dmarcRecord}

    return domainDns


def getCert(domain):
    print("\n\nGetting certificates")
    domainCert = json.dumps(crtshAPI().search(domain))
    return domainCert


def getSubdomains(domain, domainCert):
    subdomainListCrt = []
    print("\n\nGetting subdomains")
    for row in domainCert:
        if row['common_name'].lower() not in subdomainListCrt and "*" not in row['common_name']:
            subdomainListCrt.append(row['common_name'].lower())
        altNames = row['name_value'].split("\n")
        for altName in altNames:
            if altName.lower() not in subdomainListCrt and "*" not in altName:
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


def getOpenPorts(ip):
    api = Shodan('') # ADD YOUR SHODAN API KEY HERE
    shodanResponse = api.host(ip)
    return shodanResponse


domain = getInput()
print("Initiating enrichment process for domain", domain, "...")


domainWhois = getWhois(domain)
print(json.dumps(domainWhois, indent=4, default=str))


domainDns = getDns(domain)
print(json.dumps(domainDns, indent=4, default=str))


domainCert = getCert(domain)
domainCert = json.loads(domainCert)
print(json.dumps(domainCert, indent=4, default=str))


subdomainListCombined = getSubdomains(domain, domainCert)
print(subdomainListCombined)
print("Total of " + str(len(subdomainListCombined)) + " subdomains found.")


shodanIpInfo = getOpenPorts(domainDns['aRecord'])
print(json.dumps(shodanIpInfo, indent=4, default=str))
