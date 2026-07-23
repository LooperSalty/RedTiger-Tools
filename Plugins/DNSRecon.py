# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.
#
# RedTiger plugin: DNS Recon
# Enumerates common DNS records for a domain and optionally brute-forces
# subdomains from a wordlist (or a small built-in list). Uses dnspython.

from Config.Utils import *

RECORD_TYPES         = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
DEFAULT_SUBDOMAINS   = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "dns", "admin",
    "api", "dev", "staging", "test", "portal", "vpn", "remote", "blog", "shop", "cpanel",
    "webdisk", "autodiscover", "m", "mobile", "app", "cdn", "img", "static", "assets", "secure",
    "git", "gitlab", "jenkins", "docker", "db", "database", "mysql", "backup", "cloud", "status",
]
SUBDOMAIN_WORKERS    = 40


def CleanDomain(value):
    value = value.strip().lower()
    if "://" in value: value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value


def QueryRecords(domain, timeout):
    resolver          = dns.resolver.Resolver()
    resolver.timeout  = timeout
    resolver.lifetime = timeout
    results           = {}

    for record_type in RECORD_TYPES:
        try:
            answers               = resolver.resolve(domain, record_type)
            results[record_type]  = sorted(str(rdata).strip() for rdata in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers): results[record_type] = []
        except (dns.exception.Timeout, Exception): results[record_type] = []

    return results


def ResolveSubdomain(subdomain, domain, timeout):
    fqdn              = f"{subdomain}.{domain}"
    resolver          = dns.resolver.Resolver()
    resolver.timeout  = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(fqdn, "A")
        return fqdn, sorted(str(rdata).strip() for rdata in answers)
    except Exception: return None


def LoadWordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            return [line.strip() for line in file if line.strip() and not line.startswith("#")]
    except (FileNotFoundError, PermissionError, OSError):
        ErrorPath()
        return []


def Register():
    return {
        "name"       : "DNS Recon",
        "description": "Enumerate DNS records and brute-force subdomains.",
        "function"   : Run,
        "arguments"  : {
            "target"      : {"required": True,  "type": str,   "help": "Domain target: <domain>"},
            "wordlist"    : {"required": False, "type": str,   "help": "Subdomain wordlist file: <path> (uses a built-in list if omitted)"},
            "dns-timeout" : {"required": False, "type": float, "help": "DNS query timeout in seconds: <timeout>", "default": 3.0},
            "output"      : {"required": False, "action": "store_true", "help": "Creating additional JSON output."},
        },
    }


def Run(target=None, wordlist=None, dns_timeout=None, output=None):
    Title("DNS Recon")

    if not target: target = Input("Domain [-t] -> ")
    domain = CleanDomain(target)
    if not domain or "." not in domain: ErrorTarget()

    if not has_cli_args:
        wordlist    = Input("Subdomain wordlist [-w] (leave empty for the built-in list) -> ").strip() or None
        dns_timeout = Input("DNS timeout [-DT] (default: 3.0) -> ").strip()

    try:
        dns_timeout = float(dns_timeout) if dns_timeout else 3.0
    except (ValueError, TypeError): ErrorTimeout()

    Info(f"Target domain: {white}{domain}")
    Info(f"DNS timeout: {white}{dns_timeout}s")

    # DNS records
    Wait("Querying DNS records..")
    records = QueryRecords(domain, dns_timeout)
    found_any = False
    for record_type in RECORD_TYPES:
        values = records.get(record_type, [])
        if values:
            found_any = True
            for value in values: Add(f"{record_type:<6}{white}{value}")
    if not found_any: Error("No DNS records found.")

    # Subdomains
    subdomains = LoadWordlist(wordlist) if wordlist else list(DEFAULT_SUBDOMAINS)
    Wait(f"Scanning {len(subdomains)} subdomains..")

    live_subdomains = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=SUBDOMAIN_WORKERS) as executor:
        futures = [executor.submit(ResolveSubdomain, sub, domain, dns_timeout) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                fqdn, ips = result
                live_subdomains[fqdn] = ips
                Add(f"{green}{fqdn}{white} -> {', '.join(ips)}")

    Info(f"Live subdomains: {white}{len(live_subdomains)}{red}/{white}{len(subdomains)}")

    json_data = {
        "Parameters": {
            "Domain": domain,
            "DNS timeout": dns_timeout,
            "Wordlist": wordlist if wordlist else "built-in",
        },
        "Records": {rt: records.get(rt, []) for rt in RECORD_TYPES},
        "Subdomains": live_subdomains,
    }

    if output in (True, None): SaveJsonToFile(json_data, f"Result_DNSRecon_{domain}", json_output=output)
    Continue()
    Reset()
