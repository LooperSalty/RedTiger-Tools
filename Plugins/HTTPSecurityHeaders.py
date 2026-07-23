# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.
#
# RedTiger plugin: HTTP Security Headers
# Fetches a URL and grades its HTTP security headers (HSTS, CSP, X-Frame-Options,
# X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Uses requests with
# TLS verification kept ON; certificate problems are reported, not bypassed.

from Config.Utils import *

# (header, weight, recommendation)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", 3, "Enforce HTTPS with a long max-age."),
    ("Content-Security-Policy",   3, "Restrict sources to mitigate XSS/injection."),
    ("X-Frame-Options",           2, "Set DENY or SAMEORIGIN to prevent clickjacking."),
    ("X-Content-Type-Options",    2, "Set 'nosniff' to stop MIME sniffing."),
    ("Referrer-Policy",           1, "Limit referrer leakage (e.g. no-referrer)."),
    ("Permissions-Policy",        1, "Restrict powerful browser features."),
]
# Headers that leak implementation details.
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def NormalizeUrl(value):
    value = value.strip()
    if "://" not in value: value = "https://" + value
    return value


def ResolveUserAgent(useragent):
    if not useragent: return default_useragent
    if str(useragent).strip().lower() == "random":
        try:
            with open(path_file_useragent, "r", encoding="utf-8", errors="ignore") as file:
                agents = [line.strip() for line in file if line.strip()]
            if agents: return random.choice(agents)
        except (FileNotFoundError, OSError): pass
        return default_useragent
    return useragent


def Grade(score, maximum):
    ratio = score / maximum if maximum else 0
    if   ratio >= 0.9: return "A"
    elif ratio >= 0.7: return "B"
    elif ratio >= 0.5: return "C"
    elif ratio >= 0.3: return "D"
    return "F"


def Register():
    return {
        "name"       : "HTTP Security Headers",
        "description": "Analyze and grade a website's HTTP security headers.",
        "function"   : Run,
        "arguments"  : {
            "target"       : {"required": True,  "type": str, "help": "Website target: <URL> / <domain>"},
            "http-timeout" : {"required": False, "type": float, "help": "Max HTTP timeout in seconds: <timeout>", "default": 5.0},
            "http-proxy"   : {"required": False, "type": str, "help": "Set an HTTP proxy: <proxy:port>"},
            "useragent"    : {"required": False, "type": str, "help": "Set a user-agent: random / <useragent>"},
            "output"       : {"required": False, "action": "store_true", "help": "Creating additional JSON output."},
        },
    }


def Run(target=None, http_timeout=None, http_proxy=None, useragent=None, output=None):
    Title("HTTP Security Headers")

    if not target: target = Input("Target [-t] -> ")

    if not has_cli_args:
        http_timeout = Input("Max HTTP timeout [-HT] (default: 5.0) -> ").strip()
        http_proxy   = Input("HTTP proxy [-HP] (default: none) -> ").strip() or None
        useragent    = Input("User-Agent [-u] (random / <useragent>, default: tool) -> ").strip() or None

    try: http_timeout = float(http_timeout) if http_timeout else 5.0
    except (ValueError, TypeError): ErrorTimeout()

    url        = NormalizeUrl(target)
    useragent  = ResolveUserAgent(useragent)
    proxies    = {"http": http_proxy, "https": http_proxy} if http_proxy else None

    Info(f"Target: {white}{url}")
    Wait("Requesting..")

    try:
        response = requests.get(url, timeout=http_timeout, headers={"User-Agent": useragent}, proxies=proxies, allow_redirects=True)
    except requests.exceptions.SSLError:
        Error(f"TLS certificate could not be verified. Use the SSL Certificate Inspector to inspect it, or test the http:// endpoint.")
        Continue(); Reset(); return
    except requests.exceptions.RequestException as error:
        Error(f"Request failed: {white}{error}")
        Continue(); Reset(); return

    headers = {key.lower(): value for key, value in response.headers.items()}
    Info(f"HTTP {white}{response.status_code}{red} - final URL: {white}{response.url}")

    score, maximum = 0, sum(weight for _, weight, _ in SECURITY_HEADERS)
    present, missing = {}, []
    for header, weight, recommendation in SECURITY_HEADERS:
        value = headers.get(header.lower())
        if value:
            score += weight
            present[header] = value
            Add(f"{green}{header}{white}: {value}")
        else:
            missing.append(header)
            Error(f"Missing {header}{red} - {white}{recommendation}")

    disclosures = {header: headers[header.lower()] for header in DISCLOSURE_HEADERS if header.lower() in headers}
    for header, value in disclosures.items(): Info(f"Info disclosure {white}{header}: {value}")

    grade = Grade(score, maximum)
    Info(f"Score: {white}{score}{red}/{white}{maximum}{red} - Grade: {white}{grade}")

    json_data = {
        "Parameters": {
            "URL": url,
            "HTTP timeout": http_timeout,
            "HTTP proxy": http_proxy if http_proxy else None,
            "User-agent": useragent,
        },
        "Informations": {
            "Status code": response.status_code,
            "Final URL": response.url,
            "Score": f"{score}/{maximum}",
            "Grade": grade,
            "Present": present,
            "Missing": missing,
            "Information disclosure": disclosures,
        },
    }

    if output in (True, None): SaveJsonToFile(json_data, f"Result_HTTPSecurityHeaders_{url}", json_output=output)
    Continue()
    Reset()
