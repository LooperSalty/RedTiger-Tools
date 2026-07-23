# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.
#
# RedTiger plugin: SSL Certificate Inspector
# Fetches the X.509 certificate presented by a host and displays its details
# (subject, issuer, validity, SAN, signature) plus basic weakness checks.
# Uses the ssl module and the cryptography library (required by pyOpenSSL).

from Config.Utils import *
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

EXPIRY_WARNING_DAYS = 30


def ParseTarget(value, default_port):
    value = value.strip().lower()
    if "://" in value: value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    host, _, port = value.partition(":")
    try: port = int(port) if port else int(default_port)
    except (ValueError, TypeError): port = int(default_port)
    return host, port


def FetchCertificate(host, port, timeout):
    # Verification is deliberately disabled: this is a certificate *inspection* tool, so it must
    # retrieve and display the certificate a host actually presents even when it is self-signed,
    # expired, or from an untrusted CA (exactly the cases worth inspecting). No sensitive data is
    # ever sent over this socket -- we read the presented certificate and close. Do NOT copy this
    # pattern into code that exchanges data with the server.
    context                = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode    = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der      = ssock.getpeercert(binary_form=True)
            tls_ver  = ssock.version()
            cipher   = ssock.cipher()
    return der, tls_ver, cipher


def NameToDict(name):
    result = {}
    for attribute in name:
        result[attribute.oid._name] = attribute.value
    return result


def GetSubjectAltNames(cert):
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [str(entry) for entry in extension.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound: return []


def NotAfterUtc(cert):
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def NotBeforeUtc(cert):
    return getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def Register():
    return {
        "name"       : "SSL Certificate Inspector",
        "description": "Inspect a host's TLS certificate and validity.",
        "function"   : Run,
        "arguments"  : {
            "target"         : {"required": True,  "type": str, "help": "Host target: <host> / <host:port>"},
            "port"           : {"required": False, "type": int, "help": "TLS port: <port>", "default": 443},
            "socket-timeout" : {"required": False, "type": float, "help": "Max socket timeout in seconds: <timeout>", "default": 5.0},
            "output"         : {"required": False, "action": "store_true", "help": "Creating additional JSON output."},
        },
    }


def Run(target=None, port=None, socket_timeout=None, output=None):
    Title("SSL Certificate Inspector")

    if not target: target = Input("Host [-t] -> ")

    if not has_cli_args:
        port           = Input("Port [-p] (default: 443) -> ").strip()
        socket_timeout = Input("Max socket timeout [-ST] (default: 5.0) -> ").strip()

    try: port = int(port) if port else 443
    except (ValueError, TypeError): ErrorPort()
    try: socket_timeout = float(socket_timeout) if socket_timeout else 5.0
    except (ValueError, TypeError): ErrorTimeout()

    host, port = ParseTarget(target, port)
    if not host: ErrorTarget()

    Info(f"Target: {white}{host}:{port}")
    Wait("Fetching certificate..")

    try:
        der, tls_version, cipher = FetchCertificate(host, port, socket_timeout)
    except socket.timeout: ErrorTimeout(); return
    except (socket.gaierror, ConnectionRefusedError, OSError, ssl.SSLError) as error:
        Error(f"Could not retrieve certificate: {white}{error}")
        Continue(); Reset(); return

    cert       = x509.load_der_x509_certificate(der)
    subject    = NameToDict(cert.subject)
    issuer     = NameToDict(cert.issuer)
    san        = GetSubjectAltNames(cert)
    sig_algo   = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    public_key = cert.public_key()
    key_bits   = getattr(public_key, "key_size", None)
    key_type   = type(public_key).__name__.replace("PublicKey", "")
    not_before = NotBeforeUtc(cert)
    not_after  = NotAfterUtc(cert)
    now        = datetime.datetime.now(datetime.timezone.utc)
    days_left  = (not_after - now).days
    expired    = now > not_after

    Add(f"TLS version   {white}{tls_version}")
    Add(f"Cipher        {white}{cipher[0] if cipher else 'unknown'}")
    Add(f"Subject CN    {white}{subject.get('commonName', 'N/A')}")
    Add(f"Issuer        {white}{issuer.get('commonName', issuer.get('organizationName', 'N/A'))}")
    Add(f"Signature     {white}{sig_algo}")
    Add(f"Key size      {white}{key_bits} bits ({key_type})")
    Add(f"Valid from    {white}{not_before}")
    Add(f"Valid until   {white}{not_after}")
    if san: Add(f"SAN           {white}{', '.join(san)}")

    if expired: Error("Certificate is EXPIRED.")
    elif days_left <= EXPIRY_WARNING_DAYS: Error(f"Certificate expires soon: {white}{days_left} day(s) left.")
    else: Add(f"Expiry        {green}OK{white} ({days_left} day(s) left)")

    # Weak-key thresholds are key-type aware: 256-bit RSA is weak, but 256-bit EC (~RSA-3072) is strong.
    weak_key = False
    if key_bits is not None:
        if key_type in ("RSA", "DSA"): weak_key = key_bits < 2048
        elif key_type == "EllipticCurve": weak_key = key_bits < 224

    if sig_algo.lower() in ("md5", "sha1"): Error(f"Weak signature algorithm: {white}{sig_algo}")
    if weak_key: Error(f"Weak key size: {white}{key_bits} bits ({key_type})")

    json_data = {
        "Parameters": {"Host": host, "Port": port, "Socket timeout": socket_timeout},
        "Informations": {
            "TLS version": tls_version,
            "Cipher": cipher[0] if cipher else None,
            "Subject": subject,
            "Issuer": issuer,
            "Signature algorithm": sig_algo,
            "Key size": key_bits,
            "Key type": key_type,
            "Weak key": weak_key,
            "Valid from": str(not_before),
            "Valid until": str(not_after),
            "Days left": days_left,
            "Expired": bool(expired),
            "Subject alternative names": san,
        },
    }

    if output in (True, None): SaveJsonToFile(json_data, f"Result_SSLCertificate_{host}", json_output=output)
    Continue()
    Reset()
