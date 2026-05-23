from flask import Flask, request, jsonify, render_template
import geoip2.database
import socket
import ipaddress
import os
import re
import ssl
import datetime
import subprocess
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import whois as pywhois   # python-whois
import requests as _req
import json as _json

import dns.resolver
import dns.message
import dns.query
import dns.rdatatype

from dotenv import load_dotenv
load_dotenv()

LOG_DIR = os.path.join(os.path.dirname(__file__), "log")
os.makedirs(LOG_DIR, exist_ok=True)

DNS_RESOLVER_HOST = os.environ.get("DNS_RESOLVER_HOST", "8.8.8.8")
DNS_RESOLVER_PORT = int(os.environ.get("DNS_RESOLVER_PORT", 53))

custom_resolver = dns.resolver.Resolver(configure=False)
custom_resolver.nameservers = [DNS_RESOLVER_HOST]
custom_resolver.port = DNS_RESOLVER_PORT
custom_resolver.lifetime = 5
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# ── Безпека ──────────────────────────────────────────────────────────────────

BLOCKED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.0.0.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-:\[\]]+$')


def is_blocked_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in BLOCKED_NETWORKS)
    except ValueError:
        return False


def resolve_and_validate(host: str) -> tuple[str | None, str | None]:
    if not _HOST_RE.match(host):
        return None, "Недопустимі символи в імені хоста"
    try:
        addr = ipaddress.ip_address(host)
        if is_blocked_ip(host):
            return None, "Приватні та зарезервовані адреси заборонені"
        return host, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            if is_blocked_ip(ip):
                return None, f"Домен резолвиться у заборонену адресу ({ip})"
        return infos[0][4][0], None
    except socket.gaierror:
        return None, f"Не вдалось резолвити хост: {host}"


def sanitize_host(raw: str) -> str:
    host = raw.strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    return host.split("/")[0].split("?")[0]


# ── Rate limiting ─────────────────────────────────────────────────────────────

_rate_lock = threading.Lock()
_rate_store: dict[str, list[float]] = defaultdict(list)

RATE_LIMITS = {
    'default':  (30, 60),
    'ping':     (10, 60),
    'tcpcheck': (10, 60),
    'dns':      (10, 60),
    'ssl':      (10, 60),
    'whois':    (10, 60),
    'rdap':     (10, 60),
}

_CLEANUP_INTERVAL = 300
_last_cleanup = time.monotonic()


def _maybe_cleanup():
    global _last_cleanup
    now = time.monotonic()
    if now - _last_cleanup < _CLEANUP_INTERVAL:
        return
    max_window = max(w for _, w in RATE_LIMITS.values())
    stale = [k for k, ts in _rate_store.items() if not ts or now - ts[-1] > max_window]
    for k in stale:
        del _rate_store[k]
    _last_cleanup = now


def get_client_ip() -> str:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    return ip or "unknown"


def check_rate_limit(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _rate_lock:
        _maybe_cleanup()
        filtered = [t for t in _rate_store[key] if now - t < window]
        if len(filtered) >= limit:
            _rate_store[key] = filtered
            return False
        filtered.append(now)
        _rate_store[key] = filtered
        return True


def rate_limited(endpoint: str):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            limit, window = RATE_LIMITS.get(endpoint, RATE_LIMITS['default'])
            client_ip = get_client_ip()
            key = f"{endpoint}:{client_ip}"
            if not check_rate_limit(key, limit, window):
                return jsonify({"error": f"Забагато запитів. Ліміт: {limit} за {window} сек"}), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ─────────────────────────────────────────────────────────────────────────────

CITY_DB = os.path.join("data", "GeoLite2-City.mmdb")
ASN_DB  = os.path.join("data", "GeoLite2-ASN.mmdb")


def get_rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def lookup_ip(ip: str) -> dict:
    result = {"ip": ip, "rdns": get_rdns(ip)}
    try:
        with geoip2.database.Reader(CITY_DB) as reader:
            city = reader.city(ip)
            result["country"]     = city.country.name
            result["country_iso"] = city.country.iso_code
            result["continent"]   = city.continent.name
            result["city"]        = city.city.name
            result["region"]      = city.subdivisions.most_specific.name
            result["timezone"]    = city.location.time_zone
            result["latitude"]    = city.location.latitude
            result["longitude"]   = city.location.longitude
            result["postal"]      = city.postal.code
    except Exception as e:
        result["geo_error"] = str(e)
    try:
        with geoip2.database.Reader(ASN_DB) as reader:
            asn = reader.asn(ip)
            result["asn"]     = asn.autonomous_system_number
            result["asn_org"] = asn.autonomous_system_organization
    except Exception as e:
        result["asn_error"] = str(e)
    try:
        addr = ipaddress.ip_address(ip)
        result["version"]     = addr.version
        result["is_private"]  = addr.is_private
        result["is_loopback"] = addr.is_loopback
    except Exception:
        pass
    return result


def resolve_domain(domain: str) -> dict:
    result = {"domain": domain, "ips": []}
    try:
        infos = socket.getaddrinfo(domain, None)
        seen: list[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.append(ip)
        result["ips"] = seen
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def is_domain(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/myip")
def api_myip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    try:
        addr = ipaddress.ip_address(ip)
        resp = jsonify({"ip": ip, "version": addr.version})
    except Exception:
        resp = jsonify({"ip": ip, "version": None})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/config")
def api_config():
    return jsonify({
        "ipv4_endpoint": os.environ.get("IPV4_ENDPOINT", "/api/myip"),
        "ipv6_endpoint": os.environ.get("IPV6_ENDPOINT", "/api/myip"),
    })


@app.route("/api/resolve")
@rate_limited('default')
def api_resolve():
    domain = sanitize_host(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "Параметр domain не вказано"}), 400
    _, err = resolve_and_validate(domain)
    if err:
        return jsonify({"error": err}), 403
    data = resolve_domain(domain)
    enriched = []
    for ip in data.get("ips", []):
        info = lookup_ip(ip)
        enriched.append(info)
    data["results"] = enriched
    return jsonify(data)


@app.route("/api/lookup")
@rate_limited('default')
def api_lookup():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "Параметр ip не вказано"}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"Невалідна IP-адреса: {ip}"}), 400
    if is_blocked_ip(ip):
        return jsonify({"error": "Приватні та зарезервовані адреси заборонені"}), 403
    data = lookup_ip(ip)
    return jsonify(data)


@app.route("/api/query")
@rate_limited('default')
def api_query():
    q = sanitize_host(request.args.get("q", ""))
    if not q:
        return jsonify({"error": "Параметр q не вказано"}), 400
    if is_domain(q):
        _, err = resolve_and_validate(q)
        if err:
            return jsonify({"error": err}), 403
        return _resolve_and_enrich(q)
    else:
        try:
            ipaddress.ip_address(q)
        except ValueError:
            return jsonify({"error": f"Невалідний запит: {q}"}), 400
        if is_blocked_ip(q):
            return jsonify({"error": "Приватні та зарезервовані адреси заборонені"}), 403
        data = lookup_ip(q)
        data["type"] = "ip"
        return jsonify(data)


def _resolve_and_enrich(domain: str):
    data = resolve_domain(domain)
    enriched = []
    for ip in data.get("ips", []):
        info = lookup_ip(ip)
        enriched.append(info)
    data["results"] = enriched
    data["type"] = "domain"
    return jsonify(data)


# ── DNS ───────────────────────────────────────────────────────────────────────

DNS_RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR',
    'SRV', 'CAA', 'NAPTR', 'SSHFP', 'TLSA', 'DNSKEY',
    'DS', 'CDS', 'CDNSKEY', 'NSEC', 'NSEC3',
    'HTTPS', 'SVCB', 'CERT',
    'HINFO', 'LOC', 'RP', 'AFSDB',
]


def query_dns(domain: str, rtype: str) -> dict:
    result = {"type": rtype, "records": []}
    try:
        answers = custom_resolver.resolve(domain, rtype)
        for r in answers:
            result["records"].append(r.to_text())
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        result["error"] = "Домен не існує"
    except dns.resolver.Timeout:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_dnssec(domain: str) -> dict:
    result = {"type": "DNSSEC", "records": []}
    signed = False
    try:
        dnskey_ans = custom_resolver.resolve(domain, 'DNSKEY')
        key_count = len(list(dnskey_ans))
        result["records"].append(f"DNSKEY: знайдено {key_count} ключ(ів)")
        try:
            ds_ans = custom_resolver.resolve(domain, 'DS')
            result["records"].append(f"DS: знайдено {len(list(ds_ans))} запис(ів) у батьківській зоні")
            signed = True
        except Exception:
            result["records"].append("DS: не знайдено в батьківській зоні")
        req = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        resp = dns.query.udp(req, DNS_RESOLVER_HOST, port=DNS_RESOLVER_PORT, timeout=5)
        has_rrsig = any(
            r.rdtype == dns.rdatatype.RRSIG
            for rrset in resp.answer
            for r in rrset
        )
        if has_rrsig:
            result["records"].append("RRSIG: підписи присутні у відповіді (DNSSEC активний)")
            signed = True
        else:
            result["records"].append("RRSIG: підписів у відповіді немає")
        result["records"].append(f"Статус: {'✓ DNSSEC увімкнено' if signed else '✗ DNSSEC не активний'}")
    except dns.resolver.NXDOMAIN:
        result["error"] = "Домен не існує"
    except dns.resolver.NoAnswer:
        result["records"].append("DNSKEY: не знайдено")
        result["records"].append("Статус: ✗ DNSSEC не налаштовано")
    except Exception as e:
        result["error"] = str(e)
    return result


@app.route("/api/dns")
@rate_limited('dns')
def api_dns():
    domain = sanitize_host(request.args.get("domain", ""))
    rtype  = request.args.get("type", "").strip().upper()
    if not domain:
        return jsonify({"error": "Параметр domain не вказано"}), 400
    if not _HOST_RE.match(domain):
        return jsonify({"error": "Недопустимі символи в імені домену"}), 400
    if rtype == 'DNSSEC':
        results = [check_dnssec(domain)]
        return jsonify({"domain": domain, "results": results})
    if rtype:
        if rtype not in DNS_RECORD_TYPES:
            return jsonify({"error": f"Невідомий тип запису: {rtype}"}), 400
        types_to_query = [rtype]
    else:
        types_to_query = DNS_RECORD_TYPES
    results = []
    for t in types_to_query:
        r = query_dns(domain, t)
        if r.get("records") or r.get("error"):
            results.append(r)
    response = {"domain": domain, "results": results}
    if not rtype:
        response["dnssec"] = check_dnssec(domain)
    return jsonify(response)


# ── SSL ───────────────────────────────────────────────────────────────────────

def _parse_cert_date(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, '%b %d %H:%M:%S %Y %Z')


def check_ssl(host: str, port: int = 443) -> dict:
    _, err = resolve_and_validate(host)
    if err:
        return {"host": host, "port": port, "valid": False, "error": err}

    # ── Крок 1: отримуємо сирі дані — ніякої верифікації взагалі ──
    try:
        ctx_raw = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_raw.check_hostname = False
        ctx_raw.verify_mode = ssl.CERT_NONE  # тільки NONE гарантує що не впаде

        conn = socket.create_connection((host, port), timeout=10)
        with ctx_raw.wrap_socket(conn, server_hostname=host) as s:
            cert_bin = s.getpeercert(binary_form=True)   # завжди є при CERT_NONE
            cipher   = s.cipher()
            tls_ver  = s.version()
    except Exception as e:
        return {"host": host, "port": port, "valid": False, "error": str(e)}

    if not cert_bin:
        return {"host": host, "port": port, "valid": False, "error": "Сертифікат не отримано"}

    # ── Парсимо через тимчасовий файл (стандартна бібліотека) ──
    # ssl може розпарсити DER якщо завантажити як CA і зробити фейковий verify
    # Найпростіше — decode через openssl subprocess АБО через вбудований match_hostname
    # Але найчистіше — зробити окремий context з CERT_OPTIONAL і CA з системи
    cert = None
    try:
        ctx_parse = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_parse.check_hostname = False
        ctx_parse.verify_mode = ssl.CERT_OPTIONAL
        ctx_parse.load_default_certs()

        conn2 = socket.create_connection((host, port), timeout=10)
        with ctx_parse.wrap_socket(conn2, server_hostname=host) as s2:
            cert = s2.getpeercert(binary_form=False)
    except ssl.SSLError:
        # Сертифікат невалідний (прострочений, self-signed тощо) —
        # але бінарні дані вже є, парсимо вручну через тимчасовий workaround
        cert = None
    except Exception:
        cert = None

    # Якщо CERT_OPTIONAL теж не дав dict (прострочений/недовірений) —
    # парсимо DER вручну через ssl.DER_cert_to_PEM + subproccess openssl
    # АБО через єдиний доступний без залежностей спосіб:
    if not cert:
        cert = _parse_der_cert(cert_bin)   # див. нижче

    if not cert:
        return {"host": host, "port": port, "valid": False, "error": "Не вдалось розпарсити сертифікат"}

    # ── Крок 2: перевіряємо довіреність окремо (незалежно від Кроку 1) ──
    trusted = True
    trust_error = None
    try:
        ctx_v = ssl.create_default_context()
        conn3 = socket.create_connection((host, port), timeout=10)
        with ctx_v.wrap_socket(conn3, server_hostname=host):
            pass
    except ssl.SSLCertVerificationError as e:
        trusted = False
        trust_error = str(e)
    except ssl.SSLError as e:
        trusted = False
        trust_error = str(e)
    except Exception:
        pass

    # ── Парсимо поля ──
    try:
        not_before = _parse_cert_date(cert['notBefore'])
        not_after  = _parse_cert_date(cert['notAfter'])
        now        = datetime.datetime.utcnow()
        days_left  = (not_after - now).days

        subject  = dict(x[0] for x in cert.get('subject', []))
        issuer   = dict(x[0] for x in cert.get('issuer',  []))
        san_list = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']

        name_match = _check_name_match(host, cert)


        chain_info = [{
            "common_name":  subject.get('commonName'),
            "organization": subject.get('organizationName'),
            "issuer":       issuer.get('commonName'),
            "not_before":   not_before.strftime('%d %B %Y'),
            "not_after":    not_after.strftime('%d %B %Y'),
        }]

        return {
            "host":           host,
            "port":           port,
            "valid":          trusted and days_left >= 0 and name_match,
            "trusted":        trusted,
            "trust_error":    trust_error,
            "name_match":     name_match,
            "days_left":      days_left,
            "expired":        days_left < 0,
            "not_before":     not_before.strftime('%d %B %Y'),
            "not_after":      not_after.strftime('%d %B %Y'),
            "common_name":    subject.get('commonName'),
            "issuer_cn":      issuer.get('commonName'),
            "issuer_org":     issuer.get('organizationName'),
            "issuer_country": issuer.get('countryName'),
            "san":            san_list,
            "san_count":      len(san_list),
            "tls_version":    tls_ver,
            "cipher":         cipher[0] if cipher else None,
            "key_bits":       cipher[2] if cipher else None,
            "chain":          chain_info,
        }
    except Exception as e:
        return {"host": host, "port": port, "valid": False, "error": str(e)}

@app.route("/api/ssl")
@rate_limited('ssl')
def api_ssl():
    host = sanitize_host(request.args.get("host", ""))
    port = request.args.get("port", 443)
    if not host:
        return jsonify({"error": "Параметр host не вказано"}), 400
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"error": "Невалідний порт"}), 400
    _, err = resolve_and_validate(host)
    if err:
        return jsonify({"error": err}), 403
    return jsonify(check_ssl(host, port))

import subprocess, tempfile, os

def _check_name_match(host: str, cert: dict) -> bool:
    """
    RFC 6125 сумісна перевірка імені хоста.
    Wildcard *.example.com покриває ТІЛЬКИ один рівень: foo.example.com
    але НЕ покриває: foo.bar.example.com
    """
    def match_hostname(pattern: str, host: str) -> bool:
        if pattern.startswith('*.'):
            # Wildcard: рівно один лейбл зліва, без крапок
            suffix = pattern[2:]  # "badssl.com"
            # Хост повинен мати рівно один лейбл перед suffix
            if not host.endswith('.' + suffix):
                return False
            prefix = host[: -(len(suffix) + 1)]  # те що до ".badssl.com"
            return '.' not in prefix and len(prefix) > 0  # ← ключова перевірка
        else:
            return pattern.lower() == host.lower()

    host = host.lower()

    # Перевіряємо SAN (пріоритет над CN згідно RFC)
    san_entries = cert.get('subjectAltName', [])
    if san_entries:
        return any(
            match_hostname(v.lower(), host)
            for t, v in san_entries if t == 'DNS'
        )

    # Якщо SAN немає — fallback на CN (застаріло, але ще зустрічається)
    subject = dict(x[0] for x in cert.get('subject', []))
    cn = subject.get('commonName', '')
    return match_hostname(cn.lower(), host)

def _parse_der_cert(der_bytes: bytes) -> dict | None:
    """Парсить DER сертифікат у dict сумісний з getpeercert() без зовнішніх бібліотек."""
    try:
        # Конвертуємо DER → PEM
        import base64
        pem = (
            "-----BEGIN CERTIFICATE-----\n" +
            base64.b64encode(der_bytes).decode() +
            "\n-----END CERTIFICATE-----\n"
        )

        # Записуємо у temp файл і парсимо через openssl
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
            f.write(pem)
            tmp = f.name

        result = subprocess.run(
            ["openssl", "x509", "-in", tmp, "-noout", "-text", "-nameopt", "RFC2253"],
            capture_output=True, text=True, timeout=5
        )
        os.unlink(tmp)

        if result.returncode != 0:
            return None

        return _parse_openssl_text(result.stdout)
    except Exception:
        return None


def _parse_openssl_text(text: str) -> dict:
    """Перетворює вивід openssl x509 -text у dict формат getpeercert()."""
    import re

    cert = {}

    # notBefore / notAfter
    nb = re.search(r'Not Before\s*:\s*(.+)', text)
    na = re.search(r'Not After\s*:\s*(.+)', text)
    if nb: cert['notBefore'] = nb.group(1).strip()
    if na: cert['notAfter']  = na.group(1).strip()

    # Subject
    subj = re.search(r'Subject:\s*(.+)', text)
    if subj:
        cert['subject'] = _parse_rfc2253(subj.group(1).strip())

    # Issuer
    issr = re.search(r'Issuer:\s*(.+)', text)
    if issr:
        cert['issuer'] = _parse_rfc2253(issr.group(1).strip())

    # SAN
    san_match = re.search(r'Subject Alternative Name:\s*\n\s*(.+)', text)
    if san_match:
        sans = []
        for entry in san_match.group(1).split(','):
            entry = entry.strip()
            if entry.startswith('DNS:'):
                sans.append(('DNS', entry[4:].strip()))
            elif entry.startswith('IP Address:'):
                sans.append(('IP Address', entry[11:].strip()))
        cert['subjectAltName'] = sans

    return cert


def _parse_rfc2253(s: str) -> tuple:
    """CN=example.com,O=Org → (('commonName','example.com'),('organizationName','Org'))"""
    mapping = {
        'CN': 'commonName', 'O': 'organizationName',
        'C':  'countryName', 'L': 'localityName',
        'ST': 'stateOrProvinceName', 'OU': 'organizationalUnitName',
    }
    result = []
    import re
    for m in re.finditer(r'(\w+)=([^,]+)', s):
        key = mapping.get(m.group(1), m.group(1))
        result.append(((key, m.group(2).strip()),))
    return tuple(result)

# ── Ping ──────────────────────────────────────────────────────────────────────

def do_ping(host: str, count: int = 4) -> dict:
    try:
        proc = subprocess.run(
            ['ping', '-c', str(count), '-W', '2', host],
            capture_output=True, text=True, timeout=15
        )
        output = proc.stdout
        result = {"host": host, "output": output, "success": proc.returncode == 0}
        loss_match = re.search(r'(\d+)% packet loss', output)
        rtt_match  = re.search(r'rtt [^=]+ = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        result["packet_loss"] = int(loss_match.group(1)) if loss_match else None
        if rtt_match:
            result["rtt"] = {
                "min":  float(rtt_match.group(1)),
                "avg":  float(rtt_match.group(2)),
                "max":  float(rtt_match.group(3)),
                "mdev": float(rtt_match.group(4)),
            }
        return result
    except subprocess.TimeoutExpired:
        return {"host": host, "success": False, "error": "Timeout"}
    except Exception as e:
        return {"host": host, "success": False, "error": str(e)}


@app.route("/api/ping")
@rate_limited('ping')
def api_ping():
    host  = sanitize_host(request.args.get("host", ""))
    count = min(int(request.args.get("count", 4)), 10)
    if not host:
        return jsonify({"error": "Параметр host не вказано"}), 400
    _, err = resolve_and_validate(host)
    if err:
        return jsonify({"error": err}), 403
    return jsonify(do_ping(host, count))


# ── TCP check ─────────────────────────────────────────────────────────────────

KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB", 3389: "RDP",
}


def check_tcp_port(host: str, port: int, timeout: float = 1.5) -> dict:
    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ms = round((time.monotonic() - start) * 1000, 2)
        sock.close()
        return {"host": host, "port": port, "open": True, "ms": ms}
    except socket.timeout:
        return {"host": host, "port": port, "open": False, "error": "Timeout"}
    except ConnectionRefusedError:
        return {"host": host, "port": port, "open": False, "error": "Connection refused"}
    except Exception as e:
        return {"host": host, "port": port, "open": False, "error": str(e)}


@app.route("/api/tcpcheck")
@rate_limited('tcpcheck')
def api_tcpcheck():
    host        = sanitize_host(request.args.get("host", ""))
    ports_param = request.args.get("ports", "").strip()
    if not host:
        return jsonify({"error": "Параметр host не вказано"}), 400
    _, err = resolve_and_validate(host)
    if err:
        return jsonify({"error": err}), 403
    ports: list[int] = []
    for part in ports_param.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ports += list(range(int(a), min(int(b) + 1, int(a) + 100)))
            except ValueError:
                return jsonify({"error": f"Невалідний діапазон портів: {part}"}), 400
        elif part.isdigit():
            ports.append(int(part))
        elif part:
            return jsonify({"error": f"Невалідний порт: {part}"}), 400
    if not ports:
        return jsonify({"error": "Вкажіть порти: ?ports=80,443,22 або ?ports=80-90"}), 400
    if len(ports) > 100:
        return jsonify({"error": "Максимум 100 портів за раз"}), 400
    for p in ports:
        if not (1 <= p <= 65535):
            return jsonify({"error": f"Порт поза допустимим діапазоном (1–65535): {p}"}), 400

    def check_one(port: int):
        r = check_tcp_port(host, port)
        r["service"] = KNOWN_PORTS.get(port)
        return port, r

    results_map: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=min(len(ports), 50)) as ex:
        futures = {ex.submit(check_one, p): p for p in ports}
        for future in as_completed(futures):
            try:
                port, r = future.result()
                results_map[port] = r
            except Exception as e:
                port = futures[future]
                results_map[port] = {"host": host, "port": port, "open": False, "error": str(e)}

    results = [results_map[p] for p in ports]
    return jsonify({"host": host, "results": results})


# ═════════════════════════════════════════════════════════════════════════════
# WHOIS
# ═════════════════════════════════════════════════════════════════════════════

def _fmt_date(v):
    """datetime / list[datetime] → ISO-рядок (перша дата)."""
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
        if v is None:
            return None
    return v.isoformat() if hasattr(v, 'isoformat') else str(v)


def _dedup(v):
    """Список → унікальні значення; одне значення → як є."""
    if isinstance(v, list):
        seen, out = set(), []
        for x in v:
            k = str(x).lower()
            if k not in seen:
                seen.add(k)
                out.append(x)
        return out[0] if len(out) == 1 else out
    return v


def do_whois_domain(domain: str) -> dict:
    try:
        w = pywhois.whois(domain)
    except Exception as e:
        return {"error": str(e)}

    if not w or not w.domain_name:
        return {"error": "Не вдалось отримати WHOIS-дані (домен не зареєстрований або недоступний)"}
    
    raw = w.text if hasattr(w, 'text') else None
    if raw:
        raw = "\n".join(
            line for line in raw.splitlines()
            if not line.startswith("% Request from")
        )

    return {
        "type":            "domain",
        "domain":          _dedup(w.domain_name),
        "registrar":       w.registrar,
        "registrar_url":   w.registrar_url if hasattr(w, 'registrar_url') else None,
        "whois_server":    w.whois_server  if hasattr(w, 'whois_server')  else None,
        "status":          _dedup(w.status),
        "name_servers":    _dedup([ns.lower() for ns in w.name_servers] if w.name_servers else []),
        "created":         _fmt_date(w.creation_date),
        "updated":         _fmt_date(w.updated_date),
        "expires":         _fmt_date(w.expiration_date),
        "dnssec":          w.dnssec if hasattr(w, 'dnssec') else None,
        # Контактні дані (якщо не приховані GDPR)
        "registrant_name":    getattr(w, 'name',         None),
        "registrant_org":     getattr(w, 'org',          None),
        "registrant_country": getattr(w, 'country',      None),
        "registrant_city":    getattr(w, 'city',         None),
        "registrant_email":   getattr(w, 'emails',       None),
        "admin_email":        getattr(w, 'admin_email',  None),
        "tech_email":         getattr(w, 'tech_email',   None),
        # Сирий текст (завжди корисний)
        "raw": raw,
        
    }


def do_whois_ip(ip: str) -> dict:
    """WHOIS для IP через системний whois або socket до whois.arin.net."""
    try:
        proc = subprocess.run(
            ['whois', ip],
            capture_output=True, text=True, timeout=15
        )
        raw = proc.stdout.strip()
        if not raw:
            return {"error": "Порожня відповідь WHOIS"}

        result: dict = {"type": "ip", "ip": ip, "raw": raw}

        # Парсимо найпоширеніші поля
        def _field(pattern: str) -> str | None:
            m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
            return m.group(1).strip() if m else None

        result["netname"]    = _field(r'^(?:NetName|netname)\s*:\s*(.+)$')
        result["netrange"]   = _field(r'^(?:NetRange|inetnum)\s*:\s*(.+)$')
        result["cidr"]       = _field(r'^(?:CIDR|route)\s*:\s*(.+)$')
        result["country"]    = _field(r'^(?:Country|country)\s*:\s*(.+)$')
        result["city"]       = _field(r'^(?:City|city)\s*:\s*(.+)$')
        result["org"]        = _field(r'^(?:OrgName|org-name|org)\s*:\s*(.+)$')
        result["descr"]      = _field(r'^(?:descr|OrgTechName)\s*:\s*(.+)$')
        result["abuse_email"] = _field(r'^(?:OrgAbuseEmail|abuse-mailbox)\s*:\s*(.+)$')

        # Визначаємо реєстра (RIR)
        for rir in ('ARIN', 'RIPE', 'APNIC', 'LACNIC', 'AFRINIC'):
            if rir.lower() in raw.lower():
                result["rir"] = rir
                break

        return result
    except subprocess.TimeoutExpired:
        return {"error": "WHOIS timeout"}
    except FileNotFoundError:
        return {"error": "Команда 'whois' не знайдена на сервері"}
    except Exception as e:
        return {"error": str(e)}


@app.route("/api/whois")
@rate_limited('whois')
def api_whois():
    q = sanitize_host(request.args.get("q", ""))
    if not q:
        return jsonify({"error": "Параметр q не вказано"}), 400

    if is_domain(q):
        # Доменне ім'я
        if not _HOST_RE.match(q):
            return jsonify({"error": "Недопустимі символи в імені домену"}), 400
        return jsonify(do_whois_domain(q))
    else:
        # IP-адреса
        try:
            ipaddress.ip_address(q)
        except ValueError:
            return jsonify({"error": f"Невалідний запит: {q}"}), 400
        if is_blocked_ip(q):
            return jsonify({"error": "Приватні та зарезервовані адреси заборонені"}), 403
        return jsonify(do_whois_ip(q))


# ═════════════════════════════════════════════════════════════════════════════
# RDAP  (Registration Data Access Protocol — RFC 9083 / RFC 9224)
# ═════════════════════════════════════════════════════════════════════════════

# Bootstrap-URL для RDAP (IANA офіційні)
RDAP_DOMAIN_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_IPV4_BOOTSTRAP   = "https://data.iana.org/rdap/ipv4.json"
RDAP_IPV6_BOOTSTRAP   = "https://data.iana.org/rdap/ipv6.json"
RDAP_ASN_BOOTSTRAP    = "https://data.iana.org/rdap/asn.json"

# Кеш bootstrap-даних (в пам'яті, на час роботи процесу)
_rdap_bootstrap_cache: dict[str, tuple[float, dict]] = {}
_RDAP_CACHE_TTL = 3600  # 1 година


def _load_bootstrap(url: str) -> dict | None:
    now = time.time()
    if url in _rdap_bootstrap_cache:
        ts, data = _rdap_bootstrap_cache[url]
        if now - ts < _RDAP_CACHE_TTL:
            return data
    try:
        r = _req.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        _rdap_bootstrap_cache[url] = (now, data)
        return data
    except Exception:
        return None


def _find_rdap_server_domain(domain: str) -> str | None:
    """Знаходить RDAP-сервер для TLD через IANA bootstrap."""
    tld = domain.rsplit('.', 1)[-1].lower()
    bootstrap = _load_bootstrap(RDAP_DOMAIN_BOOTSTRAP)
    if not bootstrap:
        # Fallback на загальновідомий сервер
        return f"https://rdap.org/domain/{domain}"
    for entry in bootstrap.get("services", []):
        tlds, urls = entry[0], entry[1]
        if tld in [t.lower() for t in tlds]:
            return urls[0].rstrip('/') + f"/domain/{domain}"
    # Fallback: rdap.org — агрегатор
    return f"https://rdap.org/domain/{domain}"


def _find_rdap_server_ip(ip: str) -> str | None:
    """Знаходить RDAP-сервер для IP через IANA bootstrap."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    url = RDAP_IPV4_BOOTSTRAP if addr.version == 4 else RDAP_IPV6_BOOTSTRAP
    bootstrap = _load_bootstrap(url)
    if not bootstrap:
        return f"https://rdap.org/ip/{ip}"

    for entry in bootstrap.get("services", []):
        prefixes, urls = entry[0], entry[1]
        for prefix in prefixes:
            try:
                if addr in ipaddress.ip_network(prefix, strict=False):
                    return urls[0].rstrip('/') + f"/ip/{ip}"
            except Exception:
                continue
    return f"https://rdap.org/ip/{ip}"


def _find_rdap_server_asn(asn: int) -> str | None:
    """Знаходить RDAP-сервер для ASN через IANA bootstrap."""
    bootstrap = _load_bootstrap(RDAP_ASN_BOOTSTRAP)
    if not bootstrap:
        return f"https://rdap.org/autnum/{asn}"
    for entry in bootstrap.get("services", []):
        ranges, urls = entry[0], entry[1]
        for r in ranges:
            try:
                parts = r.split('-')
                lo = int(parts[0])
                hi = int(parts[1]) if len(parts) > 1 else lo
                if lo <= asn <= hi:
                    return urls[0].rstrip('/') + f"/autnum/{asn}"
            except Exception:
                continue
    return f"https://rdap.org/autnum/{asn}"


def _fetch_rdap(rdap_url: str) -> dict:
    """Виконує HTTP GET до RDAP-сервера, повертає розпарсений JSON."""
    try:
        headers = {"Accept": "application/rdap+json, application/json"}
        r = _req.get(rdap_url, headers=headers, timeout=15, allow_redirects=True)
        r.raise_for_status()
        return r.json()
    except _req.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.reason}"}
    except _req.exceptions.Timeout:
        return {"error": "RDAP timeout"}
    except Exception as e:
        return {"error": str(e)}


# ── RDAP-парсери ──────────────────────────────────────────────────────────────

def _rdap_vcard(vcard_array: list) -> dict:
    """Витягує поля з vCard (jCard формат RFC 7095)."""
    result = {}
    if not vcard_array or len(vcard_array) < 2:
        return result
    for prop in vcard_array[1:]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name, _, _, value = prop[0], prop[1], prop[2], prop[3]
        if name == 'fn':
            result['name'] = value
        elif name == 'org':
            result['org'] = value[0] if isinstance(value, list) else value
        elif name == 'email':
            result.setdefault('emails', []).append(value)
        elif name == 'tel':
            result.setdefault('phones', []).append(value)
        elif name == 'adr':
            # value: [pobox, ext, street, city, region, postal, country]
            if isinstance(value, list):
                result['address'] = {
                    'street': value[2], 'city': value[3],
                    'region': value[4], 'postal': value[5],
                    'country': value[6],
                }
    return result


def _rdap_entities(entities: list) -> list[dict]:
    """Парсить масив entities (registrant, registrar, abuse тощо)."""
    out = []
    for ent in (entities or []):
        roles = ent.get('roles', [])
        e: dict = {"roles": roles}
        vc = ent.get('vcardArray')
        if vc:
            e.update(_rdap_vcard(vc))
        # Рекурсивно — abuse contact може бути у вкладених entities
        sub = ent.get('entities', [])
        if sub:
            e['entities'] = _rdap_entities(sub)
        if ent.get('handle'):
            e['handle'] = ent['handle']
        if ent.get('publicIds'):
            e['publicIds'] = ent['publicIds']
        out.append(e)
    return out


def _rdap_events(events: list) -> dict:
    """eventAction → eventDate."""
    result = {}
    for ev in (events or []):
        action = ev.get('eventAction', '')
        date   = ev.get('eventDate', '')
        if action and date:
            result[action] = date
    return result


def _rdap_notices(notices: list) -> list[str]:
    return [n.get('title', '') for n in (notices or []) if n.get('title')]


def parse_rdap_domain(raw: dict, domain: str) -> dict:
    if 'error' in raw:
        return raw
    events = _rdap_events(raw.get('events', []))
    return {
        "type":         "domain",
        "domain":       raw.get('ldhName', domain),
        "handle":       raw.get('handle'),
        "status":       raw.get('status', []),
        "created":      events.get('registration'),
        "updated":      events.get('last changed'),
        "expires":      events.get('expiration'),
        "transferred":  events.get('last update of RDAP database'),
        "name_servers": [
            ns.get('ldhName', '').lower()
            for ns in raw.get('nameservers', [])
        ],
        "dnssec_delegation": raw.get('secureDNS', {}).get('delegationSigned'),
        "dnssec_zone":       raw.get('secureDNS', {}).get('zoneSigned'),
        "entities":     _rdap_entities(raw.get('entities', [])),
        "notices":      _rdap_notices(raw.get('notices', [])),
        "rdap_conformance": raw.get('rdapConformance', []),
        "links":        [l.get('href') for l in raw.get('links', []) if l.get('rel') == 'related'],
        "raw":          raw,
    }


def parse_rdap_ip(raw: dict, ip: str) -> dict:
    if 'error' in raw:
        return raw
    events = _rdap_events(raw.get('events', []))
    return {
        "type":        "ip",
        "ip":          ip,
        "handle":      raw.get('handle'),
        "name":        raw.get('name'),
        "type_ip":     raw.get('type'),         # ALLOCATED, ASSIGNED тощо
        "start_addr":  raw.get('startAddress'),
        "end_addr":    raw.get('endAddress'),
        "cidr":        [c.get('v4prefix') or c.get('v6prefix') for c in raw.get('cidr0_cidrs', [])],
        "country":     raw.get('country'),
        "parent_handle": raw.get('parentHandle'),
        "status":      raw.get('status', []),
        "created":     events.get('registration'),
        "updated":     events.get('last changed'),
        "entities":    _rdap_entities(raw.get('entities', [])),
        "notices":     _rdap_notices(raw.get('notices', [])),
        "rdap_conformance": raw.get('rdapConformance', []),
        "raw":         raw,
    }


def parse_rdap_asn(raw: dict, asn: int) -> dict:
    if 'error' in raw:
        return raw
    events = _rdap_events(raw.get('events', []))
    return {
        "type":        "asn",
        "asn":         asn,
        "handle":      raw.get('handle'),
        "name":        raw.get('name'),
        "start_asn":   raw.get('startAutnum'),
        "end_asn":     raw.get('endAutnum'),
        "status":      raw.get('status', []),
        "created":     events.get('registration'),
        "updated":     events.get('last changed'),
        "entities":    _rdap_entities(raw.get('entities', [])),
        "notices":     _rdap_notices(raw.get('notices', [])),
        "rdap_conformance": raw.get('rdapConformance', []),
        "raw":         raw,
    }


# ── RDAP endpoint ─────────────────────────────────────────────────────────────

@app.route("/api/rdap")
@rate_limited('rdap')
def api_rdap():
    """
    GET /api/rdap?q=<domain|ip|asn>
    Приклади:
      /api/rdap?q=example.com
      /api/rdap?q=8.8.8.8
      /api/rdap?q=AS15169
      /api/rdap?q=15169        ← теж ASN
    """
    q = sanitize_host(request.args.get("q", ""))
    if not q:
        return jsonify({"error": "Параметр q не вказано"}), 400

    # ── ASN ──
    asn_match = re.fullmatch(r'(?:AS)?(\d+)', q, re.IGNORECASE)
    if asn_match and not re.search(r'\.', q):
        asn = int(asn_match.group(1))
        rdap_url = _find_rdap_server_asn(asn)
        raw = _fetch_rdap(rdap_url)
        return jsonify(parse_rdap_asn(raw, asn))

    # ── IP ──
    try:
        ipaddress.ip_address(q)
        if is_blocked_ip(q):
            return jsonify({"error": "Приватні та зарезервовані адреси заборонені"}), 403
        rdap_url = _find_rdap_server_ip(q)
        raw = _fetch_rdap(rdap_url)
        return jsonify(parse_rdap_ip(raw, q))
    except ValueError:
        pass

    # ── Domain ──
    if not _HOST_RE.match(q):
        return jsonify({"error": "Недопустимі символи в імені"}), 400
    rdap_url = _find_rdap_server_domain(q)
    raw = _fetch_rdap(rdap_url)
    return jsonify(parse_rdap_domain(raw, q))


# ── RDAP пошук (search endpoints — підтримуються не всіма серверами) ──────────

@app.route("/api/rdap/search")
@rate_limited('rdap')
def api_rdap_search():
    """
    GET /api/rdap/search?type=domain&name=example*
    GET /api/rdap/search?type=entity&fn=John*
    GET /api/rdap/search?type=nameserver&name=ns1*
    """
    search_type = request.args.get("type", "domain").lower()
    name        = request.args.get("name", "").strip()
    fn          = request.args.get("fn",   "").strip()   # для entity

    if search_type == "domain":
        if not name:
            return jsonify({"error": "Параметр name не вказано"}), 400
        # Беремо сервер на основі TLD (якщо є)
        tld = name.rstrip('*').rsplit('.', 1)[-1].lower() if '.' in name else ""
        base = "https://rdap.org"
        if tld:
            bootstrap = _load_bootstrap(RDAP_DOMAIN_BOOTSTRAP)
            if bootstrap:
                for entry in bootstrap.get("services", []):
                    if tld in [t.lower() for t in entry[0]]:
                        base = entry[1][0].rstrip('/')
                        break
        url = f"{base}/domains?name={name}"
        raw = _fetch_rdap(url)
        return jsonify({"type": "domain_search", "query": name, "raw": raw})

    elif search_type == "entity":
        query = fn or name
        if not query:
            return jsonify({"error": "Вкажіть параметр fn або name"}), 400
        url = f"https://rdap.org/entities?fn={query}"
        raw = _fetch_rdap(url)
        return jsonify({"type": "entity_search", "query": query, "raw": raw})

    elif search_type == "nameserver":
        if not name:
            return jsonify({"error": "Параметр name не вказано"}), 400
        url = f"https://rdap.org/nameservers?name={name}"
        raw = _fetch_rdap(url)
        return jsonify({"type": "nameserver_search", "query": name, "raw": raw})

    else:
        return jsonify({"error": "type має бути: domain, entity, nameserver"}), 400
    
@app.route("/api-docs")
def api_docs():
    return render_template("api.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)