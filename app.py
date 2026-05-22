from flask import Flask, request, jsonify, render_template
import geoip2.database
import socket
import ipaddress
import os
import re
import subprocess
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from dotenv import load_dotenv

import dns.resolver
import dns.message
import dns.query
import dns.rdatatype

# ── Кастомний DNS резолвер ────────────────────────────────────────────────────
DNS_RESOLVER_HOST = '127.0.0.1'  # замінити на свій
DNS_RESOLVER_PORT = 53           # замінити на свій порт

load_dotenv()

LOG_DIR = os.path.join(os.path.dirname(__file__), "log")
os.makedirs(LOG_DIR, exist_ok=True)

custom_resolver = dns.resolver.Resolver(configure=False)
custom_resolver.nameservers = [DNS_RESOLVER_HOST]
custom_resolver.port = DNS_RESOLVER_PORT
custom_resolver.lifetime = 5
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# ── Безпека ──────────────────────────────────────────────────────────────────

# Приватні та зарезервовані діапазони (SSRF захист)
BLOCKED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),    # AWS metadata, link-local
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.0.0.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('224.0.0.0/4'),       # Multicast
    ipaddress.ip_network('240.0.0.0/4'),       # Reserved
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

# Дозволені символи в іменах хостів
_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-:\[\]]+$')


def is_blocked_ip(ip_str: str) -> bool:
    """Перевіряє чи IP належить до приватних/зарезервованих мереж."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in BLOCKED_NETWORKS)
    except ValueError:
        return False


def resolve_and_validate(host: str) -> tuple[str | None, str | None]:
    """
    Резолвить хост і перевіряє що жоден IP не є приватним.
    Повертає (ip, None) або (None, error_message).
    """
    if not _HOST_RE.match(host):
        return None, "Недопустимі символи в імені хоста"

    # Якщо вже IP — просто перевіряємо
    try:
        addr = ipaddress.ip_address(host)
        if is_blocked_ip(host):
            return None, "Приватні та зарезервовані адреси заборонені"
        return host, None
    except ValueError:
        pass

    # Домен — резолвимо і перевіряємо всі IP
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
    """Прибирає схему і шлях, залишає тільки хост."""
    host = raw.strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    return host.split("/")[0].split("?")[0]


# ── Rate limiting (in-memory) ─────────────────────────────────────────────────

_rate_lock = threading.Lock()
_rate_store: dict[str, list[float]] = defaultdict(list)

RATE_LIMITS = {
    'default':  (30, 60),
    'ping':     (10, 60),
    'tcpcheck': (10, 60),
    'dns':      (30, 60),
}

# Очищення старих записів кожні N секунд
_CLEANUP_INTERVAL = 300
_last_cleanup = time.monotonic()


def _maybe_cleanup():
    """Видаляє застарілі ключі з rate store (викликається під локом)."""
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
    """Повертає True якщо запит дозволено, False якщо перевищено ліміт."""
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
    """Декоратор для rate limiting."""
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

# Шляхи до баз GeoLite2
CITY_DB = os.path.join("data", "GeoLite2-City.mmdb")
ASN_DB  = os.path.join("data", "GeoLite2-ASN.mmdb")


def get_rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def lookup_ip(ip: str) -> dict:
    result = {"ip": ip, "rdns": get_rdns(ip)}

    # GeoLite2 City
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

    # GeoLite2 ASN
    try:
        with geoip2.database.Reader(ASN_DB) as reader:
            asn = reader.asn(ip)
            result["asn"]     = asn.autonomous_system_number
            result["asn_org"] = asn.autonomous_system_organization
    except Exception as e:
        result["asn_error"] = str(e)

    # Тип адреси
    try:
        addr = ipaddress.ip_address(ip)
        result["version"]     = addr.version
        result["is_private"]  = addr.is_private
        result["is_loopback"] = addr.is_loopback
    except Exception:
        pass

    return result


def resolve_domain(domain: str) -> dict:
    """Резолвить домен у список IP (A та AAAA записи)."""
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
    """Перевіряє, чи це домен (не IP)."""
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
    """Повертає IP адресу з якої прийшов запит."""
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


@app.route("/api/resolve")
@rate_limited('default')
def api_resolve():
    # Виправлено: використовуємо sanitize_host замість ламаного lstrip
    domain = sanitize_host(request.args.get("domain", ""))

    if not domain:
        return jsonify({"error": "Параметр domain не вказано"}), 400

    # SSRF захист — перевіряємо домен перед резолвингом
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

    # SSRF захист
    if is_blocked_ip(ip):
        return jsonify({"error": "Приватні та зарезервовані адреси заборонені"}), 403

    data = lookup_ip(ip)
    return jsonify(data)


@app.route("/api/query")
@rate_limited('default')
def api_query():
    """Універсальний endpoint — сам визначає IP чи домен."""
    q = sanitize_host(request.args.get("q", ""))
    if not q:
        return jsonify({"error": "Параметр q не вказано"}), 400

    if is_domain(q):
        # SSRF захист
        _, err = resolve_and_validate(q)
        if err:
            return jsonify({"error": err}), 403
        return _resolve_and_enrich(q)
    else:
        try:
            ipaddress.ip_address(q)
        except ValueError:
            return jsonify({"error": f"Невалідний запит: {q}"}), 400
        # SSRF захист
        if is_blocked_ip(q):
            return jsonify({"error": "Приватні та зарезервовані адреси заборонені"}), 403
        data = lookup_ip(q)
        data["type"] = "ip"
        return jsonify(data)


def _resolve_and_enrich(domain: str):
    """Внутрішній хелпер: резолвить домен і збагачує geo-даними."""
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
    # Основні
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR',
    # Сервіси
    'SRV', 'CAA', 'NAPTR', 'SSHFP', 'TLSA', 'DNSKEY',
    # DNSSEC
    'DS', 'CDS', 'CDNSKEY', 'NSEC', 'NSEC3',
    # Сучасні
    'HTTPS', 'SVCB', 'CERT',
    # Рідкісні
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
    """Перевіряє чи увімкнено DNSSEC: шукає DNSKEY і DS записи, перевіряє RRSIG."""
    result = {"type": "DNSSEC", "records": []}
    signed = False
    try:
        # Перевіряємо DNSKEY
        dnskey_ans = custom_resolver.resolve(domain, 'DNSKEY')
        key_count = len(list(dnskey_ans))
        result["records"].append(f"DNSKEY: знайдено {key_count} ключ(ів)")

        # Перевіряємо DS у батьківській зоні
        try:
            ds_ans = custom_resolver.resolve(domain, 'DS')
            result["records"].append(f"DS: знайдено {len(list(ds_ans))} запис(ів) у батьківській зоні")
            signed = True
        except Exception:
            result["records"].append("DS: не знайдено в батьківській зоні")

        # Перевіряємо чи A-запис має RRSIG (через DO bit)
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

    # DNSSEC статус тільки при запиті ALL
    if not rtype:
        response["dnssec"] = check_dnssec(domain)

    return jsonify(response)


# ── Ping ──────────────────────────────────────────────────────────────────────

def do_ping(host: str, count: int = 4) -> dict:
    """ICMP ping через системну утиліту."""
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
    """Перевіряє доступність TCP порту."""
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

    # Парсимо порти: "80,443,22" або "80-90" або "22"
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

    # Перевіряємо що всі порти у валідному діапазоні
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

@app.route("/api-docs")
def api_docs():
    return render_template("api.html")

@app.route("/api/config")
def api_config():
    return jsonify({
        "ipv4_endpoint": os.environ.get("IPV4_ENDPOINT", "/api/myip")
    })
    
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
