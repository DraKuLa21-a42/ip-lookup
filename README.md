# ip//lookup

Веб-сервіс для аналізу IP-адрес та доменів. Визначає geo-інформацію, виконує DNS-запити, перевіряє SSL-сертифікати, доступність хостів через ICMP та TCP.

## Можливості

- **IP / Домен** — geo-інформація (країна, місто, координати, часовий пояс), ASN та провайдер, зворотний DNS, визначення типу адреси
- **DNS записи** — підтримка 27 типів записів, перевірка DNSSEC
- **SSL** — перевірка сертифікату: термін дії, ланцюжок довіри, SAN, TLS-версія, шифр, відповідність імені хоста
- **Ping** — ICMP ping з RTT статистикою (min/avg/max/mdev) та відсотком втрат
- **TCP** — перевірка портів списком або діапазоном, паралельне сканування до 100 портів
- **WHOIS** — реєстраційна інформація для доменів та IP-адрес
- **RDAP** — структурований аналог WHOIS (RFC 9083) для доменів, IP та ASN
- **Мій IP** — автоматичне визначення IPv4 та IPv6 адреси клієнта

## Вимоги

- Python 3.10+
- GeoLite2 бази даних (City, ASN) від MaxMind у папці `data/`
- `openssl` — для парсингу самопідписаних та прострочених сертифікатів

## Встановлення

```bash
useradd dev
mkdir -p /opt/scripts
cd /opt/scripts
git clone https://github.com/DraKuLa21-a42/ip-lookup.git
cd ip-lookup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
```

Створи `.env` файл:

```env
IPV4_ENDPOINT=https://ip-lookup-v4.example.com/api/myip
DNS_RESOLVER_HOST=1.1.1.1
DNS_RESOLVER_PORT=53
```

> `IPV4_ENDPOINT` — піддомен з тільки `A` записом у DNS. Потрібен для коректного визначення IPv4 адреси клієнта коли основний домен має і `A` і `AAAA`.

> `DNS_RESOLVER_HOST`, `DNS_RESOLVER_PORT` — можливість вказати свій DNS сервер. Якщо не вказано — використовується `8.8.8.8`.

Запуск:

```bash
bash update-geolite.sh # Отримання актуальних geolite баз
ln -s "$PWD/ip-lookup.service" /etc/systemd/system/ip-lookup.service
ln -s "$PWD/nginx/ip-lookup.conf" /etc/nginx/conf.d/ip-lookup.conf # у файлі потрібно вказати свої домени та сертифікат
systemctl daemon-reload
systemctl enable --now ip-lookup
systemctl status ip-lookup
systemctl restart nginx

crontab -u dev -e
'11 2 * * * /bin/bash /opt/scripts/ip-lookup/update-geolite.sh'
```

## DNS налаштування

Для коректного визначення обох адрес клієнта:

| Домен | DNS записи | Призначення |
|---|---|---|
| `ip-lookup.example.com` | `A` + `AAAA` | основний сайт |
| `ip-lookup-v4.example.com` | тільки `A` | визначення IPv4 |

## API

Base URL: `https://ip-lookup.example.com`

Всі відповіді — `application/json`. Rate limit прив'язаний до IP клієнта.

### GET /api/myip

Повертає IP клієнта.

```
GET /api/myip
```

```json
{"ip": "2a03::1", "version": 6}
```

---

### GET /api/query

Універсальний ендпоінт — автоматично визначає IP чи домен.

```
GET /api/query?q=8.8.8.8
GET /api/query?q=github.com
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `q` | так | IP-адреса або домен |

---

### GET /api/lookup

Geo-інформація за IP-адресою.

```
GET /api/lookup?ip=1.1.1.1
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `ip` | так | IPv4 або IPv6 адреса |

---

### GET /api/resolve

Резолвить домен у список IP з geo-інформацією.

```
GET /api/resolve?domain=cloudflare.com
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `domain` | так | Доменне ім'я |

---

### GET /api/dns

DNS-записи домену.

```
GET /api/dns?domain=google.com
GET /api/dns?domain=google.com&type=MX
GET /api/dns?domain=google.com&type=DNSSEC
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `domain` | так | Доменне ім'я |
| `type` | ні | Тип запису. Якщо не вказано — повертаються всі |

Підтримувані типи: `A` `AAAA` `CNAME` `MX` `NS` `TXT` `SOA` `PTR` `SRV` `CAA` `NAPTR` `SSHFP` `TLSA` `DNSKEY` `DS` `CDS` `CDNSKEY` `NSEC` `NSEC3` `HTTPS` `SVCB` `CERT` `HINFO` `LOC` `RP` `AFSDB` + спеціальний `DNSSEC` (перевірка підпису зони).

Ліміт: 30 запитів / 60 сек.

---

### GET /api/ssl

Перевірка SSL/TLS сертифікату хоста.

```
GET /api/ssl?host=github.com
GET /api/ssl?host=example.com&port=8443
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `host` | так | Домен або IP-адреса |
| `port` | ні | TCP-порт. За замовчуванням: `443` |

**Повертає:**

| Поле | Опис |
|---|---|
| `valid` | Загальний результат: сертифікат довірений, не прострочений, ім'я збігається |
| `trusted` | Чи перевірено ланцюжок довіри системними CA |
| `trust_error` | Причина недовіри (якщо є) |
| `name_match` | Відповідність `host` і SAN/CN сертифікату (з підтримкою wildcard) |
| `expired` | `true` якщо сертифікат прострочений |
| `days_left` | Днів до закінчення дії |
| `not_before` / `not_after` | Дати дії сертифікату |
| `common_name` | CN сертифікату |
| `issuer_cn` / `issuer_org` | Інформація про видавця |
| `san` | Список SAN DNS-записів |
| `tls_version` | Версія TLS протоколу (`TLSv1.2`, `TLSv1.3`) |
| `cipher` | Назва активного шифру |
| `key_bits` | Розмір ключа шифру |
| `chain` | Масив з деталями сертифікатів у ланцюжку |

Приклад відповіді:

```json
{
  "host": "github.com",
  "port": 443,
  "valid": true,
  "trusted": true,
  "trust_error": null,
  "name_match": true,
  "expired": false,
  "days_left": 187,
  "not_before": "15 January 2025",
  "not_after": "15 July 2025",
  "common_name": "github.com",
  "issuer_cn": "DigiCert TLS RSA SHA256 2020 CA1",
  "issuer_org": "DigiCert Inc",
  "issuer_country": "US",
  "san": ["github.com", "www.github.com"],
  "san_count": 2,
  "tls_version": "TLSv1.3",
  "cipher": "TLS_AES_128_GCM_SHA256",
  "key_bits": 128,
  "chain": [
    {
      "common_name": "github.com",
      "organization": "GitHub, Inc.",
      "issuer": "DigiCert TLS RSA SHA256 2020 CA1",
      "not_before": "15 January 2025",
      "not_after": "15 July 2025"
    }
  ]
}
```

Ліміт: 10 запитів / 60 сек.

---

### GET /api/ping

ICMP ping до хоста.

```
GET /api/ping?host=8.8.8.8&count=4
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `host` | так | IP або домен |
| `count` | ні | Кількість пакетів, 1–10. За замовчуванням: `4` |

Ліміт: 10 запитів / 60 сек.

---

### GET /api/tcpcheck

Перевірка TCP-портів.

```
GET /api/tcpcheck?host=github.com&ports=22,80,443
GET /api/tcpcheck?host=example.com&ports=8080-8090
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `host` | так | IP або домен |
| `ports` | так | Порти: `80`, `80,443,22` або `8080-8090` (макс. 100) |

Ліміт: 10 запитів / 60 сек.

---

### GET /api/whois

WHOIS-інформація для домену або IP-адреси. Для доменів використовується `python-whois`, для IP — системна команда `whois` із парсингом ключових полів. Контактні дані можуть бути приховані через GDPR/редакцію реєстратора.

```
GET /api/whois?q=github.com
GET /api/whois?q=8.8.8.8
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `q` | так | Доменне ім'я або IP-адреса |

**Повертає для домену:**

| Поле | Тип | Опис |
|---|---|---|
| `type` | string | Завжди `"domain"` |
| `domain` | string | Нормалізована назва домену |
| `registrar` | string \| null | Назва реєстратора |
| `registrar_url` | string \| null | URL реєстратора |
| `whois_server` | string \| null | WHOIS-сервер реєстратора |
| `status` | string \| string[] | Статуси EPP домену |
| `name_servers` | string[] | Список NS-серверів (lower-case, дедупліковані) |
| `created` / `updated` / `expires` | string \| null | Дати реєстрації, оновлення та закінчення (ISO 8601) |
| `dnssec` | string \| null | Статус DNSSEC з WHOIS (наприклад, `unsigned`) |
| `registrant_name` / `registrant_org` | string \| null | Дані власника (можуть бути приховані GDPR) |
| `registrant_country` / `registrant_city` | string \| null | Географія власника |
| `registrant_email` / `admin_email` / `tech_email` | string \| null | Контактні email (часто приховані) |
| `raw` | string | Повний сирий текст WHOIS-відповіді |

**Повертає для IP:**

| Поле | Тип | Опис |
|---|---|---|
| `type` | string | Завжди `"ip"` |
| `ip` | string | Запитана IP-адреса |
| `netname` | string \| null | Назва мережі |
| `netrange` | string \| null | Діапазон адрес мережі |
| `cidr` | string \| null | CIDR-нотація блоку |
| `country` | string \| null | Код країни |
| `org` | string \| null | Організація-власник блоку |
| `abuse_email` | string \| null | Email для репортів зловживань |
| `rir` | string \| null | Регіональний реєстр: `ARIN`, `RIPE`, `APNIC`, `LACNIC`, `AFRINIC` |
| `raw` | string | Повний сирий текст WHOIS-відповіді |

Ліміт: 30 запитів / 60 сек.

---

### GET /api/rdap

RDAP (RFC 9083) — структурований аналог WHOIS для домену, IP або ASN. Сервер автоматично обирає потрібний RDAP-endpoint через IANA bootstrap (`data.iana.org/rdap`) з кешуванням на 1 годину.

```
GET /api/rdap?q=github.com
GET /api/rdap?q=8.8.8.8
GET /api/rdap?q=AS15169
GET /api/rdap?q=15169
```

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `q` | так | Доменне ім'я, IP-адреса або ASN (`AS15169` або `15169`) |

**Повертає для домену:**

| Поле | Тип | Опис |
|---|---|---|
| `type` | string | `"domain"` |
| `domain` | string | LDH-назва домену |
| `handle` | string \| null | Унікальний ідентифікатор об'єкта в реєстрі |
| `status` | string[] | Масив статусів EPP |
| `created` / `updated` / `expires` | string \| null | Дати з events (ISO 8601) |
| `name_servers` | string[] | Авторитативні NS (lower-case) |
| `dnssec_delegation` | boolean \| null | `true` якщо делегування підписане |
| `dnssec_zone` | boolean \| null | `true` якщо зона підписана |
| `entities` | object[] | Контакти: registrant, registrar, abuse тощо |
| `notices` | string[] | Назви правових повідомлень від реєстру |
| `rdap_conformance` | string[] | Профілі RDAP відповіді |
| `raw` | object | Повний JSON від RDAP-сервера |

**Повертає для IP:**

| Поле | Тип | Опис |
|---|---|---|
| `type` | string | `"ip"` |
| `handle` / `name` | string \| null | Ідентифікатор та назва мережевого блоку |
| `type_ip` | string \| null | Тип алокації: `ALLOCATED`, `ASSIGNED` тощо |
| `start_addr` / `end_addr` | string | Початкова та кінцева адреса блоку |
| `cidr` | string[] | CIDR-нотація |
| `country` | string \| null | Код країни реєстрації блоку |
| `parent_handle` | string \| null | Handle батьківського блоку |
| `entities` | object[] | Контакти організації |

**Повертає для ASN:**

| Поле | Тип | Опис |
|---|---|---|
| `type` | string | `"asn"` |
| `asn` | integer | Номер автономної системи |
| `handle` / `name` | string \| null | Ідентифікатор та назва AS |
| `start_asn` / `end_asn` | integer \| null | Діапазон ASN блоку |
| `entities` | object[] | Контакти організації |

Ліміт: 30 запитів / 60 сек.

---

### GET /api/config

Повертає публічну конфігурацію для фронтенду.

```json
{"ipv4_endpoint": "https://ip-lookup-v4.example.com/api/myip"}
```

## Безпека

- SSRF захист — приватні та зарезервовані діапазони заблоковані (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` та інші)
- Валідація символів у іменах хостів
- Rate limiting на всіх ендпоінтах
- Перевірка всіх IP при резолвингу доменів (не тільки першого)
- SSL перевірка розділяє отримання сертифікату і перевірку довіри — навіть прострочені або self-signed сертифікати повністю аналізуються

## Помилки

| Код | Причина |
|---|---|
| `400` | Відсутній або невалідний параметр |
| `403` | Заблокована адреса (SSRF захист) |
| `429` | Перевищено rate limit |

## Залежності

```
flask
geoip2
dnspython
python-whois
python-dotenv
```