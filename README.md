# ip//lookup

Веб-сервіс для аналізу IP-адрес та доменів. Визначає geo-інформацію, виконує DNS-запити, перевіряє SSL-сертифікати, доступність хостів через ICMP та TCP.

## Можливості

- **IP / Домен** — geo-інформація (країна, місто, координати, часовий пояс), ASN та провайдер, зворотний DNS, визначення типу адреси
- **DNS записи** — підтримка 27 типів записів, перевірка DNSSEC
- **SSL** — перевірка сертифікату: термін дії, ланцюжок довіри, SAN, TLS-версія, шифр, відповідність імені хоста
- **Ping** — ICMP ping з RTT статистикою (min/avg/max/mdev) та відсотком втрат
- **TCP** — перевірка портів списком або діапазоном, паралельне сканування до 100 портів
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
python-dotenv
```