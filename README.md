# ip//lookup

Веб-сервіс для аналізу IP-адрес та доменів. Визначає geo-інформацію, виконує DNS-запити, перевіряє доступність хостів через ICMP та TCP.

## Можливості

- **IP / Домен** — geo-інформація (країна, місто, координати, часовий пояс), ASN та провайдер, зворотний DNS, визначення типу адреси
- **DNS записи** — підтримка 27 типів записів, перевірка DNSSEC
- **Ping** — ICMP ping з RTT статистикою (min/avg/max/mdev) та відсотком втрат
- **TCP** — перевірка портів списком або діапазоном, паралельне сканування до 100 портів
- **Мій IP** — автоматичне визначення IPv4 та IPv6 адреси клієнта

## Вимоги

- Python 3.10+
- GeoLite2 бази даних (City, ASN) від MaxMind у папці `data/`

## Встановлення

```bash
useradd dev
mkdir -p /opt/scripts
cd /opt/scripts
git clone https://github.com/DraKuLa21-a42/ip-lookup.git
cd ip-lookup
python3 -m venv venv
source venv/bin/acivate
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
> `DNS_RESOLVER_HOST`, `DNS_RESOLVER_PORT` - Можливість вказати свій DNS сервер. Якщо DNS_RESOLVER не буде вказаний, буде використовуватись 8.8.8.8.

Запуск:

```bash
bash update-geolite.sh # Отримання актуальних geolite баз
ln -s "$PWD/ip-lookup.service" /etc/systemd/system/ip-lookup.service
ln -s "$PWD/nginx/ip-lookup.conf" /etc/nginx/conf.d/ip-lookup.conf # у файлі потрібно вказати свої домени та сертифікат
systemctl daemon-reload
systemctl enable --now ip-lookup
systemctl status ip-lookup
systemctl restart nginx 

crontab -e
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
