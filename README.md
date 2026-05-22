# IP Lookup Service

Сервіс для отримання інформації про IP-адресу: геолокація, провайдер (ASN), rDNS.

## Залежності

- Python 3.9+
- Flask
- geoip2
- Бази даних MaxMind GeoLite2

## Швидкий старт

### 1. Встановити залежності

```bash
pip install -r requirements.txt
```

### 2. Скачати бази GeoLite2

1. Зареєструватись на https://www.maxmind.com/en/geolite2/signup
2. Після входу перейти до: Account → Downloads → GeoLite2 City і GeoLite2 ASN
3. Скачати `.mmdb` файли
4. Покласти їх у папку `data/`:

```
ip-lookup/
└── data/
    ├── GeoLite2-City.mmdb
    └── GeoLite2-ASN.mmdb
```

### 3. Запустити

```bash
python app.py
```

Відкрити http://localhost:5000

## API

```
GET /api/lookup?ip=8.8.8.8
```

Відповідь (JSON):
```json
{
  "ip": "8.8.8.8",
  "rdns": "dns.google",
  "country": "United States",
  "country_iso": "US",
  "continent": "North America",
  "city": "Mountain View",
  "region": "California",
  "timezone": "America/Los_Angeles",
  "latitude": 37.386,
  "longitude": -122.0838,
  "postal": "94035",
  "asn": 15169,
  "asn_org": "GOOGLE",
  "version": 4,
  "is_private": false
}
```

## Автооновлення баз (опціонально)

MaxMind надає утиліту `geoipupdate` для автоматичного оновлення кожного вівторка.

```bash
# Ubuntu/Debian
sudo apt install geoipupdate

# Налаштувати /etc/GeoIP.conf з вашим AccountID та LicenseKey
# Додати до cron:
# 0 3 * * 2 geoipupdate
```
