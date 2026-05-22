#!/usr/bin/env bash

set -Eeuo pipefail

# ── Налаштування ─────────────────────────────────────────────────────────────

REPO="P3TERX/GeoLite.mmdb"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

TMP_DIR="/tmp/tmp-geolite-update"
TARGET_DIR="./data"

STATE_FILE="${TARGET_DIR}/.geolite_version"

FILES=(
    "GeoLite2-ASN.mmdb"
    "GeoLite2-City.mmdb"
)

# ── Підготовка ───────────────────────────────────────────────────────────────

mkdir -p "$TMP_DIR"
mkdir -p "$TARGET_DIR"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

# ── Отримання останньої версії ───────────────────────────────────────────────

LATEST_TAG=$(curl -fsSL "$API_URL" | jq -r '.tag_name')

if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
    echo "ERROR: Не вдалося отримати версію релізу"
    exit 1
fi

echo "Latest release: $LATEST_TAG"

# ── Перевірка чи вже оновлено ────────────────────────────────────────────────

if [[ -f "$STATE_FILE" ]]; then
    CURRENT_TAG=$(cat "$STATE_FILE")

    if [[ "$CURRENT_TAG" == "$LATEST_TAG" ]]; then
        echo "Already up to date"
        exit 0
    fi
fi

BASE_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}"

# ── Скачування та перевірка ──────────────────────────────────────────────────

for file in "${FILES[@]}"; do

    TMP_FILE="${TMP_DIR}/${file}"

    echo "Downloading ${file}..."

    curl -fL \
        --connect-timeout 10 \
        --retry 3 \
        --retry-delay 2 \
        -o "$TMP_FILE" \
        "${BASE_URL}/${file}"

    # Перевірка що файл існує
    if [[ ! -f "$TMP_FILE" ]]; then
        echo "ERROR: Файл не скачався: $file"
        exit 1
    fi

    # Перевірка що файл не порожній
    if [[ ! -s "$TMP_FILE" ]]; then
        echo "ERROR: Порожній файл: $file"
        exit 1
    fi

    # Перевірка що це не HTML
    MIME=$(file --brief --mime-type "$TMP_FILE")

    if [[ "$MIME" == "text/html" ]]; then
        echo "ERROR: Замість MMDB отримано HTML: $file"
        head -n 20 "$TMP_FILE"
        exit 1
    fi

    # Перевірка magic bytes MaxMind DB
    if ! strings "$TMP_FILE" | grep -q "MaxMind.com"; then
        echo "ERROR: Файл не схожий на MaxMind DB: $file"
        exit 1
    fi

    echo "Validated: $file"

done

# ── Встановлення файлів ──────────────────────────────────────────────────────

for file in "${FILES[@]}"; do

    SRC="${TMP_DIR}/${file}"
    DST="${TARGET_DIR}/${file}"

    echo "Installing ${file}..."

    # Атомарна заміна
    mv "$SRC" "$DST"

    chown "${OWNER}:${GROUP}" "$DST"
    chmod 0644 "$DST"

done

# ── Збереження версії ────────────────────────────────────────────────────────

echo "$LATEST_TAG" > "$STATE_FILE"

echo "Update completed successfully"
