// ── whois.js  (ES module, підключи як: import './whois.js' у main.js) ────────

// ─── стан ────────────────────────────────────────────────────────────────────

export let whoisMode = 'whois';
export function selectWhoisMode(mode) {
    whoisMode = mode;
    document.getElementById('wm-whois').classList.toggle('active', mode === 'whois');
    document.getElementById('wm-rdap').classList.toggle('active', mode === 'rdap');
}

// ─── головна точка входу ──────────────────────────────────────────────────────
export async function runWhois(query) {
    const q = query.trim();
    if (!q) return;

    const resultEl = document.getElementById('result');
    resultEl.innerHTML = `<div class="loading">Запит WHOIS / RDAP…</div>`;

    try {
        const endpoint = whoisMode === 'rdap' ? '/api/rdap' : '/api/whois';
        const res = await fetch(`${endpoint}?q=${encodeURIComponent(q)}`);
        const data = await res.json();

        if (data.error) {
            resultEl.innerHTML = renderError(data.error);
            return;
        }

        resultEl.innerHTML =
            whoisMode === 'rdap' ? renderRdap(data) : renderWhois(data);

        // підсвічування raw-блоку
        document.querySelectorAll('.raw-toggle').forEach(btn =>
            btn.addEventListener('click', () => {
                const pre = btn.nextElementSibling;
                const open = pre.style.display !== 'none';
                pre.style.display = open ? 'none' : 'block';
                btn.textContent = open ? '▶ Сирі дані' : '▼ Сирі дані';
            })
        );
    } catch (e) {
        resultEl.innerHTML = renderError(e.message);
    }
}

// ─── WHOIS renderer ───────────────────────────────────────────────────────────
function renderWhois(d) {
    const type = d.type === 'ip' ? 'IP WHOIS' : 'Domain WHOIS';

    const rows = d.type === 'domain' ? [
        ['Домен', d.domain],
        ['Реєстратор', d.registrar],
        ['WHOIS-сервер', d.whois_server],
        ['Статус', fmtList(d.status)],
        ['Name servers', fmtList(d.name_servers)],
        ['Створено', fmtDate(d.created)],
        ['Оновлено', fmtDate(d.updated)],
        ['Спливає', fmtDate(d.expires)],
        ['DNSSEC', d.dnssec],
        ['Реєстрант', d.registrant_name],
        ['Організація', d.registrant_org],
        ['Країна', d.registrant_country],
        ['Місто', d.registrant_city],
        ['Email', d.registrant_email],
    ] : [
        ['IP', d.ip],
        ['Мережа', d.netrange],
        ['CIDR', d.cidr],
        ['Net name', d.netname],
        ['Організація', d.org],
        ['Опис', d.descr],
        ['Країна', d.country],
        ['RIR', d.rir],
        ['Abuse email', d.abuse_email],
    ];

    return `
    <div class="whois-card">
      <div class="wcard-header">
        <span class="wcard-badge ${d.type}">${type}</span>
        <span class="wcard-title">${esc(String(d.domain || d.ip || ''))}</span>
      </div>
      <table class="wcard-table">${rows.filter(r => val(r[1])).map(r =>
        `<tr><td class="wk">${r[0]}</td><td class="wv">${esc(String(r[1]))}</td></tr>`
    ).join('')}</table>
      ${d.raw ? `<button class="raw-toggle">▶ Сирі дані</button>
      <pre class="raw-pre" style="display:none">${esc(d.raw)}</pre>` : ''}
    </div>`;
}

// ─── RDAP renderer ────────────────────────────────────────────────────────────
function renderRdap(d) {
    const typeLabels = { domain: 'Domain RDAP', ip: 'IP RDAP', asn: 'ASN RDAP' };
    const header = typeLabels[d.type] || 'RDAP';
    const title = d.domain || d.ip || (d.asn ? `AS${d.asn}` : '') || '';

    const rows = d.type === 'domain' ? [
        ['Домен', d.domain],
        ['Handle', d.handle],
        ['Статус', fmtList(d.status)],
        ['Name servers', fmtList(d.name_servers)],
        ['Створено', fmtDate(d.created)],
        ['Оновлено', fmtDate(d.updated)],
        ['Спливає', fmtDate(d.expires)],
        ['DNSSEC', d.dnssec_delegation != null ? (d.dnssec_delegation ? 'yes' : 'no') : null],
    ] : d.type === 'ip' ? [
        ['IP', d.ip],
        ['Handle', d.handle],
        ['Назва', d.name],
        ['Тип', d.type_ip],
        ['Діапазон', d.start_addr && d.end_addr ? `${d.start_addr} – ${d.end_addr}` : null],
        ['CIDR', fmtList(d.cidr)],
        ['Країна', d.country],
        ['Статус', fmtList(d.status)],
        ['Створено', fmtDate(d.created)],
        ['Оновлено', fmtDate(d.updated)],
    ] : [
        ['ASN', d.asn],
        ['Handle', d.handle],
        ['Назва', d.name],
        ['Діапазон ASN', d.start_asn && d.end_asn ? `${d.start_asn} – ${d.end_asn}` : null],
        ['Статус', fmtList(d.status)],
        ['Створено', fmtDate(d.created)],
        ['Оновлено', fmtDate(d.updated)],
    ];

    const entitiesHtml = renderEntities(d.entities);

    return `
    <div class="whois-card rdap">
      <div class="wcard-header">
        <span class="wcard-badge rdap">${header}</span>
        <span class="wcard-title">${esc(title)}</span>
        <span class="rdap-tag">RFC 9083</span>
      </div>
      <table class="wcard-table">${rows.filter(r => val(r[1])).map(r =>
        `<tr><td class="wk">${r[0]}</td><td class="wv">${esc(String(r[1]))}</td></tr>`
    ).join('')}</table>
      ${entitiesHtml}
      ${d.raw ? `<button class="raw-toggle">▶ Сирі дані (JSON)</button>
      <pre class="raw-pre" style="display:none">${esc(JSON.stringify(d.raw, null, 2))}</pre>` : ''}
    </div>`;
}

function renderEntities(entities = []) {
    if (!entities.length) return '';
    const cards = entities.map(e => {
        const roles = (e.roles || []).join(', ');
        const fields = [
            ['Роль', roles],
            ['Handle', e.handle],
            ['Ім\'я', e.name],
            ['Організація', e.org],
            ['Email', fmtList(e.emails)],
            ['Телефон', fmtList(e.phones)],
            ['Адреса', e.address ? Object.values(e.address).filter(Boolean).join(', ') : null],
        ];
        return `<div class="entity-card">
      <div class="entity-role">${esc(roles) || '—'}</div>
      <table class="wcard-table">${fields.filter(r => val(r[1])).map(r =>
            `<tr><td class="wk">${r[0]}</td><td class="wv">${esc(String(r[1]))}</td></tr>`
        ).join('')}</table>
    </div>`;
    });
    return `<div class="entities-section"><div class="entities-label">Контакти</div>${cards.join('')}</div>`;
}

// ─── helpers ─────────────────────────────────────────────────────────────────
function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function val(v) {
    if (v == null) return false;
    if (Array.isArray(v)) return v.length > 0;
    return String(v).trim() !== '';
}
function fmtList(v) {
    if (!v) return null;
    const arr = Array.isArray(v) ? v : [v];
    return arr.filter(Boolean).join('\n');
}
function fmtDate(s) {
    if (!s) return null;
    const d = new Date(s);
    if (isNaN(d)) return s;
    return d.toLocaleString('uk-UA', { dateStyle: 'medium', timeStyle: 'short' });
}
function renderError(msg) {
    return `<div class="error-box">⚠ ${esc(msg)}</div>`;
}