/**
 * ip.js — IP / Domain lookup tab
 */

// ── Helpers ──────────────────────────────────────────────────────────────

export function countryFlag(iso) {
  if (!iso) return '';
  return `<img src="https://flagcdn.com/20x15/${iso.toLowerCase()}.png"
               srcset="https://flagcdn.com/40x30/${iso.toLowerCase()}.png 2x"
               width="20" height="15" alt="${iso}"
               style="border-radius:2px;vertical-align:middle;margin-right:6px;box-shadow:0 0 0 1px rgba(255,255,255,.1)">`;
}

export function val(v, cls = '') {
  if (v === null || v === undefined || v === '')
    return `<span class="row-value none">—</span>`;
  return `<span class="row-value ${cls}">${v}</span>`;
}

export function loading(msg) {
  return `<div class="card"><div class="state"><div class="spinner"></div>${msg}</div></div>`;
}

export function errCard(msg) {
  return `<div class="card"><div class="state"><div class="error-icon">❌</div>${msg}</div></div>`;
}

// ── IP rows & map ─────────────────────────────────────────────────────────

function ipRowsHtml(d) {
  const flag = countryFlag(d.country_iso);
  const rows = [
    ['rDNS',         d.rdns],
    ['Країна',       d.country ? `${flag} ${d.country}` : null],
    ['Місто',        d.city],
    ['Регіон',       d.region],
    ['Часовий пояс', d.timezone],
    ['Координати',   (d.latitude && d.longitude) ? `${d.latitude}, ${d.longitude}` : null],
    ['ASN',          d.asn ? `AS${d.asn}` : null, 'accent'],
    ['Провайдер',    d.asn_org],
    ['IP версія',    d.version ? `IPv${d.version}` : null],
  ];
  return rows.map(([label, value, cls = '']) => `
    <div class="row">
      <span class="row-label">${label}</span>
      ${val(value, cls)}
    </div>`).join('');
}

function mapHtml(d) {
  const links = [];
  if (d.latitude && d.longitude) {
    const osmHref = `https://www.openstreetmap.org/?mlat=${d.latitude}&mlon=${d.longitude}&zoom=10`;
    links.push(`<a class="map-link" href="${osmHref}" target="_blank" rel="noopener">↗ OpenStreetMap</a>`);
  }
  if (d.ip)  links.push(`<a class="map-link" href="https://bgp.tools/prefix/${d.ip}" target="_blank" rel="noopener">↗ bgp.tools / IP</a>`);
  if (d.asn) links.push(`<a class="map-link" href="https://bgp.tools/as/${d.asn}" target="_blank" rel="noopener">↗ bgp.tools / AS${d.asn}</a>`);
  if (!links.length) return '';
  return `<div class="card-footer">${links.join('')}</div>`;
}

// ── Renderers ─────────────────────────────────────────────────────────────

export function render(d, resultEl) {
  if (d.error) { resultEl.innerHTML = errCard(d.error); return; }
  const flag = countryFlag(d.country_iso);
  const isPrivate = d.is_private;
  const tagHtml = `<span class="tag ${isPrivate ? 'tag-private' : 'tag-public'}">${isPrivate ? 'приватна' : 'публічна'}</span>`;
  resultEl.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="ip-badge">${d.ip}</div>
          <div class="country-name">${d.country || 'Невідома локація'}</div>
        </div>
        <span class="flag">${flag}</span>
        ${tagHtml}
      </div>
      <div class="rows">${ipRowsHtml(d)}</div>
      ${mapHtml(d)}
    </div>`;
}

export function renderDomain(d, resultEl, lookupIp) {
  if (d.error) { resultEl.innerHTML = errCard('Не вдалось резолвити: ' + d.error); return; }
  const results = d.results || [];
  const chipsHtml = results.map(r =>
    `<span class="ip-chip" onclick="lookupIp('${r.ip}')" title="Деталі">${r.ip}</span>`
  ).join('');

  let html = `
    <div class="card">
      <div class="domain-header">
        <div>
          <div class="domain-badge">⬡ ${d.domain}</div>
          <div style="font-size:.78rem;color:var(--muted);margin-top:4px">резолвінг доменного імені</div>
        </div>
        <span class="domain-count">${results.length} IP</span>
      </div>
      <div class="row">
        <span class="row-label">IP адреси</span>
        <span class="row-value">${chipsHtml || '<span class="row-value none">—</span>'}</span>
      </div>
    </div>`;

  results.forEach((r, i) => {
    const flag = countryFlag(r.country_iso);
    const isPrivate = r.is_private;
    const tagHtml = `<span class="tag ${isPrivate ? 'tag-private' : 'tag-public'}">${isPrivate ? 'приватна' : 'публічна'}</span>`;
    html += `
      <div class="card" style="animation-delay:${i * 60}ms">
        <div class="card-header">
          <div>
            <div class="ip-badge">${r.ip}</div>
            <div class="country-name">${r.country || 'Невідома локація'}</div>
          </div>
          <span class="flag">${flag}</span>
          ${tagHtml}
        </div>
        <div class="rows">${ipRowsHtml(r)}</div>
        ${mapHtml(r)}
      </div>`;
  });
  resultEl.innerHTML = html;
}

// ── Fetch ─────────────────────────────────────────────────────────────────

export function doLookup(query, resultEl, lookupIp) {
  if (!query) return;
  resultEl.innerHTML = loading('Запит…');
  fetch('/api/query?q=' + encodeURIComponent(query))
    .then(r => r.json())
    .then(d => {
      if (d.type === 'domain') renderDomain(d, resultEl, lookupIp);
      else render(d, resultEl);
    })
    .catch(err => { resultEl.innerHTML = errCard(err.message); });
}
