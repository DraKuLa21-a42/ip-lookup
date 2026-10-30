/**
 * dns.js — DNS records tab
 */
import { loading, errCard } from './ip.js';

export function doDnsLookup(domain, currentDnsType, resultEl) {
  if (!domain) return;
  resultEl.innerHTML = loading('DNS запит…');
  const typeParam = currentDnsType === 'ALL' ? '' : '&type=' + currentDnsType;
  fetch('/api/dns?domain=' + encodeURIComponent(domain) + typeParam)
    .then(r => r.json())
    .then(d => renderDns(d, resultEl))
    .catch(err => { resultEl.innerHTML = errCard(err.message); });
}

function renderDns(d, resultEl) {
  if (d.error) { resultEl.innerHTML = errCard(d.error); return; }
  const items = d.results || [];
  if (!items.length) {
    resultEl.innerHTML = `<div class="card"><div class="state">Записів не знайдено</div></div>`;
    return;
  }

  let html = `
    <div class="card" style="margin-bottom:0;border-radius:10px;overflow:visible;background:transparent;border:none">
      <div style="padding:0 0 10px;font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)">${d.domain}</div>
    </div>`;

  items.forEach(item => {
    const recordsHtml = item.error
      ? `<div class="dns-error">${item.error}</div>`
      : item.records.map(r => `<div class="dns-record">${r}</div>`).join('');
    html += `
      <div class="card">
        <div class="dns-type-header">
          <span class="dns-type-label">${item.type}</span>
          <span style="font-size:.75rem;color:var(--muted)">${item.records?.length || 0} ${item.records?.length === 1 ? 'запис' : 'записи'}</span>
        </div>
        ${recordsHtml}
      </div>`;
  });

  resultEl.innerHTML = html;
}
