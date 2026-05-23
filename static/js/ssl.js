/**
 * ssl.js — SSL certificate tab
 */
import { loading, errCard, val } from './ip.js';

export function doSslLookup(host, port, resultEl) {
  if (!host) return;
  resultEl.innerHTML = loading('Перевірка SSL…');
  fetch(`/api/ssl?host=${encodeURIComponent(host)}&port=${port}`)
    .then(r => r.json())
    .then(d => renderSsl(d, resultEl))
    .catch(err => { resultEl.innerHTML = errCard(err.message); });
}

function renderSsl(d, resultEl) {
  if (d.error && !d.common_name) {
    resultEl.innerHTML = errCard(d.error);
    return;
  }

  const statusTag = d.valid
    ? `<span class="tag tag-ok">✓ Дійсний</span>`
    : `<span class="tag tag-danger">✗ Недійсний</span>`;

  const daysColor = d.days_left < 0 ? 'danger' : d.days_left < 14 ? 'warn' : 'ok';
  const daysText  = d.days_left < 0
    ? `прострочений ${Math.abs(d.days_left)} дн. тому`
    : `${d.days_left} дн. залишилось`;

  const sanHtml = d.san && d.san.length
    ? `<div class="ssl-san-list">${d.san.map(s => `<span class="ssl-san">${s}</span>`).join('')}</div>`
    : `<span class="row-value none">—</span>`;

  const summaryHtml = `
    <div class="ssl-summary">
      <div class="ssl-stat">
        <div class="ssl-stat-label">Сертифікат</div>
        <div class="ssl-stat-val ${d.trusted ? 'ok' : 'danger'}">${d.trusted ? '✓ Довірений' : '✗ Не довірений'}</div>
      </div>
      <div class="ssl-stat">
        <div class="ssl-stat-label">Термін дії</div>
        <div class="ssl-stat-val ${daysColor}">${daysText}</div>
      </div>
      <div class="ssl-stat">
        <div class="ssl-stat-label">Ім'я збігається</div>
        <div class="ssl-stat-val ${d.name_match ? 'ok' : 'danger'}">${d.name_match ? '✓ Так' : '✗ Ні'}</div>
      </div>
      <div class="ssl-stat">
        <div class="ssl-stat-label">TLS версія</div>
        <div class="ssl-stat-val neutral">${d.tls_version || '—'}</div>
      </div>
    </div>`;

  const rows = [
    ['Common Name', d.common_name],
    ['Дійсний з',   d.not_before],
    ['Дійсний до',  d.not_after],
    ['Видавець',    d.issuer_cn ? `${d.issuer_cn}${d.issuer_country ? ', ' + d.issuer_country : ''}` : null],
    ['Організація', d.issuer_org],
    ['Шифр',        d.cipher],
    ['Розмір ключа',d.key_bits ? `${d.key_bits} bit` : null],
    ['SAN',         '__san__'],
  ];

  const rowsHtml = rows.map(([label, value]) => `
    <div class="row">
      <span class="row-label">${label}</span>
      ${value === '__san__' ? `<span class="row-value">${sanHtml}</span>` : val(value)}
    </div>`).join('');

  let chainHtml = '';
  if (d.chain && d.chain.length) {
    chainHtml = `
      <div class="ssl-chain">
        <div class="ssl-chain-title">Ланцюжок сертифікатів</div>
        ${d.chain.map((c, i) => `
          <div class="ssl-chain-item">
            <div class="ssl-chain-num">${i + 1}</div>
            <div>
              <div class="ssl-chain-cn">${c.common_name || '—'}</div>
              <div class="ssl-chain-meta">
                ${c.organization ? c.organization + ' · ' : ''}
                Видавець: ${c.issuer || '—'}<br>
                ${c.not_before} → ${c.not_after}
              </div>
            </div>
          </div>`).join('')}
      </div>`;
  }

  resultEl.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="ip-badge">${d.host}</div>
          <div class="country-name">порт ${d.port}</div>
        </div>
        ${statusTag}
      </div>
      ${summaryHtml}
      <div class="rows">${rowsHtml}</div>
      ${chainHtml}
    </div>`;
}
