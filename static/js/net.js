/**
 * net.js — Ping / TCP port check tab
 */
import { loading, errCard } from './ip.js';

export const PORT_PRESETS = [
  { label: 'Web',     ports: '80,443,8080,8443' },
  { label: 'Mail',    ports: '25,465,587,110,995,143,993' },
  { label: 'SSH',     ports: '22' },
  { label: 'DB',      ports: '3306,5432,6379,27017' },
  { label: 'Загальні',ports: '21,22,23,25,53,80,110,143,443,3389' },
];

// ── Ping ──────────────────────────────────────────────────────────────────

export function doPing(host, count, resultEl) {
  if (!host) return;
  resultEl.innerHTML = loading(`Пінгуємо ${host}…`);
  fetch(`/api/ping?host=${encodeURIComponent(host)}&count=${count}`)
    .then(r => r.json())
    .then(d => renderPing(d, resultEl))
    .catch(err => { resultEl.innerHTML = errCard(err.message); });
}

function renderPing(d, resultEl) {
  if (d.error && !d.output) { resultEl.innerHTML = errCard(d.error); return; }
  const statusColor = d.success ? 'var(--success)' : 'var(--warn)';
  const statusText  = d.success ? '✓ Доступний'   : '✗ Недоступний';
  const loss = d.packet_loss !== null ? d.packet_loss + '%' : '—';
  const rtt  = d.rtt || {};

  resultEl.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="ip-badge">${d.host}</div>
          <div class="country-name" style="color:${statusColor}">${statusText}</div>
        </div>
        <span class="tag" style="background:${d.success ? 'rgba(16,185,129,.15)' : 'rgba(245,158,11,.12)'};color:${statusColor};border-color:${statusColor}40">
          Втрати: ${loss}
        </span>
      </div>
      <div class="ping-stats">
        <div class="ping-stat"><div class="ping-stat-val">${rtt.min ?? '—'}</div><div class="ping-stat-label">min ms</div></div>
        <div class="ping-stat"><div class="ping-stat-val">${rtt.avg ?? '—'}</div><div class="ping-stat-label">avg ms</div></div>
        <div class="ping-stat"><div class="ping-stat-val">${rtt.max ?? '—'}</div><div class="ping-stat-label">max ms</div></div>
        <div class="ping-stat"><div class="ping-stat-val">${rtt.mdev ?? '—'}</div><div class="ping-stat-label">mdev ms</div></div>
      </div>
      <div class="ping-output">${d.output || d.error || ''}</div>
    </div>`;
}

// ── TCP ───────────────────────────────────────────────────────────────────

export function doTcpCheck(host, ports, resultEl) {
  if (!host || !ports) return;
  resultEl.innerHTML = loading('Перевіряємо порти…');
  fetch(`/api/tcpcheck?host=${encodeURIComponent(host)}&ports=${encodeURIComponent(ports)}`)
    .then(r => r.json())
    .then(d => renderTcp(d, resultEl))
    .catch(err => { resultEl.innerHTML = errCard(err.message); });
}

function renderTcp(d, resultEl) {
  if (d.error) { resultEl.innerHTML = errCard(d.error); return; }
  const open = d.results.filter(r => r.open).length;
  const rows = d.results.map(r => `
    <div class="tcp-row">
      <span style="color:var(--muted);font-size:.8rem">${r.port}</span>
      <span class="${r.open ? 'tcp-open' : 'tcp-closed'}">${r.open ? '● open' : '○ closed'}</span>
      <span style="color:var(--muted);font-size:.8rem">${r.service || ''} ${r.error && !r.open ? '<span class="tcp-error">(' + r.error + ')</span>' : ''}</span>
      <span class="tcp-ms">${r.open ? r.ms + ' ms' : ''}</span>
    </div>`).join('');

  resultEl.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="ip-badge">${d.host}</div>
          <div class="country-name">TCP port scan</div>
        </div>
        <span class="tag tag-public">${open} open</span>
      </div>
      <div style="display:grid;grid-template-columns:80px 140px 1fr 80px;padding:8px 24px;border-bottom:1px solid var(--border)">
        <span style="font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)">Порт</span>
        <span style="font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)">Статус</span>
        <span style="font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)">Сервіс</span>
        <span style="font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);text-align:right">RTT</span>
      </div>
      <div class="rows">${rows}</div>
    </div>`;
}
