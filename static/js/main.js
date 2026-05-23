/**
 * main.js — entry point
 * Orchestrates tabs, "my IP" widget, and routes search actions.
 */
import { doLookup }              from './ip.js';
import { doDnsLookup }           from './dns.js';
import { doSslLookup }           from './ssl.js';
import { doPing, doTcpCheck, PORT_PRESETS } from './net.js';

// ── DOM refs ──────────────────────────────────────────────────────────────
const ipInput  = document.getElementById('ipInput');
const resultEl = document.getElementById('result');

// ── Global helpers (used by inline onclick in rendered HTML) ──────────────
window.lookupIp = window.lookupIpInSearch = (ip) => {
  ipInput.value = ip;
  dispatch();
};

// ── Dispatch ──────────────────────────────────────────────────────────────
function dispatch() {
  const q = ipInput.value.trim();
  if (!q) return;
  switch (currentTab) {
    case 'dns': doDnsLookup(q, currentDnsType, resultEl); break;
    case 'ssl': doSslLookup(q, document.getElementById('ssl-port').value.trim() || '443', resultEl); break;
    case 'net': currentNetMode === 'ping'
      ? doPing(q, document.getElementById('ping-count').value, resultEl)
      : doTcpCheck(q, document.getElementById('ports-input').value.trim(), resultEl);
      break;
    default:    doLookup(q, resultEl, window.lookupIp);
  }
}

ipInput.addEventListener('keydown', e => { if (e.key === 'Enter') dispatch(); });
document.getElementById('search-btn').addEventListener('click', dispatch);

// ── Tabs ──────────────────────────────────────────────────────────────────
let currentTab = 'ip';

const TAB_PLACEHOLDERS = {
  ip:  'IP або домен: 8.8.8.8, google.com',
  dns: 'Домен: google.com, fb.com',
  ssl: 'Домен: google.com, github.com',
  net: 'IP або домен: 8.8.8.8, google.com',
};

window.switchTab = (tab) => {
  currentTab = tab;
  ['ip', 'dns', 'ssl', 'net'].forEach(t =>
    document.getElementById('tab-' + t).classList.toggle('active', t === tab)
  );
  document.getElementById('dns-types').style.display   = tab === 'dns' ? 'flex' : 'none';
  document.getElementById('ssl-panel').style.display   = tab === 'ssl' ? 'block' : 'none';
  document.getElementById('net-panel').style.display   = tab === 'net' ? 'block' : 'none';
  document.getElementById('myipBlock').style.display   = (tab === 'dns' || tab === 'ssl') ? 'none' : '';
  resultEl.innerHTML = '';
  ipInput.placeholder = TAB_PLACEHOLDERS[tab];
};

// ── DNS type selector ─────────────────────────────────────────────────────
let currentDnsType = 'ALL';

window.selectType = (t) => {
  currentDnsType = t;
  document.querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('dt-' + t).classList.add('active');
};

// ── Net mode ──────────────────────────────────────────────────────────────
let currentNetMode = 'ping';

window.selectNetMode = (mode) => {
  currentNetMode = mode;
  document.getElementById('nm-ping').classList.toggle('active', mode === 'ping');
  document.getElementById('nm-tcp').classList.toggle('active', mode === 'tcp');
  document.getElementById('ping-opts').style.display = mode === 'ping' ? 'flex' : 'none';
  document.getElementById('tcp-opts').style.display  = mode === 'tcp'  ? 'block' : 'none';
  resultEl.innerHTML = '';
};

// ── Port presets ──────────────────────────────────────────────────────────
window.applyPreset = (ports) => { document.getElementById('ports-input').value = ports; };

document.getElementById('port-presets').innerHTML = PORT_PRESETS.map(p =>
  `<button class="type-btn" onclick="applyPreset('${p.ports}')">${p.label}</button>`
).join('');

// ── My IP ─────────────────────────────────────────────────────────────────
let myIpv4 = null;

function setMyIp(elId, ip) {
  const el = document.getElementById(elId);
  if (!ip) {
    el.className = 'myip-addr none';
    el.textContent = 'недоступна';
    return;
  }
  el.className = 'myip-addr';
  el.innerHTML = `<a onclick="lookupIpInSearch('${ip}')" title="Пошук">${ip}</a>`;
}

function fetchWithRetry(url, retries = 3, delay = 800) {
  return fetch(url, { cache: 'no-store' })
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .catch(err => {
      if (retries <= 0) throw err;
      return new Promise(res => setTimeout(res, delay))
        .then(() => fetchWithRetry(url, retries - 1, delay));
    });
}

fetch('/api/config')
  .then(r => r.json())
  .then(cfg => {
    fetchWithRetry(cfg.ipv4_endpoint)
      .then(d => { myIpv4 = d.ip; setMyIp('myipV4', d.ip); })
      .catch(() => setMyIp('myipV4', null));
  })
  .catch(() => setMyIp('myipV4', null));

fetchWithRetry('/api/myip')
  .then(d => {
    setTimeout(() => {
      if (d.ip === myIpv4) setMyIp('myipV6', null);
      else setMyIp('myipV6', d.ip);
    }, 100);
  })
  .catch(() => setMyIp('myipV6', null));
