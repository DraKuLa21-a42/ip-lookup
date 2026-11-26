/**
 * target.js — нормалізація вводу в рядку пошуку.
 * Дзеркало parse_target() з app.py: приймає URL, host:port, [IPv6]:port,
 * user@host, mailto:, лапки, пробіли тощо й повертає { host, port }.
 *
 *   https://mail.google.com/mail/u/0/#inbox → { host: 'mail.google.com', port: null }
 *   1.1.1.1:53                              → { host: '1.1.1.1',         port: 53 }
 *   [2001:db8::1]:443                       → { host: '2001:db8::1',     port: 443 }
 *
 * IDN (кирилиця) лишається як є для відображення — у punycode його переводить бекенд.
 */
export function parseTarget(raw) {
  let s = String(raw ?? '').trim().replace(/^["'<>`]+|["'<>`]+$/g, '').trim();
  if (!s) return { host: '', port: null };

  s = s.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '');   // будь-яка схема://
  s = s.replace(/^mailto:/i, '');
  s = s.split(/[/?#\s\\]/, 1)[0];                     // шлях, query, fragment
  if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);  // userinfo

  let port = null;
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end !== -1) {
      const rest = s.slice(end + 1);
      s = s.slice(1, end);
      if (/^:\d+$/.test(rest)) port = Number(rest.slice(1));
    } else {
      s = s.replace(/^\[+/, '');
    }
  } else if ((s.match(/:/g) || []).length === 1) {
    const [h, p] = s.split(':');
    s = h;
    if (/^\d+$/.test(p)) port = Number(p);
  }
  // ≥2 двокрапок без дужок — голий IPv6, не чіпаємо

  s = s.split('%', 1)[0].replace(/\.+$/, '').toLowerCase();
  if (/^as\d+$/.test(s)) s = s.toUpperCase();
  if (port !== null && (port < 1 || port > 65535)) port = null;

  return { host: s, port };
}
