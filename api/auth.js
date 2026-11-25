/* CASARIO admin sign-in (Vercel Node function). Credentials come from environment variables:
   ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_SESSION_SECRET (16+ random characters).
   Nothing secret is stored in the repo or sent to the browser. Session = signed, HttpOnly cookie. */
const crypto = require('crypto');
const COOKIE = 'casario_admin', TTL = 8 * 3600, MAX_FAILS = 5, WINDOW_MS = 10 * 60 * 1000;
const fails = new Map(); // best-effort per-instance throttle

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const hmac = (p, k) => crypto.createHmac('sha256', k).update(p).digest('base64url');
const mint = (email, k) => { const p = Buffer.from(JSON.stringify({ e: email, exp: Math.floor(Date.now() / 1000) + TTL })).toString('base64url'); return p + '.' + hmac(p, k); };
function check(tok, k) {
  if (!tok || tok.indexOf('.') < 1) return null;
  const [p, s] = tok.split('.'); const e = hmac(p, k);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() / 1000 ? o : null; } catch (_) { return null; }
}
const cookieOf = req => { const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(COOKIE + '=')); return m ? m.slice(COOKIE.length + 1) : ''; };
const send = (res, code, obj, extra) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); if (extra) res.setHeader('Set-Cookie', extra); res.end(JSON.stringify(obj)); };
const readJson = req => new Promise(r => { if (req.body !== undefined) return r(typeof req.body === 'string' ? safe(req.body) : req.body || {}); let d = ''; req.on('data', c => { d += c; if (d.length > 5000) req.destroy(); }); req.on('end', () => r(safe(d))); req.on('error', () => r({})); });
const safe = s => { try { return JSON.parse(s) || {}; } catch (_) { return {}; } };
const sameOrigin = req => { const o = req.headers.origin; if (!o) return true; try { return new URL(o).host === req.headers.host; } catch (_) { return false; } };

module.exports = async (req, res) => {
  const { ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_SESSION_SECRET } = process.env;
  const url = new URL(req.url, 'http://x'), a = url.searchParams.get('a');
  const secure = (req.headers['x-forwarded-proto'] === 'https') ? '; Secure' : '';
  const base = `${COOKIE}=%s; HttpOnly; SameSite=Strict; Path=/${secure}`;
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SESSION_SECRET || ADMIN_SESSION_SECRET.length < 16) return send(res, 503, { error: 'not_configured' });

  if (a === 'session' && req.method === 'GET') {
    const s = check(cookieOf(req), ADMIN_SESSION_SECRET);
    return s ? send(res, 200, { ok: true, email: s.e }) : send(res, 401, { ok: false });
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  if (!sameOrigin(req)) return send(res, 403, { error: 'origin' });

  if (a === 'logout') return send(res, 200, { ok: true }, base.replace('%s', '') + '; Max-Age=0');

  if (a === 'login') {
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim(), now = Date.now();
    const f = (fails.get(ip) || []).filter(t => now - t < WINDOW_MS);
    if (f.length >= MAX_FAILS) return send(res, 429, { error: 'too_many' });
    const b = await readJson(req);
    const ok = same(String(b.email || '').trim().toLowerCase(), ADMIN_EMAIL.trim().toLowerCase()) & same(b.password || '', ADMIN_PASSWORD);
    if (!ok) { f.push(now); fails.set(ip, f); await new Promise(r => setTimeout(r, 500)); return send(res, 401, { error: 'invalid' }); }
    fails.delete(ip);
    return send(res, 200, { ok: true }, base.replace('%s', mint(ADMIN_EMAIL.trim().toLowerCase(), ADMIN_SESSION_SECRET)) + `; Max-Age=${TTL}`);
  }
  return send(res, 404, { error: 'unknown' });
};
