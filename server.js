'use strict';
// Loan Runner server - zero dependencies, Node 16+
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const USERS_FILE = path.join(__dirname, 'users.json');
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_BODY = 1024 * 1024;

/* ---------- users ---------- */
function hash(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verify(pw, stored) {
  const [salt, h] = stored.split(':');
  const a = Buffer.from(h, 'hex');
  const b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function saveUsers(u) { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2)); }
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    saveUsers({
      admin: { role: 'admin', pass: hash(process.env.ADMIN_PASSWORD || 'admin123') },
      user: { role: 'user', pass: hash('user123') }
    });
    console.log('Created users.json  ->  admin/admin123 and user/user123 (CHANGE THESE)');
  }
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}
let users = loadUsers();

/* ---------- sessions & login throttle ---------- */
const sessions = new Map();
const fails = new Map();
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function getSession(req) {
  const t = parseCookies(req).sid;
  const s = t && sessions.get(t);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(t); return null; }
  return { token: t, ...s };
}

/* ---------- helpers ---------- */
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0, data = '';
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('too large')); req.destroy(); return; }
      data += c;
    });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}

/* ---------- API ---------- */
async function api(req, res, url) {
  const route = req.method + ' ' + url.pathname;

  if (route === 'POST /api/login') {
    const ip = req.socket.remoteAddress;
    const f = fails.get(ip);
    if (f && f.n >= 8 && Date.now() - f.t < 5 * 60 * 1000)
      return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const { username, password, mode } = await readJson(req);
    const u = typeof username === 'string' && Object.hasOwn(users, username) ? users[username] : null;
    const good = u && typeof password === 'string' && verify(password, u.pass) && (mode !== 'admin' || u.role === 'admin');
    if (!good) {
      fails.set(ip, { n: (f ? f.n : 0) + 1, t: Date.now() });
      return send(res, 401, { error: mode === 'admin' ? 'Invalid admin credentials' : 'Invalid username or password' });
    }
    fails.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username, role: u.role, exp: Date.now() + SESSION_MS });
    res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}`);
    return send(res, 200, { username, role: u.role });
  }

  const s = getSession(req);
  if (route === 'GET /api/me') return s ? send(res, 200, { username: s.username, role: s.role }) : send(res, 401, { error: 'Not logged in' });
  if (!s) return send(res, 401, { error: 'Not logged in' });

  if (route === 'POST /api/logout') {
    sessions.delete(s.token);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
    return send(res, 200, { ok: true });
  }

  if (route === 'POST /api/users') {
    if (s.role !== 'admin') return send(res, 403, { error: 'Admin only' });
    const { username, password, role } = await readJson(req);
    if (!/^[A-Za-z0-9._-]{3,32}$/.test(username || '')) return send(res, 400, { error: 'Username: 3-32 letters/numbers/._-' });
    if (typeof password !== 'string' || password.length < 6) return send(res, 400, { error: 'Password must be 6+ characters' });
    if (Object.hasOwn(users, username)) return send(res, 409, { error: 'User already exists' });
    users[username] = { role: role === 'admin' ? 'admin' : 'user', pass: hash(password) };
    saveUsers(users);
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: 'Not found' });
}

/* ---------- static files ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) await api(req, res, url);
    else if (req.method === 'GET') serveStatic(req, res, url);
    else { res.writeHead(405); res.end(); }
  } catch (e) {
    if (!res.headersSent) send(res, 400, { error: e.message || 'Bad request' });
    else res.end();
  }
});

server.listen(PORT, () => console.log(`Server running -> http://localhost:${PORT}`));
