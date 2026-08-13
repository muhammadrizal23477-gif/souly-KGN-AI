/* =========================================================
   SoulyKGN Server
   - Express + better-sqlite3 (data permanen, banyak pengguna)
   - Auth sederhana (username + password, token session)
   - Riwayat chat tersimpan per akun, bisa diakses dari device manapun
   - Proxy panggilan AI (API key aman di server, tidak kelihatan di browser)
   ========================================================= */

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;

/* Konfigurasi provider AI — default pakai Groq (gratis, cepat, kompatibel format OpenAI).
   Bisa diganti ke provider OpenAI-compatible lain (mis. OpenRouter) hanya lewat env var,
   tanpa ubah kode. WAJIB set AI_API_KEY di Render supaya AI bisa merespon. */
const AI_BASE_URL = process.env.AI_BASE_URL || 'https://openrouter.ai/api/v1/chat/completions';
const AI_MODEL = process.env.AI_MODEL || 'Qwen3Reranker8B';
const AI_API_KEY = process.env.AI_API_KEY || '';

const app = express();

/* CORS — supaya tidak muncul "Failed to fetch" kalau halaman dibuka dari
   origin/domain lain (mis. preview lokal, atau frontend dipisah dari
   backend). Aman diaktifkan longgar karena endpoint pakai token header
   sendiri (x-souly-user / x-souly-token), bukan cookie. */
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-souly-user, x-souly-token');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'app')));

/* ---------------- Database ----------------
   PENTING soal data akun tidak ke-reset:
   Secara default file DB disimpan di dalam folder project (soulykgn.db).
   Di Render Free, folder ini TIDAK permanen — setiap kali service di-redeploy
   dari nol (bukan sekadar restart), isi folder project akan dibuat ulang dan
   file .db ikut hilang, sehingga akun & chat kelihatan "ke-reset".

   Supaya akun benar-benar permanen walau redeploy:
   1. Di Render, buka service ini → tab "Disks" → "Add Disk"
      (butuh paket berbayar, mulai ~$7/bulan; Mount Path bebas, mis. /var/data)
   2. Tambahkan Environment Variable:  DB_PATH = /var/data/soulykgn.db
   3. Manual Deploy ulang. Sejak itu database disimpan di disk permanen,
      bukan di folder project, jadi tidak akan ikut ke-reset lagi.

   Kalau env var DB_PATH tidak diisi, server tetap jalan seperti biasa
   (pakai soulykgn.db di folder project) — cukup untuk testing, tapi
   berisiko ke-reset saat redeploy total di paket Free. */
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'soulykgn.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    token TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    theme TEXT NOT NULL,
    mode TEXT NOT NULL,
    title TEXT NOT NULL,
    messages TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_chats_username ON chats(username);
`);

/* ---------------- Helper ---------------- */
function newToken() {
  return crypto.randomBytes(24).toString('hex');
}
function isValidUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_.]{3,20}$/.test(u);
}

/* ---------------- Auth middleware ---------------- */
function requireAuth(req, res, next) {
  const username = req.header('x-souly-user');
  const token = req.header('x-souly-token');
  if (!username || !token) return res.status(401).json({ error: 'Belum login' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || user.token !== token) return res.status(401).json({ error: 'Sesi tidak valid, silakan login lagi' });
  req.username = username;
  next();
}

/* ---------------- Auth routes ---------------- */
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Username 3-20 karakter, huruf/angka/underscore saja' });
  }
  if (!password || String(password).length < 4) {
    return res.status(400).json({ error: 'Password minimal 4 karakter' });
  }
  const existing = db.prepare('SELECT username FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username sudah dipakai, coba yang lain' });

  const hash = bcrypt.hashSync(String(password), 10);
  const token = newToken();
  db.prepare('INSERT INTO users (username, password_hash, token, created_at) VALUES (?,?,?,?)')
    .run(username, hash, token, Date.now());
  res.json({ username, token });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash)) {
    return res.status(401).json({ error: 'Username atau password salah' });
  }
  const token = newToken();
  db.prepare('UPDATE users SET token = ? WHERE username = ?').run(token, username);
  res.json({ username, token });
});

app.post('/api/logout', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET token = NULL WHERE username = ?').run(req.username);
  res.json({ ok: true });
});

/* ---------------- Chat persistence routes ---------------- */
app.get('/api/chats', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM chats WHERE username = ? ORDER BY updated_at DESC').all(req.username);
  const chats = rows.map(r => ({
    id: r.id,
    theme: r.theme,
    mode: r.mode,
    title: r.title,
    messages: JSON.parse(r.messages),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
  res.json({ chats });
});

app.post('/api/chats', requireAuth, (req, res) => {
  const c = req.body || {};
  if (!c.id || !c.theme || !c.mode) return res.status(400).json({ error: 'Data chat tidak lengkap' });

  const existing = db.prepare('SELECT username FROM chats WHERE id = ?').get(c.id);
  if (existing && existing.username !== req.username) {
    return res.status(403).json({ error: 'Chat ini bukan milik akunmu' });
  }

  const now = Date.now();
  const messagesJson = JSON.stringify(c.messages || []);
  if (existing) {
    db.prepare('UPDATE chats SET theme=?, mode=?, title=?, messages=?, updated_at=? WHERE id=?')
      .run(c.theme, c.mode, c.title || c.theme, messagesJson, now, c.id);
  } else {
    db.prepare('INSERT INTO chats (id, username, theme, mode, title, messages, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(c.id, req.username, c.theme, c.mode, c.title || c.theme, messagesJson, c.createdAt || now, now);
  }
  res.json({ ok: true });
});

app.delete('/api/chats/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM chats WHERE id = ? AND username = ?').run(req.params.id, req.username);
  res.json({ ok: true });
});

/* ---------------- AI proxy ---------------- */
const BASE_PERSONA =
  "Kamu adalah SoulyKGN, teman ngobrol AI yang hangat, suportif, dan asik diajak cerita. Selalu balas dalam Bahasa Indonesia yang natural dan mengalir — hindari jawaban template, daftar bernomor, atau nada menggurui kalau nggak perlu. Sesuaikan panjang balasan dengan konteks: kadang cukup satu-dua kalimat, kadang lebih panjang kalau memang perlu. Dengarkan dulu sebelum buru-buru kasih solusi. Kamu tetap AI, bukan pengganti hubungan manusia — kalau user kelihatan butuh bantuan yang lebih serius, dorong dengan lembut supaya dia juga cerita ke orang terdekat atau profesional, tanpa terkesan menggurui.";

const MODE_SYSTEM = {
  ai: "Gaya bicara: sopan, jelas, dan cukup terstruktur seperti asisten yang kompeten dan empatik — tapi tetap hangat dan personal, BUKAN kaku seperti robot customer service atau template. Gunakan Bahasa Indonesia baku yang santun namun tetap mengalir natural.",
  human: "Gaya bicara: santai banget kayak ngobrol sama sahabat deket sendiri. Boleh pakai bahasa gaul sehari-hari anak muda Indonesia secukupnya (contoh: gapapa, btw, wkwk, santuy, anjay) supaya kerasa natural — tapi jangan berlebihan sampai susah dibaca. Pakai 'aku-kamu' atau 'gue-lu' sesuai konteks obrolan. Hindari bahasa baku yang kaku.",
};

const THEME_SYSTEM = {
  kangen: "Topik saat ini: KANGEN. User sedang membawa rasa rindu — bisa ke seseorang, ke masa lalu, ke suatu tempat, atau momen tertentu yang nggak akan terulang. Posisikan dirimu sebagai teman yang menemani perasaan itu, bukan buru-buru bilang 'move on' atau menghakimi kenapa dia masih kepikiran. Ajak dia cerita lebih dalam soal apa yang dirindukan, validasi perasaannya, dan sesekali balas dengan nuansa hangat dan sedikit nostalgic. Nggak perlu terburu-buru kasih solusi.",
  excited: "Topik saat ini: EXCITED. User sedang senang, semangat, atau menantikan sesuatu. Ikut merayakan energinya dengan tulus, jangan datar atau formal, tunjukkan antusiasme yang matching sama dia. Ajukan pertanyaan lanjutan yang bikin dia makin semangat cerita detailnya. Boleh pakai gaya bahasa yang hidup dan ekspresif.",
  vent: "Topik saat ini: LUAPKAN RASA. Ini ruang aman buat user melampiaskan uneg-uneg, kesal, capek, sedih, atau emosi yang menumpuk. Dengarkan dulu tanpa menghakimi, jangan buru-buru kasih solusi atau nasihat kecuali dia memang minta. Validasi perasaannya dulu, kasih ruang buat dia cerita sampai tuntas, baru kalau relevan tanya apa yang dia butuh selanjutnya (didengerin aja, atau dibantu cari solusi).",
  motivasi: "Topik saat ini: MOTIVASI. User butuh dorongan semangat atau lagi ngerasa down soal usaha, target, atau hidupnya. Kasih semangat yang genuine dan personal, bukan kata-kata mutiara generik yang pasaran. Bantu dia lihat progress kecil yang udah dia capai, dan kalau relevan, dorong dia mikirin satu langkah kecil konkret berikutnya. Tetap realistis, jangan lebay.",
  semua: "Topik saat ini: SEMUA TEMA (bebas/campuran). Ikuti alur obrolan user secara natural — bisa jadi campuran rindu, excited, curhat, atau butuh motivasi tergantung apa yang dia bawa ke obrolan. Baca konteksnya dan sesuaikan nada balasanmu tema per tema tanpa perlu dia sebutin eksplisit.",
};

function buildSystemPrompt(theme, mode) {
  const t = THEME_SYSTEM[theme] || THEME_SYSTEM.semua;
  const m = MODE_SYSTEM[mode] || MODE_SYSTEM.ai;
  return `${BASE_PERSONA}\n\n${m}\n\n${t}`;
}

app.post('/api/ai', requireAuth, async (req, res) => {
  if (!AI_API_KEY) {
    return res.status(500).json({ error: 'AI_API_KEY belum diatur di server. Admin perlu set environment variable AI_API_KEY di Render.' });
  }
  const { theme, mode, messages } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: 'Pesan kosong' });
  }

  const system = buildSystemPrompt(theme, mode);
  const chatMessages = [
    { role: 'system', content: system },
    ...messages.slice(-30).map(m => ({
      role: m.role === 'assistant' ? 'assistant' : 'user',
      content: String(m.text || '').slice(0, 4000),
    })),
  ];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25000); // 25 detik, biar tidak nge-hang kalau provider lambat/mati

  try {
    const response = await fetch(AI_BASE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${AI_API_KEY}`,
      },
      body: JSON.stringify({
        model: AI_MODEL,
        messages: chatMessages,
        max_tokens: 700,
        temperature: 0.9,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      console.error('AI provider error:', response.status, errText);
      // Diagnosa singkat untuk kasus paling umum, biar ketahuan tanpa buka Logs Render.
      let hint = 'AI sedang bermasalah, coba lagi sebentar ya.';
      if (response.status === 401 || response.status === 403) hint = 'API key AI ditolak provider (salah/kadaluarsa). Cek ulang AI_API_KEY di Render.';
      else if (response.status === 404) hint = 'Model/endpoint AI tidak ditemukan. Cek ulang AI_MODEL dan AI_BASE_URL di Render.';
      else if (response.status === 429) hint = 'Limit pemakaian AI gratis lagi penuh, tunggu sebentar atau ganti model.';
      return res.status(502).json({ error: hint, providerStatus: response.status });
    }

    const data = await response.json();
    const reply = data?.choices?.[0]?.message?.content
      || data?.content?.[0]?.text
      || 'Maaf, aku belum bisa jawab itu sekarang.';
    res.json({ reply });
  } catch (err) {
    clearTimeout(timeout);
    console.error('AI proxy error:', err);
    // Beda pesan untuk beda penyebab, supaya gampang didiagnosa dari sisi user juga.
    let msg = 'Gagal menghubungi AI, coba lagi ya.';
    if (err.name === 'AbortError') msg = 'AI kelamaan merespon (timeout), coba lagi ya.';
    else if (err.cause && err.cause.code === 'ENOTFOUND') msg = 'AI_BASE_URL tidak valid/tidak bisa dijangkau. Cek ulang di Environment Render.';
    res.status(500).json({ error: msg, detail: String(err.message || err) });
  }
});

/* ---------------- Health check ---------------- */
app.get('/health', (req, res) => {
  res.json({ ok: true, aiConfigured: !!AI_API_KEY, time: new Date().toISOString() });
});

/* Fallback ke index.html untuk root */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'app', 'index.html'));
});

/* Error handler paling akhir — pastikan error apa pun tetap dibalas
   sebagai JSON (bukan halaman HTML), supaya frontend tidak gagal
   parsing dan malah menampilkan "Failed to fetch"/error membingungkan. */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Terjadi kesalahan di server, coba lagi.' });
});

app.listen(PORT, () => {
  console.log(`SoulyKGN server berjalan di port ${PORT}`);
  console.log(`Database   : ${DB_PATH}`);
  console.log(`AI provider: ${AI_BASE_URL} (model: ${AI_MODEL})`);
  console.log(AI_API_KEY ? 'AI_API_KEY terdeteksi ✅' : '⚠️  AI_API_KEY belum diset — AI belum bisa merespon! Set di Render → Environment → AI_API_KEY.');
});
