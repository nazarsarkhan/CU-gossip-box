// server/server.js — статика + API (Express 5 совместимо)
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN; // если фронт на другом домене/порту

app.use(cors({ origin: '*' }));

app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// антиспам для /api/*
app.use('/api/', rateLimit({ windowMs: 60_000, max: 20 }));

// === API ===
const risky = /(\+?\d[\d\s\-()]{8,})|([\w.+-]+@[\w-]+\.[a-z]{2,})|(t\.me\/)/i;

app.post('/api/submit', (req, res) => {
  const text = (req.body?.text || '').trim();
  const lang = req.body?.lang === 'ru' ? 'ru' : 'en';

  if (text.length < 10 || text.length > 2000) {
    return res.status(400).type('text').send('Invalid length');
  }
  if (risky.test(text)) {
    return res.status(400).type('text').send('PII detected');
  }

  const ip =
    (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() ||
    req.socket.remoteAddress || '';
  const ip_hash = ip ? crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16) : null;
  const ua = String(req.get('user-agent') || '').slice(0, 180);

  try {
    const id = db.insertSubmission({ text, lang, ip_hash, ua });
    return res.status(201).type('text').send('OK ' + id);
  } catch (e) {
    console.error('[DB ERROR]', e);
    return res.status(500).type('text').send('DB error');
  }
});

// dev-эндпоинт для проверки (на проде закрой авторизацией/удали)
app.get('/api/admin/list', (_req, res) => {
  res.json(db.listLatest(50));
});

// === Статика ===
// корень проекта (где лежит index.html)
const ROOT_DIR = path.resolve(__dirname, '..');

// отдаём фронт
app.use(express.static(ROOT_DIR, { index: 'index.html', extensions: ['html', 'htm'] }));

// SPA-фоллбек БЕЗ пути (middleware), чтобы не ломать Express v5
// и не перехватывать /api/*
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(ROOT_DIR, 'index.html'), (err) => {
    if (err) next(err);
  });
});

// Общий обработчик ошибок
app.use((err, _req, res, _next) => {
  console.error('[UNCAUGHT]', err);
  if (!res.headersSent) res.status(500).send('Server error');
});

app.listen(PORT, () => {
  console.log(`API + Static at http://localhost:${PORT}`);
});
