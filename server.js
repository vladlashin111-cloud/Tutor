// server.js — сервер TutorSpace (использует nedb-promises, без компиляции)
require('dotenv').config();
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const nodemailer = require('nodemailer');
const path       = require('path');
const fs         = require('fs');

const { users, schedule, homework, attachments, pwdResets, secLog, loginAttempts } = require('./db');

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tutorspace_dev_secret_CHANGE_IN_PRODUCTION';
const JWT_EXP    = process.env.JWT_EXPIRES_IN || '2h';
const COLORS     = ['#4f8ef7','#38d9a9','#f7a34f','#f75c5c','#b07ef7','#f75cb1','#5cf7d9'];

// ════════════════════════════════════════════
//  ПАПКИ
// ════════════════════════════════════════════
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR  = path.join(__dirname, 'public');
[UPLOADS_DIR, PUBLIC_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// ── Multer для загрузки файлов ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const unique = Date.now() + '_' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(jpe?g|png|gif|webp|pdf|docx?|pptx?|xlsx?)$/i.test(file.originalname);
    cb(null, ok);
  }
});

// ── Проверка JWT токена ──
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Нет токена авторизации' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Токен недействителен или истёк. Войдите снова.' }); }
}
function tutorOnly(req, res, next) {
  if (req.user.role !== 'tutor') return res.status(403).json({ error: 'Доступ только для репетиторов' });
  next();
}

// ════════════════════════════════════════════
//  ВАЛИДАЦИЯ ПАРОЛЯ
// ════════════════════════════════════════════
function validatePassword(p) {
  if (!p || p.length < 8)                                      return 'Минимум 8 символов';
  if (!/[A-Z]/.test(p))                                        return 'Нужна хотя бы одна заглавная буква';
  if (!/[a-z]/.test(p))                                        return 'Нужна хотя бы одна строчная буква';
  if (!/[0-9]/.test(p))                                        return 'Нужна хотя бы одна цифра';
  if (!/[!@#$%^&*()\-_=+\[\]{};:'"\\|,.<>/?]/.test(p))        return 'Нужен хотя бы один спецсимвол (!@#$%...)';
  return null;
}

// ════════════════════════════════════════════
//  ЗАЩИТА ОТ ПЕРЕБОРА
// ════════════════════════════════════════════
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 15 * 60 * 1000;

async function checkBrute(login) {
  const row = await loginAttempts.findOne({ login });
  if (!row) return { locked: false, left: MAX_ATTEMPTS };
  if (row.lockedUntil && new Date(row.lockedUntil) > new Date()) {
    return { locked: true, mins: Math.ceil((new Date(row.lockedUntil) - Date.now()) / 60000) };
  }
  return { locked: false, left: MAX_ATTEMPTS - (row.count || 0) };
}
async function recordFail(login) {
  const row = await loginAttempts.findOne({ login }) || { count: 0 };
  const count = (row.count || 0) + 1;
  const lockedUntil = count >= MAX_ATTEMPTS ? new Date(Date.now() + LOCKOUT_MS).toISOString() : null;
  await loginAttempts.update({ login }, { $set: { login, count: lockedUntil ? 0 : count, lockedUntil } }, { upsert: true });
}
async function resetAttempts(login) {
  await loginAttempts.remove({ login }, {});
}
async function addLog(type, login, userName, ip) {
  await secLog.insert({ type, login, user_name: userName || login, ip: ip || '—', created_at: new Date().toISOString() });
}

// ════════════════════════════════════════════
//  EMAIL
// ════════════════════════════════════════════
function getMailer() {
  if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER) return null;
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST, port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: false, auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
}
async function sendResetCode(email, name, code) {
  const mailer = getMailer();
  if (!mailer) {
    console.log(`\n[TutorSpace] Код сброса для ${name} (${email}): ${code}\n`);
    return 'console';
  }
  await mailer.sendMail({
    from: process.env.EMAIL_FROM, to: email,
    subject: 'TutorSpace — Восстановление пароля',
    html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#f5f8ff;border-radius:12px">
      <h2 style="color:#4f8ef7">🎓 TutorSpace</h2>
      <p>Здравствуйте, <b>${name}</b>!</p>
      <p>Ваш код для сброса пароля:</p>
      <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#4f8ef7;text-align:center;padding:20px;background:#fff;border-radius:8px;margin:20px 0">${code}</div>
      <p style="color:#888;font-size:13px">Код действителен 15 минут.</p>
    </div>`
  });
  return 'email';
}

// ════════════════════════════════════════════
//  ВСПОМОГАТЕЛЬНЫЕ
// ════════════════════════════════════════════
function safe(user) {
  if (!user) return null;
  const { password_hash, ...rest } = user;
  return rest;
}
async function countUsers() {
  return await users.count({});
}

// ════════════════════════════════════════════
//  МАРШРУТЫ — АВТОРИЗАЦИЯ
// ════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, role, login, email, password, subject, tutorId } = req.body;
    if (!name || !login || !password || !role) return res.status(400).json({ error: 'Заполните все обязательные поля' });
    if (!['tutor','student'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
    if (login.includes(' ') || login.length < 3) return res.status(400).json({ error: 'Логин — минимум 3 символа без пробелов' });

    const pwdErr = validatePassword(password);
    if (pwdErr) return res.status(400).json({ error: pwdErr });

    const exists = await users.findOne({ login });
    if (exists) return res.status(409).json({ error: 'Этот логин уже занят' });

    const hash  = await bcrypt.hash(password, 12);
    const total = await countUsers();
    const color = COLORS[total % COLORS.length];

    const newUser = await users.insert({
      name, role, login,
      email:         email || null,
      password_hash: hash,
      color,
      subject:       subject || null,
      tutor_id:      tutorId || null,
      created_at:    new Date().toISOString()
    });

    await addLog('register', login, name, req.ip);
    res.json({ success: true, message: 'Аккаунт создан', userId: newUser._id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера: ' + e.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { login, password, role } = req.body;
    if (!login || !password) return res.status(400).json({ error: 'Введите логин и пароль' });

    const bf = await checkBrute(login);
    if (bf.locked) return res.status(429).json({ error: `Аккаунт заблокирован. Попробуйте через ${bf.mins} мин.` });

    const user = await users.findOne({ login });
    if (!user || (role && user.role !== role)) {
      await recordFail(login);
      const left = (await checkBrute(login)).left || 0;
      await addLog('fail', login, login, req.ip);
      return res.status(401).json({ error: `Неверный логин или пароль. Осталось попыток: ${Math.max(0, left)}` });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      await recordFail(login);
      const left = (await checkBrute(login)).left || 0;
      await addLog('fail', login, user.name, req.ip);
      return res.status(401).json({ error: `Неверный пароль. Осталось попыток: ${Math.max(0, left)}` });
    }

    await resetAttempts(login);
    await addLog('login', login, user.name, req.ip);

    const token = jwt.sign(
      { id: user._id, login: user.login, role: user.role, name: user.name },
      JWT_SECRET, { expiresIn: JWT_EXP }
    );
    res.json({ token, user: safe(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { login } = req.body;
    if (!login) return res.status(400).json({ error: 'Введите логин' });

    const user = await users.findOne({ login });
    if (!user || !user.email) {
      return res.json({
        success: true,
        message: user && !user.email
          ? 'К этому аккаунту не привязана почта. Обратитесь к репетитору.'
          : 'Если аккаунт существует — код отправлен на почту.'
      });
    }

    const code    = String(Math.floor(100000 + Math.random() * 900000));
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await pwdResets.insert({ user_id: user._id, code, expires_at: expires, used: false });

    const channel = await sendResetCode(user.email, user.name, code);
    await addLog('reset_request', login, user.name, req.ip);

    res.json({
      success: true, channel,
      message: channel === 'email'
        ? `Код отправлен на ${user.email.replace(/(.{2}).+(@.+)/, '$1***$2')}`
        : 'Код выведен в консоли сервера (нет email-настроек)'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка отправки' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { login, code, newPassword } = req.body;
    if (!login || !code || !newPassword) return res.status(400).json({ error: 'Все поля обязательны' });

    const pwdErr = validatePassword(newPassword);
    if (pwdErr) return res.status(400).json({ error: pwdErr });

    const user  = await users.findOne({ login });
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

    const reset = await pwdResets.findOne({
      user_id: user._id, code, used: false,
      expires_at: { $gt: new Date().toISOString() }
    });
    if (!reset) return res.status(400).json({ error: 'Неверный код или срок действия истёк' });

    const hash = await bcrypt.hash(newPassword, 12);
    await users.update({ _id: user._id }, { $set: { password_hash: hash } });
    await pwdResets.update({ _id: reset._id }, { $set: { used: true } });
    await addLog('reset_done', login, user.name, req.ip);

    res.json({ success: true, message: 'Пароль успешно изменён' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ════════════════════════════════════════════
//  МАРШРУТЫ — ПОЛЬЗОВАТЕЛИ
// ════════════════════════════════════════════

app.get('/api/users/me', auth, async (req, res) => {
  const user = await users.findOne({ _id: req.user.id });
  if (!user) return res.status(404).json({ error: 'Не найден' });
  res.json(safe(user));
});

app.put('/api/users/me', auth, async (req, res) => {
  try {
    const { name, email, subject, tutorId, currentPassword, newPassword } = req.body;
    const user = await users.findOne({ _id: req.user.id });
    const upd  = {};

    if (newPassword) {
      if (!currentPassword) return res.status(400).json({ error: 'Введите текущий пароль' });
      const ok = await bcrypt.compare(currentPassword, user.password_hash);
      if (!ok) return res.status(400).json({ error: 'Текущий пароль неверен' });
      const e = validatePassword(newPassword);
      if (e) return res.status(400).json({ error: e });
      upd.password_hash = await bcrypt.hash(newPassword, 12);
      await addLog('password_change', user.login, user.name, req.ip);
    }
    if (name)    upd.name    = name;
    if (email !== undefined) upd.email = email || null;
    if (subject !== undefined) upd.subject = subject || null;
    if (tutorId !== undefined) upd.tutor_id = tutorId || null;

    await users.update({ _id: user._id }, { $set: upd });
    const updated = await users.findOne({ _id: user._id });
    res.json(safe(updated));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/users/tutors', async (req, res) => {
  const list = await users.find({ role: 'tutor' });
  res.json(list.map(u => ({ _id: u._id, name: u.name, login: u.login, color: u.color })));
});

app.get('/api/users/students', auth, tutorOnly, async (req, res) => {
  const sts = await users.find({ role: 'student', tutor_id: req.user.id });
  const result = await Promise.all(sts.map(async s => {
    const hwAll   = await homework.find({ student_id: s._id });
    const schedAll = await schedule.find({ student_id: s._id });
    return { ...safe(s), hwTotal: hwAll.length, hwDone: hwAll.filter(h=>h.done).length, schedCount: schedAll.length };
  }));
  res.json(result);
});

app.put('/api/users/:id/unlink', auth, tutorOnly, async (req, res) => {
  const student = await users.findOne({ _id: req.params.id });
  if (!student || student.tutor_id !== req.user.id) return res.status(403).json({ error: 'Нет доступа' });
  await users.update({ _id: student._id }, { $set: { tutor_id: null } });
  res.json({ success: true });
});

// ════════════════════════════════════════════
//  МАРШРУТЫ — РАСПИСАНИЕ
// ════════════════════════════════════════════

app.get('/api/schedule', auth, async (req, res) => {
  const query = req.user.role === 'tutor'
    ? { tutor_id: req.user.id }
    : { student_id: req.user.id };
  res.json(await schedule.find(query));
});

function timeToMin(t) {
  const [h, m] = t.split(':').map(Number);
  return h * 60 + m;
}

app.post('/api/schedule', auth, tutorOnly, async (req, res) => {
  const { studentId, studentName, day, time, subject, color, duration } = req.body;
  if (day === undefined || !time || !subject || !studentId) return res.status(400).json({ error: 'Заполните все поля' });

  const dur = parseInt(duration) || 60;
  const newStart = timeToMin(time);
  const newEnd   = newStart + dur;

  // Проверка накладок: берём все уроки этого репетитора в тот же день
  const existing = await schedule.find({ tutor_id: req.user.id, day: parseInt(day) });
  for (const lesson of existing) {
    const lessonDur   = lesson.duration || 60;
    const lessonStart = timeToMin(lesson.time);
    const lessonEnd   = lessonStart + lessonDur;

    // Перекрытие: [newStart, newEnd) ∩ [lessonStart, lessonEnd) ≠ ∅
    if (newStart < lessonEnd && newEnd > lessonStart) {
      if (String(lesson.student_id) === String(studentId)) {
        return res.status(409).json({
          error: `Этот ученик уже записан в ${lesson.time} (${lessonDur} мин)`
        });
      }
      return res.status(409).json({
        error: `Время занято: урок с ${lesson.student_name} в ${lesson.time}–${Math.floor(lessonEnd/60).toString().padStart(2,'0')}:${(lessonEnd%60).toString().padStart(2,'0')}`
      });
    }
  }

  const item = await schedule.insert({
    tutor_id: req.user.id, student_id: studentId,
    student_name: studentName, day: parseInt(day), time, subject,
    color: color || '#4f8ef7', duration: dur
  });
  res.json(item);
});

app.delete('/api/schedule/:id', auth, tutorOnly, async (req, res) => {
  const n = await schedule.remove({ _id: req.params.id, tutor_id: req.user.id }, {});
  if (!n) return res.status(404).json({ error: 'Урок не найден' });
  res.json({ success: true });
});

// ════════════════════════════════════════════
//  МАРШРУТЫ — ДОМАШНИЕ ЗАДАНИЯ
// ════════════════════════════════════════════

async function hwWithAtts(docs) {
  return Promise.all(docs.map(async h => ({
    ...h,
    attachments: await attachments.find({ homework_id: h._id })
  })));
}

app.get('/api/homework', auth, async (req, res) => {
  const query = req.user.role === 'tutor'
    ? { tutor_id: req.user.id }
    : { student_id: req.user.id };
  const docs = await homework.find(query).sort({ created_at: -1 });
  res.json(await hwWithAtts(docs));
});

app.post('/api/homework', auth, tutorOnly, upload.array('files', 10), async (req, res) => {
  try {
    const { studentId, studentName, title, description, dueDate } = req.body;
    if (!title || !studentId) return res.status(400).json({ error: 'Заполните название и ученика' });

    const hw = await homework.insert({
      tutor_id: req.user.id, student_id: studentId, student_name: studentName,
      title, description: description || null, due_date: dueDate || null,
      done: false, created_at: new Date().toISOString()
    });

    if (req.files?.length) {
      await Promise.all(req.files.map(file => attachments.insert({
        homework_id:   hw._id,
        original_name: decodeURIComponent(escape(file.originalname)),
        stored_name:   file.filename,
        mime_type:     file.mimetype,
        size:          file.size
      })));
    }
    const atts = await attachments.find({ homework_id: hw._id });
    res.json({ ...hw, attachments: atts });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/homework/:id', auth, tutorOnly, upload.array('files', 10), async (req, res) => {
  try {
    const { title, description, dueDate } = req.body;
    if (!title) return res.status(400).json({ error: 'Введите название' });

    const existing = await homework.findOne({ _id: req.params.id, tutor_id: req.user.id });
    if (!existing) return res.status(404).json({ error: 'Задание не найдено' });

    await homework.update({ _id: req.params.id }, { $set: { title, description: description || null, due_date: dueDate || null } });

    if (req.files?.length) {
      await Promise.all(req.files.map(file => attachments.insert({
        homework_id:   req.params.id,
        original_name: decodeURIComponent(escape(file.originalname)),
        stored_name:   file.filename,
        mime_type:     file.mimetype,
        size:          file.size
      })));
    }
    const hw  = await homework.findOne({ _id: req.params.id });
    const atts = await attachments.find({ homework_id: req.params.id });
    res.json({ ...hw, attachments: atts });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/homework/:id/toggle', auth, async (req, res) => {
  const hw = await homework.findOne({ _id: req.params.id });
  if (!hw) return res.status(404).json({ error: 'Не найдено' });
  if (req.user.role === 'student' && hw.student_id !== req.user.id) return res.status(403).json({ error: 'Нет доступа' });
  if (req.user.role === 'tutor'   && hw.tutor_id   !== req.user.id) return res.status(403).json({ error: 'Нет доступа' });
  await homework.update({ _id: hw._id }, { $set: { done: !hw.done } });
  res.json({ done: !hw.done });
});

app.delete('/api/homework/:id', auth, tutorOnly, async (req, res) => {
  const hw = await homework.findOne({ _id: req.params.id, tutor_id: req.user.id });
  if (!hw) return res.status(404).json({ error: 'Не найдено' });
  // Удаляем файлы с диска
  const atts = await attachments.find({ homework_id: hw._id });
  atts.forEach(a => {
    const fp = path.join(UPLOADS_DIR, a.stored_name);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  });
  await attachments.remove({ homework_id: hw._id }, { multi: true });
  await homework.remove({ _id: hw._id }, {});
  res.json({ success: true });
});

// ════════════════════════════════════════════
//  МАРШРУТЫ — ВЛОЖЕНИЯ
// ════════════════════════════════════════════

app.delete('/api/attachments/:id', auth, tutorOnly, async (req, res) => {
  const att = await attachments.findOne({ _id: req.params.id });
  if (!att) return res.status(404).json({ error: 'Файл не найден' });
  const fp = path.join(UPLOADS_DIR, att.stored_name);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  await attachments.remove({ _id: att._id }, {});
  res.json({ success: true });
});

app.get('/api/attachments/:id/download', auth, async (req, res) => {
  const att = await attachments.findOne({ _id: req.params.id });
  if (!att) return res.status(404).json({ error: 'Файл не найден' });
  const fp = path.join(UPLOADS_DIR, att.stored_name);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Файл удалён с сервера' });
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(att.original_name)}`);
  res.setHeader('Content-Type', att.mime_type);
  res.sendFile(fp);
});

// ════════════════════════════════════════════
//  МАРШРУТЫ — БЕЗОПАСНОСТЬ
// ════════════════════════════════════════════

app.get('/api/security/log', auth, tutorOnly, async (req, res) => {
  const logs = await secLog.find({}).sort({ created_at: -1 }).limit(100);
  res.json(logs);
});

// ════════════════════════════════════════════
//  SPA — все остальные запросы → index.html
// ════════════════════════════════════════════
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

// ════════════════════════════════════════════
//  ЗАПУСК
// ════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═══════════════════════════════════════');
  console.log(`  🎓 TutorSpace запущен!`);
  console.log(`  📡 http://localhost:${PORT}`);
  console.log(`  🗄  База данных: папка ./data/`);
  console.log('═══════════════════════════════════════');
  console.log('  Для доступа с других устройств:');
  console.log('  Windows: ipconfig  →  IPv4-адрес');
  console.log(`  Затем: http://ВАШ_IP:${PORT}`);
  console.log('═══════════════════════════════════════');
});
