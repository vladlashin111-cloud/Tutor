// db.js — база данных на nedb-promises (чистый JavaScript, не требует компиляции)
const Datastore = require('nedb-promises');
const path = require('path');
const fs   = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function col(name) {
  return Datastore.create({
    filename:   path.join(DATA_DIR, name + '.db'),
    autoload:   true,
    timestampData: false,
  });
}

// ════════════════════════════════════════════
//  КОЛЛЕКЦИИ
// ════════════════════════════════════════════
const users          = col('users');
const schedule       = col('schedule');
const homework       = col('homework');
const attachments    = col('attachments');
const pwdResets      = col('pwd_resets');
const secLog         = col('sec_log');
const loginAttempts  = col('login_attempts');

// ════════════════════════════════════════════
//  ИНДЕКСЫ (ускоряют поиск)
// ════════════════════════════════════════════
users.ensureIndex({ fieldName: 'login', unique: true });
loginAttempts.ensureIndex({ fieldName: 'login', unique: true });

module.exports = { users, schedule, homework, attachments, pwdResets, secLog, loginAttempts };
