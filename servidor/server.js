require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieSession = require("cookie-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");

const app = express();

const PORT = process.env.PORT || 3000;
const PREMIUM_DAYS = 30;

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET não configurado.");
}

const db = new Database("data.sqlite");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    premium_until INTEGER,
    created_at INTEGER NOT NULL
  );
`);

app.disable("x-powered-by");

app.use(helmet());

app.use(express.json({
  limit: "20kb"
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100
}));

app.use(cookieSession({
  name: "session",
  keys: [process.env.SESSION_SECRET],
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000
}));

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function getUser(id) {
  return db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(id);
}

function userPublic(user) {
  const premiumUntil = Number(user.premium_until || 0);

  return {
    id: user.id,
    email: user.email,
    premium: premiumUntil > Date.now(),
    premiumUntil: premiumUntil || null
  };
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Você precisa entrar na conta."
    });
  }

  next();
}

/* TESTE DO SERVIDOR */

app.get("/api/health", (req, res) => {
  res.json({
    online: true,
    projeto: "Matemática Fácil"
  });
});

/* CRIAR CONTA */

app.post("/api/register", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!email.includes("@")) {
    return res.status(400).json({
      error: "Digite um e-mail válido."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "A senha precisa ter pelo menos 8 caracteres."
    });
  }

  const existing = db
    .prepare("SELECT id FROM users WHERE email = ?")
    .get(email);

  if (existing) {
    return res.status(409).json({
      error: "Esse e-mail já está cadastrado."
    });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const result = db
    .prepare(`
      INSERT INTO users
      (email, password_hash, created_at)
      VALUES (?, ?, ?)
    `)
    .run(
      email,
      passwordHash,
      Date.now()
    );

  req.session.userId = result.lastInsertRowid;

  const user = getUser(req.session.userId);

  res.status(201).json({
    user: userPublic(user)
  });
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (!user) {
    return res.status(401).json({
      error: "E-mail ou senha incorretos."
    });
  }

  const valid = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!valid) {
    return res.status(401).json({
      error: "E-mail ou senha incorretos."
    });
  }

  req.session.userId = user.id;

  res.json({
    user: userPublic(user)
  });
});

/* USUÁRIO ATUAL */

app.get("/api/me", requireLogin, (req, res) => {
  const user = getUser(req.session.userId);

  if (!user) {
    req.session = null;

    return res.status(401).json({
      error: "Sessão inválida."
    });
  }

  res.json({
    user: userPublic(user)
  });
});

/* SAIR */

app.post("/api/logout", (req, res) => {
  req.session = null;

  res.json({
    ok: true
  });
});

/*
  IMPORTANTE:

  Este endpoint é somente para testes administrativos.

  No sistema real, NÃO vamos liberar Premium
  porque o usuário apertou um botão.

  O Premium será liberado somente depois
  da confirmação verdadeira do pagamento.
*/

app.post("/api/admin/grant-premium", (req, res) => {

  const secret = req.headers["x-admin-secret"];

  if (
    !secret ||
    secret !== process.env.ADMIN_SECRET
  ) {
    return res.status(403).json({
      error: "Não autorizado."
    });
  }

  const email = normalizeEmail(req.body.email);

  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (!user) {
    return res.status(404).json({
      error: "Usuário não encontrado."
    });
  }

  const now = Date.now();

  const currentPremium = Math.max(
    Number(user.premium_until || 0),
    now
  );

  const thirtyDays =
    PREMIUM_DAYS *
    24 *
    60 *
    60 *
    1000;

  const newExpiration =
    currentPremium + thirtyDays;

  db.prepare(`
    UPDATE users
    SET premium_until = ?
    WHERE id = ?
  `).run(
    newExpiration,
    user.id
  );

  res.json({
    success: true,
    premiumUntil: newExpiration
  });
});

/*
  FUTURO WEBHOOK DE PAGAMENTO

  Aqui vamos conectar o provedor de pagamento
  depois.

  NÃO coloque chave Pix, senha ou token aqui.
*/

app.post("/api/webhook", (req, res) => {

  res.status(501).json({
    error: "Pagamento ainda não conectado."
  });

});

/* INICIAR SERVIDOR */

app.listen(PORT, () => {
  console.log(
    `Matemática Fácil online na porta ${PORT}`
  );
});
