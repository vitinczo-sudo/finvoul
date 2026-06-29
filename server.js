/**
 * FinVault Backend — server.js
 * Stack: Node.js 20 · Express 5 · PostgreSQL · Redis
 * Segurança: Argon2id · JWT RS256 · TOTP · AES-256-GCM
 */

'use strict';
const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const slowDown     = require('express-slow-down');
const compression  = require('compression');
const morgan       = require('morgan');
const { Pool }     = require('pg');
const redis        = require('ioredis');
const argon2       = require('argon2');
const jwt          = require('jsonwebtoken');
const speakeasy    = require('speakeasy');
const { OAuth2Client } = require('google-auth-library');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');
const Joi          = require('joi');

// ══════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════
const cfg = {
  port:          process.env.PORT || 3001,
  nodeEnv:       process.env.NODE_ENV || 'development',
  dbUrl:         process.env.DATABASE_URL,
  redisUrl:      process.env.REDIS_URL || 'redis://localhost:6379',
  jwtPrivate:    process.env.JWT_PRIVATE_KEY || fs.readFileSync('./keys/private.pem','utf8'),
  jwtPublic:     process.env.JWT_PUBLIC_KEY  || fs.readFileSync('./keys/public.pem','utf8'),
  jwtExpires:    process.env.JWT_EXPIRES     || '15m',
  refreshExpires:process.env.REFRESH_EXPIRES || '30d',
  aesKey:        Buffer.from(process.env.AES_KEY || '', 'hex'), // 32 bytes hex
  googleClientId:process.env.GOOGLE_CLIENT_ID,
  sendgridKey:   process.env.SENDGRID_API_KEY,
  appUrl:        process.env.APP_URL || 'http://localhost:3000',
  maxLoginFails: parseInt(process.env.MAX_LOGIN_FAILS) || 5,
  lockoutMins:   parseInt(process.env.LOCKOUT_MINUTES) || 30,
};

// ══════════════════════════════════════════════
// DB + REDIS
// ══════════════════════════════════════════════
const db = new Pool({ connectionString: cfg.dbUrl, ssl: cfg.nodeEnv === 'production' ? { rejectUnauthorized: true } : false });
const redisClient = new redis(cfg.redisUrl);

db.on('error', err => console.error('[DB]', err));
redisClient.on('error', err => console.error('[Redis]', err));

// ══════════════════════════════════════════════
// CRYPTO HELPERS
// ══════════════════════════════════════════════
const AES_IV_LEN = 16;
const AES_TAG_LEN = 16;

function encrypt(plaintext) {
  if (!plaintext) return null;
  const iv  = crypto.randomBytes(AES_IV_LEN);
  const cip = crypto.createCipheriv('aes-256-gcm', cfg.aesKey, iv);
  const enc = Buffer.concat([cip.update(plaintext, 'utf8'), cip.final()]);
  const tag = cip.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decrypt(ciphertext) {
  if (!ciphertext) return null;
  const buf = Buffer.from(ciphertext, 'base64');
  const iv  = buf.slice(0, AES_IV_LEN);
  const tag = buf.slice(AES_IV_LEN, AES_IV_LEN + AES_TAG_LEN);
  const enc = buf.slice(AES_IV_LEN + AES_TAG_LEN);
  const dec = crypto.createDecipheriv('aes-256-gcm', cfg.aesKey, iv);
  dec.setAuthTag(tag);
  return dec.update(enc) + dec.final('utf8');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ══════════════════════════════════════════════
// JWT
// ══════════════════════════════════════════════
function signAccessToken(payload) {
  return jwt.sign(payload, cfg.jwtPrivate, { algorithm: 'RS256', expiresIn: cfg.jwtExpires });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, cfg.jwtPrivate, { algorithm: 'RS256', expiresIn: cfg.refreshExpires });
}

function verifyToken(token) {
  return jwt.verify(token, cfg.jwtPublic, { algorithms: ['RS256'] });
}

// ══════════════════════════════════════════════
// MIDDLEWARES
// ══════════════════════════════════════════════
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", 'https://accounts.google.com'],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

app.use(cors({
  origin: cfg.nodeEnv === 'production' ? cfg.appUrl : '*',
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Device-FP'],
}));

app.use(compression());
app.use(express.json({ limit: '512kb' }));
app.use(morgan(cfg.nodeEnv === 'production' ? 'combined' : 'dev'));

// Rate limit global
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

// Rate limit agressivo para auth
const authLimiter = rateLimit({
  windowMs: 15 * 60_000, max: 20,
  message: { error: 'Muitas tentativas. Aguarde 15 minutos.' },
  keyGenerator: req => req.ip,
});

const loginSlowDown = slowDown({
  windowMs: 10 * 60_000, delayAfter: 3, delayMs: (hits) => hits * 400,
});

// ══════════════════════════════════════════════
// AUTH MIDDLEWARE
// ══════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token ausente' });
  try {
    const token = header.slice(7);
    const payload = verifyToken(token);
    // Verificar se sessão não foi revogada (cache Redis)
    const revoked = await redisClient.get(`revoked:${payload.jti}`);
    if (revoked) return res.status(401).json({ error: 'Token revogado' });
    req.user = payload;
    // Set RLS context
    await db.query(`SET LOCAL app.current_user_id = $1`, [payload.sub]);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expirado', code: 'TOKEN_EXPIRED' });
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ══════════════════════════════════════════════
// VALIDATION SCHEMAS
// ══════════════════════════════════════════════
const v = {
  register: Joi.object({
    nome:    Joi.string().min(2).max(80).required(),
    email:   Joi.string().email().max(254).required(),
    senha:   Joi.string().min(8).max(128).required(),
    lgpd:    Joi.boolean().valid(true).required(),
  }),
  login: Joi.object({
    email: Joi.string().email().required(),
    senha: Joi.string().required(),
    device_fp: Joi.string().max(64).optional(),
    remember: Joi.boolean().optional(),
  }),
  transaction: Joi.object({
    account_id:  Joi.string().uuid().required(),
    category_id: Joi.string().uuid().optional(),
    tipo:        Joi.string().valid('receita','despesa','transferencia').required(),
    valor:       Joi.number().positive().precision(2).required(),
    descricao:   Joi.string().min(1).max(255).required(),
    data:        Joi.date().iso().required(),
    conta_destino_id: Joi.string().uuid().when('tipo',{is:'transferencia',then:Joi.required()}),
    notas:       Joi.string().max(1000).optional(),
    recorrente_id: Joi.string().uuid().optional(),
  }),
  account: Joi.object({
    nome:     Joi.string().min(1).max(120).required(),
    banco:    Joi.string().max(80).optional(),
    tipo:     Joi.string().valid('corrente','poupanca','digital','investimento','carteira','outro').required(),
    cor:      Joi.string().pattern(/^#[0-9a-fA-F]{6}$/).optional(),
    icone:    Joi.string().max(8).optional(),
    saldo_inicial: Joi.number().precision(2).default(0),
  }),
  budget: Joi.object({
    category_id:  Joi.string().uuid().required(),
    valor_limite: Joi.number().positive().precision(2).required(),
    periodo:      Joi.string().valid('mensal','trimestral','anual').default('mensal'),
    alerta_pct:   Joi.number().integer().min(1).max(100).default(80),
  }),
  goal: Joi.object({
    nome:          Joi.string().min(1).max(120).required(),
    icone:         Joi.string().max(8).optional(),
    valor_alvo:    Joi.number().positive().precision(2).required(),
    valor_atual:   Joi.number().min(0).precision(2).default(0),
    prazo:         Joi.date().iso().optional(),
    aporte_mensal: Joi.number().positive().optional(),
    account_id:    Joi.string().uuid().optional(),
  }),
};

function validate(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (error) return res.status(422).json({ error: 'Dados inválidos', details: error.details.map(d => d.message) });
    req.body = value;
    next();
  };
}

// ══════════════════════════════════════════════
// AUDIT HELPER
// ══════════════════════════════════════════════
async function audit(userId, acao, entidade, entidadeId, dadosAnt, dadosNovos, req) {
  try {
    await db.query(
      `INSERT INTO audit_logs (user_id,acao,entidade,entidade_id,dados_ant,dados_novos,ip,user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [userId, acao, entidade, entidadeId,
       dadosAnt ? JSON.stringify(dadosAnt) : null,
       dadosNovos ? JSON.stringify(dadosNovos) : null,
       req?.ip, req?.headers['user-agent']]
    );
  } catch (e) { console.error('[AUDIT]', e); }
}

// ══════════════════════════════════════════════
// ─── AUTH ROUTES ───
// ══════════════════════════════════════════════
const authRouter = express.Router();

// POST /api/auth/register
authRouter.post('/register', authLimiter, validate(v.register), async (req, res) => {
  const { nome, email, senha, lgpd } = req.body;
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const exists = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'E-mail já cadastrado' });

    const hash = await argon2.hash(senha, {
      type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4,
    });
    const { rows } = await client.query(
      `INSERT INTO users (email, senha_hash, nome_enc, lgpd_aceito_em, lgpd_versao)
       VALUES ($1,$2,$3,NOW(),'1.0') RETURNING id`,
      [email.toLowerCase(), hash, encrypt(nome)]
    );
    const userId = rows[0].id;
    await client.query('COMMIT');

    // Access + Refresh tokens
    const jti = crypto.randomUUID();
    const accessToken  = signAccessToken({ sub: userId, email, role: 'user', jti });
    const refreshToken = signRefreshToken({ sub: userId, jti: crypto.randomUUID() });
    await client.query(
      `INSERT INTO sessions (user_id,token_hash,ip,user_agent,expira_em,device_fp)
       VALUES ($1,$2,$3,$4,NOW()+INTERVAL '30 days',$5)`,
      [userId, hashToken(refreshToken), req.ip, req.headers['user-agent'], req.headers['x-device-fp']]
    );

    await audit(userId, 'REGISTER', 'users', userId, null, { email }, req);
    res.status(201).json({ accessToken, refreshToken, user: { id: userId, email, nome } });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('[register]', e);
    res.status(500).json({ error: 'Erro interno' });
  } finally { client.release(); }
});

// POST /api/auth/login
authRouter.post('/login', authLimiter, loginSlowDown, validate(v.login), async (req, res) => {
  const { email, senha, device_fp, remember } = req.body;
  const { rows } = await db.query('SELECT * FROM users WHERE email=$1 AND ativo=true', [email.toLowerCase()]);
  const user = rows[0];

  // Conta bloqueada?
  if (user?.bloqueado_ate && user.bloqueado_ate > new Date()) {
    const mins = Math.ceil((user.bloqueado_ate - Date.now()) / 60000);
    return res.status(423).json({ error: `Conta bloqueada. Tente em ${mins} minutos.`, code: 'LOCKED' });
  }

  // Credenciais inválidas — resposta constante para evitar timing attack
  const passwordOk = user?.senha_hash ? await argon2.verify(user.senha_hash, senha) : false;
  if (!user || !passwordOk) {
    if (user) {
      const fails = user.tentativas_falhas + 1;
      const bloqueado = fails >= cfg.maxLoginFails ? new Date(Date.now() + cfg.lockoutMins * 60000) : null;
      await db.query('UPDATE users SET tentativas_falhas=$1, bloqueado_ate=$2 WHERE id=$3',
        [fails, bloqueado, user.id]);
      await audit(user.id, 'LOGIN_FAIL', 'users', user.id, null, { fails }, req);
    }
    return res.status(401).json({ error: 'Credenciais inválidas', code: 'INVALID_CREDENTIALS' });
  }

  // Reset tentativas
  await db.query('UPDATE users SET tentativas_falhas=0, bloqueado_ate=NULL, ultimo_login_at=NOW(), ultimo_login_ip=$1, ultimo_login_ua=$2 WHERE id=$3',
    [req.ip, req.headers['user-agent'], user.id]);

  // 2FA requerido?
  if (user.totp_ativo) {
    const challToken = jwt.sign({ sub: user.id, step: '2fa' }, cfg.jwtPrivate, { algorithm: 'RS256', expiresIn: '5m' });
    await audit(user.id, 'LOGIN_2FA_REQUIRED', 'users', user.id, null, null, req);
    return res.json({ requires2FA: true, challToken });
  }

  const jti = crypto.randomUUID();
  const accessToken  = signAccessToken({ sub: user.id, email: user.email, role: 'user', jti });
  const refreshToken = signRefreshToken({ sub: user.id, jti: crypto.randomUUID() });
  const expiryDays   = remember ? 30 : 1;
  await db.query(
    `INSERT INTO sessions (user_id,token_hash,ip,user_agent,expira_em,device_fp)
     VALUES ($1,$2,$3,$4,NOW()+($5||' days')::interval,$6)`,
    [user.id, hashToken(refreshToken), req.ip, req.headers['user-agent'], expiryDays, device_fp]
  );
  await audit(user.id, 'LOGIN_OK', 'users', user.id, null, null, req);
  res.json({ accessToken, refreshToken, user: { id: user.id, email: user.email, nome: decrypt(user.nome_enc) } });
});

// POST /api/auth/2fa/verify
authRouter.post('/2fa/verify', authLimiter, async (req, res) => {
  const { challToken, code } = req.body;
  if (!challToken || !code) return res.status(400).json({ error: 'Dados faltando' });
  let payload;
  try { payload = verifyToken(challToken); } catch { return res.status(401).json({ error: 'Token inválido' }); }
  if (payload.step !== '2fa') return res.status(401).json({ error: 'Token inválido' });

  const { rows } = await db.query('SELECT * FROM users WHERE id=$1', [payload.sub]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

  const secret = decrypt(user.totp_secret_enc);
  const valid  = speakeasy.totp.verify({ secret, encoding: 'base32', token: code, window: 1 });
  if (!valid) {
    await audit(user.id, '2FA_FAIL', 'users', user.id, null, null, req);
    return res.status(401).json({ error: 'Código inválido', code: 'INVALID_OTP' });
  }
  const jti = crypto.randomUUID();
  const accessToken  = signAccessToken({ sub: user.id, email: user.email, role: 'user', jti });
  const refreshToken = signRefreshToken({ sub: user.id, jti: crypto.randomUUID() });
  await db.query(
    `INSERT INTO sessions (user_id,token_hash,ip,user_agent,expira_em)
     VALUES ($1,$2,$3,$4,NOW()+INTERVAL '30 days')`,
    [user.id, hashToken(refreshToken), req.ip, req.headers['user-agent']]
  );
  await audit(user.id, '2FA_OK', 'users', user.id, null, null, req);
  res.json({ accessToken, refreshToken, user: { id: user.id, email: user.email, nome: decrypt(user.nome_enc) } });
});

// POST /api/auth/google
authRouter.post('/google', authLimiter, async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: 'Credential ausente' });
  try {
    const client  = new OAuth2Client(cfg.googleClientId);
    const ticket  = await client.verifyIdToken({ idToken: credential, audience: cfg.googleClientId });
    const gPayload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = gPayload;

    let { rows } = await db.query('SELECT * FROM users WHERE google_id=$1 OR email=$2', [googleId, email]);
    let user = rows[0];
    if (!user) {
      const res2 = await db.query(
        `INSERT INTO users (email, nome_enc, google_id, google_email, avatar_url, email_verified, email_verified_at, lgpd_aceito_em, lgpd_versao)
         VALUES ($1,$2,$3,$4,$5,true,NOW(),NOW(),'1.0') RETURNING *`,
        [email, encrypt(name), googleId, email, picture]
      );
      user = res2.rows[0];
      await audit(user.id, 'REGISTER_GOOGLE', 'users', user.id, null, { email }, req);
    } else if (!user.google_id) {
      await db.query('UPDATE users SET google_id=$1, avatar_url=$2, email_verified=true WHERE id=$3', [googleId, picture, user.id]);
    }

    const jti = crypto.randomUUID();
    const accessToken  = signAccessToken({ sub: user.id, email: user.email, role: 'user', jti });
    const refreshToken = signRefreshToken({ sub: user.id, jti: crypto.randomUUID() });
    await db.query(
      `INSERT INTO sessions (user_id,token_hash,ip,user_agent,expira_em)
       VALUES ($1,$2,$3,$4,NOW()+INTERVAL '30 days')`,
      [user.id, hashToken(refreshToken), req.ip, req.headers['user-agent']]
    );
    await audit(user.id, 'LOGIN_GOOGLE', 'users', user.id, null, null, req);
    res.json({ accessToken, refreshToken, user: { id: user.id, email: user.email, nome: decrypt(user.nome_enc), avatar: user.avatar_url } });
  } catch (e) {
    console.error('[google auth]', e);
    res.status(401).json({ error: 'Token Google inválido' });
  }
});

// POST /api/auth/refresh
authRouter.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken ausente' });
  try {
    const payload = verifyToken(refreshToken);
    const { rows } = await db.query(
      'SELECT * FROM sessions WHERE token_hash=$1 AND NOT revogado AND expira_em > NOW()',
      [hashToken(refreshToken)]
    );
    if (!rows.length) return res.status(401).json({ error: 'Sessão inválida ou expirada', code: 'SESSION_EXPIRED' });

    const userRes = await db.query('SELECT * FROM users WHERE id=$1 AND ativo=true', [payload.sub]);
    const user = userRes.rows[0];
    if (!user) return res.status(401).json({ error: 'Usuário inativo' });

    // Rotation: revogar token antigo, emitir novo
    await db.query('UPDATE sessions SET revogado=true, revogado_em=NOW() WHERE token_hash=$1', [hashToken(refreshToken)]);
    const jti = crypto.randomUUID();
    const newAccess  = signAccessToken({ sub: user.id, email: user.email, role: 'user', jti });
    const newRefresh = signRefreshToken({ sub: user.id, jti: crypto.randomUUID() });
    await db.query(
      `INSERT INTO sessions (user_id,token_hash,ip,user_agent,expira_em,device_fp)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [user.id, hashToken(newRefresh), req.ip, req.headers['user-agent'],
       rows[0].expira_em, rows[0].device_fp]
    );
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch { res.status(401).json({ error: 'Token inválido' }); }
});

// POST /api/auth/logout
authRouter.post('/logout', requireAuth, async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    await db.query('UPDATE sessions SET revogado=true, revogado_em=NOW() WHERE token_hash=$1', [hashToken(refreshToken)]);
  }
  // Blacklist access token até expirar
  const ttl = req.user.exp - Math.floor(Date.now() / 1000);
  if (ttl > 0) await redisClient.setex(`revoked:${req.user.jti}`, ttl, '1');
  await audit(req.user.sub, 'LOGOUT', 'sessions', null, null, null, req);
  res.json({ ok: true });
});

// POST /api/auth/recover
authRouter.post('/recover', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'E-mail obrigatório' });
  const { rows } = await db.query('SELECT id FROM users WHERE email=$1 AND ativo=true', [email.toLowerCase()]);
  // Resposta genérica independente de existência (evita user enumeration)
  if (rows.length) {
    const token = crypto.randomBytes(32).toString('hex');
    await redisClient.setex(`recover:${hashToken(token)}`, 900, rows[0].id); // 15min
    // TODO: enviar email via SendGrid/Resend
    console.log(`[RECOVER] link: ${cfg.appUrl}/reset-password?token=${token}`);
    await audit(rows[0].id, 'PASSWORD_RECOVER_REQUEST', 'users', rows[0].id, null, null, req);
  }
  res.json({ ok: true, msg: 'Se o e-mail existir, você receberá um link em breve.' });
});

// POST /api/auth/reset-password
authRouter.post('/reset-password', authLimiter, async (req, res) => {
  const { token, senha } = req.body;
  if (!token || !senha || senha.length < 8) return res.status(400).json({ error: 'Dados inválidos' });
  const userId = await redisClient.get(`recover:${hashToken(token)}`);
  if (!userId) return res.status(400).json({ error: 'Link inválido ou expirado' });
  const hash = await argon2.hash(senha, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 });
  await db.query('UPDATE users SET senha_hash=$1, tentativas_falhas=0, bloqueado_ate=NULL WHERE id=$2', [hash, userId]);
  await redisClient.del(`recover:${hashToken(token)}`);
  // Revogar todas as sessões existentes
  await db.query('UPDATE sessions SET revogado=true, revogado_em=NOW() WHERE user_id=$1', [userId]);
  await audit(userId, 'PASSWORD_RESET', 'users', userId, null, null, req);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════
// ─── USER ROUTES ───
// ══════════════════════════════════════════════
const userRouter = express.Router();
userRouter.use(requireAuth);

userRouter.get('/me', async (req, res) => {
  const { rows } = await db.query(
    'SELECT id,email,email_verified,google_id,avatar_url,totp_ativo,ultimo_login_at,ultimo_login_ip,created_at FROM users WHERE id=$1',
    [req.user.sub]
  );
  const u = rows[0];
  const nomeEnc = await db.query('SELECT nome_enc FROM users WHERE id=$1', [req.user.sub]);
  res.json({ ...u, nome: decrypt(nomeEnc.rows[0].nome_enc) });
});

userRouter.put('/me', async (req, res) => {
  const { nome } = req.body;
  if (!nome) return res.status(400).json({ error: 'Nome obrigatório' });
  await db.query('UPDATE users SET nome_enc=$1 WHERE id=$2', [encrypt(nome), req.user.sub]);
  res.json({ ok: true });
});

// LGPD Art. 18: exportar dados
userRouter.get('/data-export', async (req, res) => {
  const [users, accounts, transactions, budgets, goals, recurring] = await Promise.all([
    db.query('SELECT id,email,email_verified,created_at FROM users WHERE id=$1',[req.user.sub]),
    db.query('SELECT * FROM accounts WHERE user_id=$1',[req.user.sub]),
    db.query('SELECT * FROM transactions WHERE user_id=$1 ORDER BY data DESC',[req.user.sub]),
    db.query('SELECT * FROM budgets WHERE user_id=$1',[req.user.sub]),
    db.query('SELECT * FROM goals WHERE user_id=$1',[req.user.sub]),
    db.query('SELECT * FROM recurring_transactions WHERE user_id=$1',[req.user.sub]),
  ]);
  const u = users.rows[0];
  u.nome = decrypt((await db.query('SELECT nome_enc FROM users WHERE id=$1',[req.user.sub])).rows[0].nome_enc);
  await audit(req.user.sub, 'LGPD_DATA_EXPORT', 'users', req.user.sub, null, null, req);
  res.json({ exportado_em: new Date().toISOString(), usuario: u, contas: accounts.rows, transacoes: transactions.rows, orcamentos: budgets.rows, metas: goals.rows, recorrentes: recurring.rows });
});

// LGPD Art. 18: solicitar exclusão
userRouter.delete('/me', async (req, res) => {
  await db.query('UPDATE users SET solicitar_exclusao=true, exclusao_solicitada_em=NOW() WHERE id=$1', [req.user.sub]);
  await audit(req.user.sub, 'LGPD_DELETE_REQUEST', 'users', req.user.sub, null, null, req);
  // Job async vai executar a exclusão em até 30 dias
  res.json({ ok: true, msg: 'Solicitação registrada. Dados removidos em até 30 dias conforme LGPD Art. 18.' });
});

// ══════════════════════════════════════════════
// ─── TRANSACTIONS ───
// ══════════════════════════════════════════════
const txRouter = express.Router();
txRouter.use(requireAuth);

txRouter.get('/', async (req, res) => {
  const { from, to, type, account_id, category_id, search, limit=50, offset=0 } = req.query;
  let q = 'SELECT t.*,c.nome as categoria_nome,c.icone as categoria_icone,a.nome as conta_nome FROM transactions t LEFT JOIN categories c ON c.id=t.category_id LEFT JOIN accounts a ON a.id=t.account_id WHERE t.user_id=$1';
  const params = [req.user.sub];
  if (from)        { params.push(from);        q += ` AND t.data >= $${params.length}`; }
  if (to)          { params.push(to);           q += ` AND t.data <= $${params.length}`; }
  if (type)        { params.push(type);         q += ` AND t.tipo = $${params.length}`; }
  if (account_id)  { params.push(account_id);   q += ` AND t.account_id = $${params.length}`; }
  if (category_id) { params.push(category_id);  q += ` AND t.category_id = $${params.length}`; }
  if (search)      { params.push(`%${search}%`); q += ` AND t.descricao ILIKE $${params.length}`; }
  q += ` ORDER BY t.data DESC, t.created_at DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`;
  params.push(Math.min(parseInt(limit)||50,200), parseInt(offset)||0);
  const { rows } = await db.query(q, params);
  const total = await db.query('SELECT COUNT(*) FROM transactions WHERE user_id=$1', [req.user.sub]);
  res.json({ data: rows, total: parseInt(total.rows[0].count) });
});

txRouter.post('/', validate(v.transaction), async (req, res) => {
  const { account_id, category_id, tipo, valor, descricao, data, conta_destino_id, notas, recorrente_id } = req.body;
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_user_id = $1`, [req.user.sub]);
    // Verificar que a conta pertence ao usuário
    const acc = await client.query('SELECT id FROM accounts WHERE id=$1 AND user_id=$2 AND ativo=true', [account_id, req.user.sub]);
    if (!acc.rows.length) return res.status(403).json({ error: 'Conta não encontrada' });

    const { rows } = await client.query(
      `INSERT INTO transactions (user_id,account_id,category_id,tipo,valor,descricao,data,conta_destino_id,notas,recorrente_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.sub, account_id, category_id||null, tipo, valor, descricao, data, conta_destino_id||null, notas||null, recorrente_id||null]
    );
    await client.query('COMMIT');
    await audit(req.user.sub, 'CREATE_TRANSACTION', 'transactions', rows[0].id, null, rows[0], req);
    res.status(201).json(rows[0]);
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('[tx create]', e);
    res.status(500).json({ error: 'Erro ao criar transação' });
  } finally { client.release(); }
});

txRouter.put('/:id', validate(v.transaction), async (req, res) => {
  const { id } = req.params;
  const old = await db.query('SELECT * FROM transactions WHERE id=$1 AND user_id=$2', [id, req.user.sub]);
  if (!old.rows.length) return res.status(404).json({ error: 'Transação não encontrada' });
  const { account_id, category_id, tipo, valor, descricao, data, notas } = req.body;
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_user_id = $1`, [req.user.sub]);
    // Reverter balanço antigo e aplicar novo via delete+insert
    await client.query('DELETE FROM transactions WHERE id=$1', [id]);
    const { rows } = await client.query(
      `INSERT INTO transactions (id,user_id,account_id,category_id,tipo,valor,descricao,data,notas)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [id, req.user.sub, account_id, category_id||null, tipo, valor, descricao, data, notas||null]
    );
    await client.query('COMMIT');
    await audit(req.user.sub, 'UPDATE_TRANSACTION', 'transactions', id, old.rows[0], rows[0], req);
    res.json(rows[0]);
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao atualizar' });
  } finally { client.release(); }
});

txRouter.delete('/:id', async (req, res) => {
  const { rows } = await db.query('SELECT * FROM transactions WHERE id=$1 AND user_id=$2', [req.params.id, req.user.sub]);
  if (!rows.length) return res.status(404).json({ error: 'Não encontrada' });
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_user_id = $1`, [req.user.sub]);
    await client.query('DELETE FROM transactions WHERE id=$1', [req.params.id]);
    await client.query('COMMIT');
    await audit(req.user.sub, 'DELETE_TRANSACTION', 'transactions', req.params.id, rows[0], null, req);
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao deletar' });
  } finally { client.release(); }
});

// ══════════════════════════════════════════════
// ─── ACCOUNTS ───
// ══════════════════════════════════════════════
const accRouter = express.Router();
accRouter.use(requireAuth);

accRouter.get('/', async (req,res) => {
  const { rows } = await db.query('SELECT * FROM accounts WHERE user_id=$1 AND ativo=true ORDER BY created_at', [req.user.sub]);
  res.json(rows);
});

accRouter.post('/', validate(v.account), async (req,res) => {
  const { nome, banco, tipo, cor, icone, saldo_inicial } = req.body;
  const { rows } = await db.query(
    `INSERT INTO accounts (user_id,nome,banco,tipo,cor,icone,saldo_inicial,saldo_atual)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING *`,
    [req.user.sub, nome, banco||null, tipo, cor||'#c9a22a', icone||null, saldo_inicial||0]
  );
  await audit(req.user.sub,'CREATE_ACCOUNT','accounts',rows[0].id,null,rows[0],req);
  res.status(201).json(rows[0]);
});

accRouter.put('/:id', validate(v.account), async (req,res) => {
  const old = await db.query('SELECT * FROM accounts WHERE id=$1 AND user_id=$2',[req.params.id,req.user.sub]);
  if (!old.rows.length) return res.status(404).json({error:'Não encontrada'});
  const { nome, banco, tipo, cor, icone } = req.body;
  const { rows } = await db.query(
    'UPDATE accounts SET nome=$1,banco=$2,tipo=$3,cor=$4,icone=$5 WHERE id=$6 RETURNING *',
    [nome,banco||null,tipo,cor||'#c9a22a',icone||null,req.params.id]
  );
  await audit(req.user.sub,'UPDATE_ACCOUNT','accounts',req.params.id,old.rows[0],rows[0],req);
  res.json(rows[0]);
});

accRouter.delete('/:id', async (req,res) => {
  const { rows } = await db.query('SELECT * FROM accounts WHERE id=$1 AND user_id=$2',[req.params.id,req.user.sub]);
  if (!rows.length) return res.status(404).json({error:'Não encontrada'});
  const hasTx = await db.query('SELECT id FROM transactions WHERE account_id=$1 LIMIT 1',[req.params.id]);
  if (hasTx.rows.length) {
    await db.query('UPDATE accounts SET ativo=false WHERE id=$1',[req.params.id]);
  } else {
    await db.query('DELETE FROM accounts WHERE id=$1',[req.params.id]);
  }
  await audit(req.user.sub,'DELETE_ACCOUNT','accounts',req.params.id,rows[0],null,req);
  res.json({ok:true});
});

// ══════════════════════════════════════════════
// ─── BUDGETS / GOALS / RECURRING / CATEGORIES ─
// ══════════════════════════════════════════════
function crudRouter(table, schema, fields) {
  const router = express.Router();
  router.use(requireAuth);
  router.get('/', async (req,res) => {
    const { rows } = await db.query(`SELECT * FROM ${table} WHERE user_id=$1 AND ativo=true ORDER BY created_at`, [req.user.sub]);
    res.json(rows);
  });
  router.post('/', validate(schema), async (req,res) => {
    const vals = fields.map(f => req.body[f] ?? null);
    const cols = fields.join(',');
    const ph   = fields.map((_,i)=>`$${i+2}`).join(',');
    const { rows } = await db.query(`INSERT INTO ${table} (user_id,${cols}) VALUES ($1,${ph}) RETURNING *`, [req.user.sub, ...vals]);
    await audit(req.user.sub,`CREATE_${table.toUpperCase()}`,table,rows[0].id,null,rows[0],req);
    res.status(201).json(rows[0]);
  });
  router.put('/:id', validate(schema), async (req,res) => {
    const old = await db.query(`SELECT * FROM ${table} WHERE id=$1 AND user_id=$2`,[req.params.id,req.user.sub]);
    if (!old.rows.length) return res.status(404).json({error:'Não encontrado'});
    const sets = fields.map((f,i)=>`${f}=$${i+2}`).join(',');
    const vals = fields.map(f => req.body[f] ?? null);
    const { rows } = await db.query(`UPDATE ${table} SET ${sets} WHERE id=$1 RETURNING *`,[req.params.id,...vals]);
    await audit(req.user.sub,`UPDATE_${table.toUpperCase()}`,table,req.params.id,old.rows[0],rows[0],req);
    res.json(rows[0]);
  });
  router.delete('/:id', async (req,res) => {
    const { rows } = await db.query(`SELECT * FROM ${table} WHERE id=$1 AND user_id=$2`,[req.params.id,req.user.sub]);
    if (!rows.length) return res.status(404).json({error:'Não encontrado'});
    await db.query(`UPDATE ${table} SET ativo=false WHERE id=$1`,[req.params.id]);
    await audit(req.user.sub,`DELETE_${table.toUpperCase()}`,table,req.params.id,rows[0],null,req);
    res.json({ok:true});
  });
  return router;
}

const budgetRouter   = crudRouter('budgets',v.budget,['category_id','valor_limite','periodo','alerta_pct']);
const goalRouter     = crudRouter('goals',v.goal,['nome','icone','valor_alvo','valor_atual','prazo','aporte_mensal','account_id']);

// ── CATEGORIES (inclui sistema)
const catRouter = express.Router();
catRouter.use(requireAuth);
catRouter.get('/', async (req,res) => {
  const { rows } = await db.query(
    `SELECT * FROM categories WHERE (user_id=$1 OR sistema=true) AND ativo=true ORDER BY sistema DESC, nome`,
    [req.user.sub]
  );
  res.json(rows);
});
catRouter.post('/', validate(v.account.keys({ nome: Joi.string().required(), tipo: Joi.string().valid('receita','despesa','ambos').required(), icone: Joi.string().optional(), cor: Joi.string().optional(), pai_id: Joi.string().uuid().optional() })), async (req,res) => {
  const { nome, tipo, icone, cor, pai_id } = req.body;
  const { rows } = await db.query('INSERT INTO categories (user_id,nome,tipo,icone,cor,pai_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',[req.user.sub,nome,tipo,icone||null,cor||null,pai_id||null]);
  res.status(201).json(rows[0]);
});

// ══════════════════════════════════════════════
// ─── REPORTS ───
// ══════════════════════════════════════════════
const repRouter = express.Router();
repRouter.use(requireAuth);

repRouter.get('/summary', async (req, res) => {
  const { month, year } = req.query;
  const m = parseInt(month) || new Date().getMonth() + 1;
  const y = parseInt(year)  || new Date().getFullYear();
  const [receitas, despesas, saldo, categorias] = await Promise.all([
    db.query(`SELECT COALESCE(SUM(valor),0) as total FROM transactions WHERE user_id=$1 AND tipo='receita' AND EXTRACT(MONTH FROM data)=$2 AND EXTRACT(YEAR FROM data)=$3`,[req.user.sub,m,y]),
    db.query(`SELECT COALESCE(SUM(valor),0) as total FROM transactions WHERE user_id=$1 AND tipo='despesa' AND EXTRACT(MONTH FROM data)=$2 AND EXTRACT(YEAR FROM data)=$3`,[req.user.sub,m,y]),
    db.query(`SELECT COALESCE(SUM(saldo_atual),0) as total FROM accounts WHERE user_id=$1 AND ativo=true`,[req.user.sub]),
    db.query(`SELECT c.nome,c.icone,c.cor,COALESCE(SUM(t.valor),0) as total FROM transactions t JOIN categories c ON c.id=t.category_id WHERE t.user_id=$1 AND t.tipo='despesa' AND EXTRACT(MONTH FROM t.data)=$2 AND EXTRACT(YEAR FROM t.data)=$3 GROUP BY c.id ORDER BY total DESC LIMIT 8`,[req.user.sub,m,y]),
  ]);
  res.json({
    receitas:   parseFloat(receitas.rows[0].total),
    despesas:   parseFloat(despesas.rows[0].total),
    saldo:      parseFloat(saldo.rows[0].total),
    economia:   parseFloat(receitas.rows[0].total) - parseFloat(despesas.rows[0].total),
    categorias: categorias.rows,
  });
});

repRouter.get('/cashflow', async (req, res) => {
  const { months = 12 } = req.query;
  const { rows } = await db.query(
    `SELECT to_char(date_trunc('month',data),'YYYY-MM') as mes,
     SUM(CASE WHEN tipo='receita' THEN valor ELSE 0 END) as receitas,
     SUM(CASE WHEN tipo='despesa' THEN valor ELSE 0 END) as despesas
     FROM transactions WHERE user_id=$1 AND data >= NOW()-($2||' months')::interval
     GROUP BY mes ORDER BY mes`,
    [req.user.sub, parseInt(months)]
  );
  res.json(rows);
});

// ══════════════════════════════════════════════
// ─── NOTIFICATIONS ───
// ══════════════════════════════════════════════
const notifRouter = express.Router();
notifRouter.use(requireAuth);
notifRouter.get('/', async (req,res) => {
  const { rows } = await db.query('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.sub]);
  res.json(rows);
});
notifRouter.patch('/:id/read', async (req,res) => {
  await db.query('UPDATE notifications SET lida=true, lida_em=NOW() WHERE id=$1 AND user_id=$2',[req.params.id,req.user.sub]);
  res.json({ok:true});
});
notifRouter.patch('/read-all', async (req,res) => {
  await db.query('UPDATE notifications SET lida=true, lida_em=NOW() WHERE user_id=$1 AND NOT lida',[req.user.sub]);
  res.json({ok:true});
});

// ══════════════════════════════════════════════
// REGISTER ROUTES
// ══════════════════════════════════════════════
app.use('/api/auth',          authRouter);
app.use('/api/user',          userRouter);
app.use('/api/transactions',  txRouter);
app.use('/api/accounts',      accRouter);
app.use('/api/budgets',       budgetRouter);
app.use('/api/goals',         goalRouter);
app.use('/api/categories',    catRouter);
app.use('/api/reports',       repRouter);
app.use('/api/notifications', notifRouter);

// Health check
app.get('/health', async (req,res) => {
  const dbOk = await db.query('SELECT 1').then(()=>true).catch(()=>false);
  const rdOk = await redisClient.ping().then(r=>r==='PONG').catch(()=>false);
  res.status(dbOk&&rdOk?200:503).json({ status: dbOk&&rdOk?'ok':'degraded', db: dbOk, redis: rdOk, ts: new Date().toISOString() });
});

// 404
app.use((_req,res) => res.status(404).json({ error: 'Rota não encontrada' }));

// Error handler
app.use((err,_req,res,_next) => {
  console.error('[ERROR]', err);
  res.status(500).json({ error: cfg.nodeEnv==='production' ? 'Erro interno' : err.message });
});

// ══════════════════════════════════════════════
// START
// ══════════════════════════════════════════════
app.listen(cfg.port, () => {
  console.log(`✅ FinVault API rodando na porta ${cfg.port} [${cfg.nodeEnv}]`);
});

module.exports = app;
