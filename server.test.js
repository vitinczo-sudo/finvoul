/**
 * FinVault — Test Suite
 * Jest + Supertest
 * Roda: npm test
 */

const request = require('supertest');
const app     = require('./server');

// ── Helpers
let accessToken, refreshToken, userId;
const TEST_EMAIL = `test_${Date.now()}@finvault.test`;
const TEST_PASS  = 'Senha@Segura123';

// ══════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════
describe('POST /api/auth/register', () => {
  test('201 — cadastro válido', async () => {
    const res = await request(app).post('/api/auth/register').send({
      nome: 'Usuário Teste', email: TEST_EMAIL, senha: TEST_PASS, lgpd: true,
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    expect(res.body.user).toHaveProperty('id');
    accessToken  = res.body.accessToken;
    refreshToken = res.body.refreshToken;
    userId       = res.body.user.id;
  });

  test('409 — e-mail duplicado', async () => {
    const res = await request(app).post('/api/auth/register').send({
      nome: 'Outro', email: TEST_EMAIL, senha: TEST_PASS, lgpd: true,
    });
    expect(res.status).toBe(409);
  });

  test('422 — e-mail inválido', async () => {
    const res = await request(app).post('/api/auth/register').send({
      nome: 'X', email: 'nao-e-email', senha: TEST_PASS, lgpd: true,
    });
    expect(res.status).toBe(422);
    expect(res.body).toHaveProperty('details');
  });

  test('422 — senha curta', async () => {
    const res = await request(app).post('/api/auth/register').send({
      nome: 'X', email: 'x@test.com', senha: '123', lgpd: true,
    });
    expect(res.status).toBe(422);
  });

  test('422 — LGPD não aceita', async () => {
    const res = await request(app).post('/api/auth/register').send({
      nome: 'X', email: 'x2@test.com', senha: TEST_PASS, lgpd: false,
    });
    expect(res.status).toBe(422);
  });
});

describe('POST /api/auth/login', () => {
  test('200 — login válido', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: TEST_EMAIL, senha: TEST_PASS,
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    accessToken  = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  test('401 — senha errada', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: TEST_EMAIL, senha: 'senhaErrada',
    });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('INVALID_CREDENTIALS');
  });

  test('401 — usuário inexistente', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'inexistente@test.com', senha: TEST_PASS,
    });
    expect(res.status).toBe(401);
  });

  test('422 — campos ausentes', async () => {
    const res = await request(app).post('/api/auth/login').send({});
    expect(res.status).toBe(422);
  });
});

describe('POST /api/auth/refresh', () => {
  test('200 — refresh válido', async () => {
    const res = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    // Atualizar tokens para próximos testes
    accessToken  = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  test('401 — token inválido', async () => {
    const res = await request(app).post('/api/auth/refresh').send({ refreshToken: 'invalid.token.here' });
    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth/recover', () => {
  test('200 — resposta genérica (existente)', async () => {
    const res = await request(app).post('/api/auth/recover').send({ email: TEST_EMAIL });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('200 — resposta genérica (inexistente — anti-enumeration)', async () => {
    const res = await request(app).post('/api/auth/recover').send({ email: 'naoexiste@x.com' });
    expect(res.status).toBe(200); // Mesmo status para não revelar se email existe
    expect(res.body.ok).toBe(true);
  });
});

// ══════════════════════════════════════════════
// USER
// ══════════════════════════════════════════════
describe('GET /api/user/me', () => {
  test('200 — retorna dados do usuário', async () => {
    const res = await request(app).get('/api/user/me').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('email', TEST_EMAIL);
    expect(res.body).toHaveProperty('nome');
    expect(res.body).not.toHaveProperty('senha_hash'); // nunca expor hash
  });

  test('401 — sem token', async () => {
    const res = await request(app).get('/api/user/me');
    expect(res.status).toBe(401);
  });

  test('401 — token malformado', async () => {
    const res = await request(app).get('/api/user/me').set('Authorization', 'Bearer lixo');
    expect(res.status).toBe(401);
  });
});

// ══════════════════════════════════════════════
// ACCOUNTS
// ══════════════════════════════════════════════
let accountId;
describe('Accounts CRUD', () => {
  test('POST 201 — criar conta', async () => {
    const res = await request(app).post('/api/accounts')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ nome: 'Conta Teste', tipo: 'corrente', saldo_inicial: 1000 });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(parseFloat(res.body.saldo_atual)).toBe(1000);
    accountId = res.body.id;
  });

  test('GET 200 — listar contas', async () => {
    const res = await request(app).get('/api/accounts').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
  });

  test('PUT 200 — editar conta', async () => {
    const res = await request(app).put(`/api/accounts/${accountId}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ nome: 'Conta Editada', tipo: 'corrente' });
    expect(res.status).toBe(200);
    expect(res.body.nome).toBe('Conta Editada');
  });

  test('403 — conta de outro usuário', async () => {
    const res = await request(app).put('/api/accounts/00000000-0000-0000-0000-000000000000')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ nome: 'Hack', tipo: 'corrente' });
    expect(res.status).toBe(404); // ou 403 — não expõe que existe
  });
});

// ══════════════════════════════════════════════
// TRANSACTIONS
// ══════════════════════════════════════════════
let txId;
describe('Transactions CRUD', () => {
  test('POST 201 — criar despesa', async () => {
    const res = await request(app).post('/api/transactions')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ account_id: accountId, tipo: 'despesa', valor: 150.50, descricao: 'Supermercado', data: '2025-03-15' });
    expect(res.status).toBe(201);
    txId = res.body.id;
  });

  test('POST 201 — criar receita', async () => {
    const res = await request(app).post('/api/transactions')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ account_id: accountId, tipo: 'receita', valor: 5000, descricao: 'Salário', data: '2025-03-01' });
    expect(res.status).toBe(201);
  });

  test('Saldo atualizado via trigger', async () => {
    const res = await request(app).get('/api/accounts').set('Authorization', `Bearer ${accessToken}`);
    const acc = res.body.find(a => a.id === accountId);
    // saldo_inicial(1000) + receita(5000) - despesa(150.50) = 5849.50
    expect(parseFloat(acc.saldo_atual)).toBeCloseTo(5849.50, 1);
  });

  test('GET 200 — listar transações com filtro', async () => {
    const res = await request(app).get('/api/transactions?tipo=despesa').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.data.every(t => t.tipo === 'despesa')).toBe(true);
  });

  test('422 — valor negativo', async () => {
    const res = await request(app).post('/api/transactions')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ account_id: accountId, tipo: 'despesa', valor: -100, descricao: 'Negativo', data: '2025-03-01' });
    expect(res.status).toBe(422);
  });

  test('422 — transferência sem conta destino', async () => {
    const res = await request(app).post('/api/transactions')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ account_id: accountId, tipo: 'transferencia', valor: 100, descricao: 'Transfer', data: '2025-03-01' });
    expect(res.status).toBe(422);
  });

  test('DELETE 200 — deletar transação', async () => {
    const res = await request(app).delete(`/api/transactions/${txId}`).set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
  });
});

// ══════════════════════════════════════════════
// SECURITY
// ══════════════════════════════════════════════
describe('Security Headers', () => {
  test('X-Content-Type-Options presente', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('X-Frame-Options presente', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-frame-options']).toBeDefined();
  });

  test('Strict-Transport-Security presente', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['strict-transport-security']).toBeDefined();
  });

  test('Não expõe X-Powered-By', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

describe('Rate Limiting', () => {
  test('429 — excesso de tentativas de login', async () => {
    const reqs = Array(25).fill(null).map(() =>
      request(app).post('/api/auth/login').send({ email: 'x@x.com', senha: 'errada123' })
    );
    const responses = await Promise.all(reqs);
    expect(responses.some(r => r.status === 429)).toBe(true);
  });
});

describe('LGPD', () => {
  test('GET /api/user/data-export — exporta todos os dados', async () => {
    const res = await request(app).get('/api/user/data-export').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('usuario');
    expect(res.body).toHaveProperty('transacoes');
    expect(res.body).toHaveProperty('contas');
    expect(res.body.usuario).not.toHaveProperty('senha_hash');
    expect(res.body.usuario).not.toHaveProperty('nome_enc'); // nome deve vir decriptado
  });
});

describe('Reports', () => {
  test('GET /api/reports/summary', async () => {
    const res = await request(app).get('/api/reports/summary?month=3&year=2025').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('receitas');
    expect(res.body).toHaveProperty('despesas');
    expect(res.body).toHaveProperty('saldo');
    expect(res.body).toHaveProperty('economia');
  });

  test('GET /api/reports/cashflow', async () => {
    const res = await request(app).get('/api/reports/cashflow?months=6').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// Cleanup
afterAll(async () => {
  // Soft-delete usuário de teste
  if (accessToken) {
    await request(app).delete('/api/user/me').set('Authorization', `Bearer ${accessToken}`);
  }
});
