-- ══════════════════════════════════════════════════
-- FinVault — PostgreSQL Schema v1.0
-- Segurança: Argon2id · AES-256-GCM · LGPD Compliant
-- ══════════════════════════════════════════════════

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────
-- ROLES
-- ─────────────────────────────────────────────────
CREATE TABLE roles (
  id        SMALLSERIAL PRIMARY KEY,
  name      VARCHAR(32) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO roles (name) VALUES ('user'), ('admin'), ('readonly');

-- ─────────────────────────────────────────────────
-- USERS  (dados pessoais criptografados AES-256-GCM)
-- ─────────────────────────────────────────────────
CREATE TABLE users (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email             VARCHAR(254) NOT NULL UNIQUE,
  email_verified    BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified_at TIMESTAMPTZ,
  senha_hash        TEXT,                          -- Argon2id (NULL se OAuth)
  nome_enc          TEXT NOT NULL,                 -- AES-256-GCM encrypted
  totp_secret_enc   TEXT,                          -- AES-256-GCM encrypted
  totp_ativo        BOOLEAN NOT NULL DEFAULT FALSE,
  google_id         VARCHAR(128) UNIQUE,
  google_email      VARCHAR(254),
  avatar_url        TEXT,
  role_id           SMALLINT NOT NULL DEFAULT 1 REFERENCES roles(id),
  tentativas_falhas SMALLINT NOT NULL DEFAULT 0,
  bloqueado_ate     TIMESTAMPTZ,
  ultimo_login_at   TIMESTAMPTZ,
  ultimo_login_ip   INET,
  ultimo_login_ua   TEXT,
  lgpd_aceito_em    TIMESTAMPTZ,
  lgpd_versao       VARCHAR(8),
  solicitar_exclusao BOOLEAN NOT NULL DEFAULT FALSE,
  exclusao_solicitada_em TIMESTAMPTZ,
  ativo             BOOLEAN NOT NULL DEFAULT TRUE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL;
CREATE INDEX idx_users_bloqueado ON users(bloqueado_ate) WHERE bloqueado_ate IS NOT NULL;

-- ─────────────────────────────────────────────────
-- SESSIONS  (JWT refresh tokens)
-- ─────────────────────────────────────────────────
CREATE TABLE sessions (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,               -- SHA-256 do refresh token
  device_fp   TEXT,                               -- browser fingerprint hash
  ip          INET,
  user_agent  TEXT,
  expira_em   TIMESTAMPTZ NOT NULL,
  revogado    BOOLEAN NOT NULL DEFAULT FALSE,
  revogado_em TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_expira ON sessions(expira_em) WHERE NOT revogado;

-- ─────────────────────────────────────────────────
-- AUDIT LOGS  (imutável — sem UPDATE/DELETE)
-- ─────────────────────────────────────────────────
CREATE TABLE audit_logs (
  id          BIGSERIAL PRIMARY KEY,
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  acao        VARCHAR(64) NOT NULL,               -- 'LOGIN_OK','LOGIN_FAIL','CREATE_TX', etc.
  entidade    VARCHAR(64),
  entidade_id UUID,
  dados_ant   JSONB,
  dados_novos JSONB,
  ip          INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_acao ON audit_logs(acao);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
-- Impedir UPDATE/DELETE via trigger
CREATE OR REPLACE FUNCTION audit_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_logs é imutável'; END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_audit_immutable
  BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_immutable();

-- ─────────────────────────────────────────────────
-- ACCOUNTS  (contas bancárias)
-- ─────────────────────────────────────────────────
CREATE TABLE accounts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nome            VARCHAR(120) NOT NULL,
  banco           VARCHAR(80),
  tipo            VARCHAR(24) NOT NULL CHECK (tipo IN ('corrente','poupanca','digital','investimento','carteira','outro')),
  cor             VARCHAR(9) DEFAULT '#c9a22a',
  icone           VARCHAR(8),
  saldo_inicial   NUMERIC(15,2) NOT NULL DEFAULT 0,
  saldo_atual     NUMERIC(15,2) NOT NULL DEFAULT 0,
  -- Open Banking (apenas metadados — nunca credenciais)
  ob_banco_id     VARCHAR(64),
  ob_account_id   TEXT,                           -- AES-256-GCM encrypted
  ob_last_sync    TIMESTAMPTZ,
  -- PCI-DSS: últimos 4 dígitos apenas
  agencia_mask    VARCHAR(8),
  conta_mask      VARCHAR(8),
  ativo           BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_accounts_user ON accounts(user_id) WHERE ativo;

-- ─────────────────────────────────────────────────
-- CATEGORIES
-- ─────────────────────────────────────────────────
CREATE TABLE categories (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE, -- NULL = sistema
  nome        VARCHAR(80) NOT NULL,
  tipo        VARCHAR(12) NOT NULL CHECK (tipo IN ('receita','despesa','ambos')),
  icone       VARCHAR(8),
  cor         VARCHAR(9),
  pai_id      UUID REFERENCES categories(id) ON DELETE SET NULL,
  sistema     BOOLEAN NOT NULL DEFAULT FALSE,
  ativo       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_categories_user ON categories(user_id);
-- Categorias padrão do sistema
INSERT INTO categories (id, nome, tipo, icone, cor, sistema) VALUES
  (uuid_generate_v4(),'Moradia','despesa','🏠','#c9a22a',true),
  (uuid_generate_v4(),'Alimentação','despesa','🍽️','#3ecf8e',true),
  (uuid_generate_v4(),'Transporte','despesa','🚗','#5b8dee',true),
  (uuid_generate_v4(),'Saúde','despesa','💊','#ef5350',true),
  (uuid_generate_v4(),'Lazer','despesa','🎭','#f59e0b',true),
  (uuid_generate_v4(),'Assinaturas','despesa','📱','#a78bfa',true),
  (uuid_generate_v4(),'Educação','despesa','📚','#06b6d4',true),
  (uuid_generate_v4(),'Compras','despesa','🛒','#f97316',true),
  (uuid_generate_v4(),'Salário','receita','💰','#3ecf8e',true),
  (uuid_generate_v4(),'Freelance','receita','💵','#c9a22a',true),
  (uuid_generate_v4(),'Investimentos','receita','📈','#5b8dee',true),
  (uuid_generate_v4(),'Outros','ambos','📌','#888888',true);

-- ─────────────────────────────────────────────────
-- TRANSACTIONS
-- ─────────────────────────────────────────────────
CREATE TABLE transactions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id      UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  category_id     UUID REFERENCES categories(id) ON DELETE SET NULL,
  tipo            VARCHAR(16) NOT NULL CHECK (tipo IN ('receita','despesa','transferencia')),
  valor           NUMERIC(15,2) NOT NULL CHECK (valor > 0),
  descricao       VARCHAR(255) NOT NULL,
  data            DATE NOT NULL,
  data_competencia DATE,
  conciliado      BOOLEAN NOT NULL DEFAULT FALSE,
  recorrente_id   UUID,                           -- FK added after recurring table
  -- Transferência
  conta_destino_id UUID REFERENCES accounts(id),
  -- Parcelamento
  total_parcelas  SMALLINT,
  parcela_num     SMALLINT,
  parcela_grupo_id UUID,
  -- Metadados OFX
  ofx_id          TEXT,
  ofx_memo        TEXT,
  notas           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tx_user_data ON transactions(user_id, data DESC);
CREATE INDEX idx_tx_account ON transactions(account_id);
CREATE INDEX idx_tx_category ON transactions(category_id);
CREATE INDEX idx_tx_ofx ON transactions(ofx_id) WHERE ofx_id IS NOT NULL;

-- ─────────────────────────────────────────────────
-- ATTACHMENTS
-- ─────────────────────────────────────────────────
CREATE TABLE attachments (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  transaction_id UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
  user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename       VARCHAR(255) NOT NULL,
  mime_type      VARCHAR(64),
  tamanho_bytes  INTEGER,
  storage_key    TEXT NOT NULL,                   -- S3/R2 object key (encrypted path)
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────
-- BUDGETS  (orçamentos)
-- ─────────────────────────────────────────────────
CREATE TABLE budgets (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category_id  UUID NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  valor_limite NUMERIC(15,2) NOT NULL CHECK (valor_limite > 0),
  periodo      VARCHAR(12) NOT NULL DEFAULT 'mensal' CHECK (periodo IN ('mensal','trimestral','anual')),
  alerta_pct   SMALLINT NOT NULL DEFAULT 80 CHECK (alerta_pct BETWEEN 1 AND 100),
  ativo        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, category_id, periodo)
);
CREATE INDEX idx_budgets_user ON budgets(user_id) WHERE ativo;

-- ─────────────────────────────────────────────────
-- GOALS  (metas)
-- ─────────────────────────────────────────────────
CREATE TABLE goals (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id      UUID REFERENCES accounts(id) ON DELETE SET NULL,
  nome            VARCHAR(120) NOT NULL,
  icone           VARCHAR(8),
  valor_alvo      NUMERIC(15,2) NOT NULL CHECK (valor_alvo > 0),
  valor_atual     NUMERIC(15,2) NOT NULL DEFAULT 0,
  prazo           DATE,
  aporte_mensal   NUMERIC(15,2),
  concluida       BOOLEAN NOT NULL DEFAULT FALSE,
  concluida_em    TIMESTAMPTZ,
  ativo           BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_goals_user ON goals(user_id) WHERE ativo;

-- ─────────────────────────────────────────────────
-- RECURRING TRANSACTIONS
-- ─────────────────────────────────────────────────
CREATE TABLE recurring_transactions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id      UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  category_id     UUID REFERENCES categories(id) ON DELETE SET NULL,
  tipo            VARCHAR(12) NOT NULL CHECK (tipo IN ('receita','despesa')),
  valor           NUMERIC(15,2) NOT NULL CHECK (valor > 0),
  descricao       VARCHAR(255) NOT NULL,
  frequencia      VARCHAR(12) NOT NULL CHECK (frequencia IN ('diaria','semanal','quinzenal','mensal','bimestral','trimestral','semestral','anual')),
  dia_vencimento  SMALLINT CHECK (dia_vencimento BETWEEN 1 AND 31),
  prox_vencimento DATE NOT NULL,
  ultima_execucao DATE,
  ativo           BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_recurring_user ON recurring_transactions(user_id) WHERE ativo;
CREATE INDEX idx_recurring_prox ON recurring_transactions(prox_vencimento) WHERE ativo;
-- FK reversa na transactions
ALTER TABLE transactions ADD CONSTRAINT fk_tx_recorrente
  FOREIGN KEY (recorrente_id) REFERENCES recurring_transactions(id) ON DELETE SET NULL;

-- ─────────────────────────────────────────────────
-- NOTIFICATIONS
-- ─────────────────────────────────────────────────
CREATE TABLE notifications (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tipo        VARCHAR(32) NOT NULL,               -- 'security','finance','system','lgpd'
  titulo      VARCHAR(120) NOT NULL,
  corpo       TEXT NOT NULL,
  lida        BOOLEAN NOT NULL DEFAULT FALSE,
  lida_em     TIMESTAMPTZ,
  acao_url    TEXT,
  acao_label  VARCHAR(80),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notif_user_unread ON notifications(user_id, created_at DESC) WHERE NOT lida;

-- ─────────────────────────────────────────────────
-- TRIGGERS: updated_at automático
-- ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_upd BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_accounts_upd BEFORE UPDATE ON accounts FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_tx_upd BEFORE UPDATE ON transactions FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_budgets_upd BEFORE UPDATE ON budgets FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_goals_upd BEFORE UPDATE ON goals FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_recurring_upd BEFORE UPDATE ON recurring_transactions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─────────────────────────────────────────────────
-- TRIGGER: saldo_atual sincronizado
-- ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION sync_account_balance() RETURNS trigger AS $$
DECLARE v_delta NUMERIC(15,2) := 0;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.tipo = 'receita' THEN v_delta := NEW.valor;
    ELSIF NEW.tipo = 'despesa' THEN v_delta := -NEW.valor;
    ELSIF NEW.tipo = 'transferencia' THEN
      v_delta := -NEW.valor;
      UPDATE accounts SET saldo_atual = saldo_atual + NEW.valor WHERE id = NEW.conta_destino_id;
    END IF;
    UPDATE accounts SET saldo_atual = saldo_atual + v_delta WHERE id = NEW.account_id;
  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.tipo = 'receita' THEN v_delta := -OLD.valor;
    ELSIF OLD.tipo = 'despesa' THEN v_delta := OLD.valor;
    ELSIF OLD.tipo = 'transferencia' THEN
      v_delta := OLD.valor;
      UPDATE accounts SET saldo_atual = saldo_atual - OLD.valor WHERE id = OLD.conta_destino_id;
    END IF;
    UPDATE accounts SET saldo_atual = saldo_atual + v_delta WHERE id = OLD.account_id;
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER trg_tx_balance AFTER INSERT OR DELETE ON transactions FOR EACH ROW EXECUTE FUNCTION sync_account_balance();

-- ─────────────────────────────────────────────────
-- ROW-LEVEL SECURITY (isolamento multi-tenant)
-- ─────────────────────────────────────────────────
ALTER TABLE accounts              ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions          ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories            ENABLE ROW LEVEL SECURITY;
ALTER TABLE budgets               ENABLE ROW LEVEL SECURITY;
ALTER TABLE goals                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE recurring_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications         ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions              ENABLE ROW LEVEL SECURITY;

-- Role da aplicação
CREATE ROLE finvault_app LOGIN PASSWORD 'CHANGE_ME_IN_ENV';

CREATE POLICY pol_accounts    ON accounts              USING (user_id = current_setting('app.current_user_id')::uuid);
CREATE POLICY pol_tx          ON transactions           USING (user_id = current_setting('app.current_user_id')::uuid);
CREATE POLICY pol_categories  ON categories             USING (user_id = current_setting('app.current_user_id')::uuid OR sistema = true);
CREATE POLICY pol_budgets     ON budgets                USING (user_id = current_setting('app.current_user_id')::uuid);
CREATE POLICY pol_goals       ON goals                  USING (user_id = current_setting('app.current_user_id')::uuid);
CREATE POLICY pol_recurring   ON recurring_transactions USING (user_id = current_setting('app.current_user_id')::uuid);
CREATE POLICY pol_notif       ON notifications          USING (user_id = current_setting('app.current_user_id')::uuid);
CREATE POLICY pol_sessions    ON sessions               USING (user_id = current_setting('app.current_user_id')::uuid);

GRANT CONNECT ON DATABASE finvault TO finvault_app;
GRANT USAGE ON SCHEMA public TO finvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO finvault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO finvault_app;
