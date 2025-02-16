-- Habilitar extensão para usar gen_random_uuid(), se quiser
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================
-- TABELA DE TENANTS (CLIENTES)
-- =========================
CREATE TABLE IF NOT EXISTS tenant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nome TEXT UNIQUE,
  plano TEXT  -- ex: 'free', 'pro', 'enterprise'
  -- Adicione campos extras se quiser
);

-- =========================
-- TABELA DE FEEDBACKS
-- =========================
CREATE TABLE IF NOT EXISTS feedback (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID REFERENCES tenant(id),
  usuario_final VARCHAR(20),
  audio_url TEXT,
  transcript TEXT,
  sentimento TEXT,
  resumo TEXT,
  criado_em TIMESTAMP NOT NULL DEFAULT now()
);

-- Índice p/ segmentar buscas por tenant
CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON feedback(tenant_id);

-- Habilitar Row Level Security
ALTER TABLE feedback ENABLE ROW LEVEL SECURITY;

-- Exemplo de política de isolamento
CREATE POLICY isolamento_tenant_feedback ON feedback
  USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- =========================
-- TABELA DE AUDITORIA
-- =========================
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT now(),
  usuario TEXT,
  tenant_id UUID,
  acao TEXT,
  detalhe TEXT
);
