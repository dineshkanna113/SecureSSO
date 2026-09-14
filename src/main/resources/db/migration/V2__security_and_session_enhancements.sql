-- V2__security_and_session_enhancements.sql: Enterprise Refresh Token Lifecycle, Sessions, Password Reset & Granular RBAC

-- 1. Seed Missing Granular Permissions
INSERT INTO permissions (code, description, category) VALUES
('ROLE_MANAGE', 'Create, update, and manage custom roles within tenant', 'ROLE_MANAGEMENT'),
('PERMISSION_READ', 'Read system permission catalog', 'ROLE_MANAGEMENT'),
('APPLICATION_READ', 'View registered client applications within tenant', 'APPLICATION'),
('TENANT_MANAGE', 'Manage tenant settings and status', 'TENANT_MANAGEMENT')
ON CONFLICT (code) DO NOTHING;

-- 2. User Sessions Table (Tenant-scoped)
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_identifier VARCHAR(100) NOT NULL UNIQUE,
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    device_info VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 3. Refresh Tokens Table (Hashed tokens, family rotation & reuse detection)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES user_sessions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_family VARCHAR(100) NOT NULL,
    sequence_number INT NOT NULL DEFAULT 1,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 4. Password Reset Tokens Table (Tenant-scoped, single-use)
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 5. Add correlation_id to audit_logs
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(100);

-- Indexes for fast session, token, and audit lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_tenant_user ON user_sessions(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_identifier ON user_sessions(session_identifier);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(token_family);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_password_reset_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_correlation ON audit_logs(tenant_id, correlation_id);
