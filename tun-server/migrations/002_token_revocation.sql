-- Token revocation table
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_by VARCHAR(255),
    reason TEXT,
    expires_at TIMESTAMPTZ -- When the original token would have expired (for cleanup)
);

-- Index for cleanup queries
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);

-- Index for audit queries
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_revoked_at ON revoked_tokens (revoked_at);

