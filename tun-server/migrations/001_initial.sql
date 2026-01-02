-- Initial schema for tun tunnel server
-- This migration creates tables for tunnel persistence and audit logging

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tunnels table: tracks active tunnel connections
CREATE TABLE IF NOT EXISTS tunnels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subdomain VARCHAR(64) UNIQUE NOT NULL,
    server_id VARCHAR(64) NOT NULL,
    token_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disconnected_at TIMESTAMPTZ,
    client_ip VARCHAR(45),
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Create indexes for common lookups
CREATE INDEX IF NOT EXISTS idx_tunnels_subdomain ON tunnels(subdomain);
CREATE INDEX IF NOT EXISTS idx_tunnels_server_id ON tunnels(server_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_token_id ON tunnels(token_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_created_at ON tunnels(created_at);
CREATE INDEX IF NOT EXISTS idx_tunnels_disconnected_at ON tunnels(disconnected_at) WHERE disconnected_at IS NOT NULL;

-- Reserved subdomains: prevents certain subdomains from being used
CREATE TABLE IF NOT EXISTS reserved_subdomains (
    subdomain VARCHAR(64) PRIMARY KEY,
    reason VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert some default reserved subdomains
INSERT INTO reserved_subdomains (subdomain, reason) VALUES
    ('www', 'Reserved system subdomain'),
    ('api', 'Reserved system subdomain'),
    ('admin', 'Reserved system subdomain'),
    ('mail', 'Reserved system subdomain'),
    ('ftp', 'Reserved system subdomain'),
    ('ssh', 'Reserved system subdomain'),
    ('dashboard', 'Reserved system subdomain'),
    ('status', 'Reserved system subdomain'),
    ('health', 'Reserved system subdomain'),
    ('metrics', 'Reserved system subdomain')
ON CONFLICT (subdomain) DO NOTHING;

-- Audit log: tracks important events for debugging and security
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    tunnel_id UUID REFERENCES tunnels(id) ON DELETE SET NULL,
    event_type VARCHAR(32) NOT NULL,
    server_id VARCHAR(64),
    client_ip VARCHAR(45),
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for audit log queries
CREATE INDEX IF NOT EXISTS idx_audit_log_tunnel_id ON audit_log(tunnel_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_server_id ON audit_log(server_id);

-- Request stats: aggregated statistics for monitoring
CREATE TABLE IF NOT EXISTS request_stats (
    id BIGSERIAL PRIMARY KEY,
    tunnel_id UUID NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    request_count BIGINT NOT NULL DEFAULT 0,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    avg_latency_ms DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for stats queries
CREATE INDEX IF NOT EXISTS idx_request_stats_tunnel_id ON request_stats(tunnel_id);
CREATE INDEX IF NOT EXISTS idx_request_stats_period ON request_stats(period_start, period_end);

-- Function to update last_seen_at timestamp
CREATE OR REPLACE FUNCTION update_tunnel_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_seen_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update last_seen_at on tunnel update
DROP TRIGGER IF EXISTS trigger_update_tunnel_last_seen ON tunnels;
CREATE TRIGGER trigger_update_tunnel_last_seen
    BEFORE UPDATE ON tunnels
    FOR EACH ROW
    EXECUTE FUNCTION update_tunnel_last_seen();

-- Function to clean up old disconnected tunnels (run periodically)
CREATE OR REPLACE FUNCTION cleanup_old_tunnels(retention_days INTEGER DEFAULT 7)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM tunnels 
    WHERE disconnected_at IS NOT NULL 
    AND disconnected_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old audit logs (run periodically)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_log 
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE tunnels IS 'Active and recently disconnected tunnel connections';
COMMENT ON TABLE reserved_subdomains IS 'Subdomains that cannot be used by clients';
COMMENT ON TABLE audit_log IS 'Security and debugging audit trail';
COMMENT ON TABLE request_stats IS 'Aggregated request statistics per tunnel';
COMMENT ON FUNCTION cleanup_old_tunnels IS 'Removes old disconnected tunnel records';
COMMENT ON FUNCTION cleanup_old_audit_logs IS 'Removes old audit log entries';

