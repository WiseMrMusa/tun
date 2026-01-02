-- Cluster peers table for horizontal scaling peer discovery
CREATE TABLE IF NOT EXISTS cluster_peers (
    server_id VARCHAR(255) PRIMARY KEY,
    internal_addr VARCHAR(255) NOT NULL,
    tunnel_count INTEGER NOT NULL DEFAULT 0,
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_healthy BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for finding healthy peers
CREATE INDEX IF NOT EXISTS idx_cluster_peers_healthy ON cluster_peers (is_healthy, last_heartbeat DESC);

-- Index for load balancing (least connections)
CREATE INDEX IF NOT EXISTS idx_cluster_peers_load ON cluster_peers (tunnel_count ASC) WHERE is_healthy = true;

