//! Database layer for tunnel persistence.
//!
//! Provides PostgreSQL-backed storage for tunnel state, enabling horizontal scaling
//! and persistence across server restarts.

use anyhow::Result;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing::{debug, info, warn};
use tun_core::protocol::TunnelId;
use uuid::Uuid;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// PostgreSQL connection URL
    pub database_url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Server ID for this instance (for horizontal scaling)
    pub server_id: String,
}

impl DbConfig {
    pub fn new(database_url: String, server_id: String) -> Self {
        Self {
            database_url,
            max_connections: 10,
            server_id,
        }
    }
}

/// A tunnel record from the database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TunnelRecord {
    pub id: Uuid,
    pub subdomain: String,
    pub server_id: String,
    pub token_id: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub client_ip: Option<String>,
    pub metadata: serde_json::Value,
}

/// Audit log event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    TunnelConnected,
    TunnelDisconnected,
    TunnelHeartbeat,
    AuthSuccess,
    AuthFailure,
    RateLimitExceeded,
    TokenRevoked,
    TokenUnrevoked,
    Error,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::TunnelConnected => "tunnel_connected",
            AuditEventType::TunnelDisconnected => "tunnel_disconnected",
            AuditEventType::TunnelHeartbeat => "tunnel_heartbeat",
            AuditEventType::AuthSuccess => "auth_success",
            AuditEventType::AuthFailure => "auth_failure",
            AuditEventType::RateLimitExceeded => "rate_limit_exceeded",
            AuditEventType::TokenRevoked => "token_revoked",
            AuditEventType::TokenUnrevoked => "token_unrevoked",
            AuditEventType::Error => "error",
        }
    }
}

/// Database layer for tunnel operations
#[derive(Clone)]
pub struct TunnelDb {
    pool: PgPool,
    server_id: String,
}

impl TunnelDb {
    /// Create a new database connection pool
    pub async fn new(config: &DbConfig) -> Result<Self> {
        info!("Connecting to database...");
        
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.database_url)
            .await?;

        info!("Database connected successfully");
        
        Ok(Self {
            pool,
            server_id: config.server_id.clone(),
        })
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> Result<()> {
        info!("Running database migrations...");
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await?;
        info!("Migrations completed");
        Ok(())
    }

    /// Register a new tunnel in the database
    pub async fn register_tunnel(
        &self,
        tunnel_id: TunnelId,
        subdomain: &str,
        token_id: &str,
        client_ip: Option<&str>,
    ) -> Result<TunnelRecord> {
        debug!("Registering tunnel {} with subdomain {}", tunnel_id, subdomain);
        
        let record = sqlx::query_as::<_, TunnelRecord>(
            r#"
            INSERT INTO tunnels (id, subdomain, server_id, token_id, client_ip)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(tunnel_id.0)
        .bind(subdomain)
        .bind(&self.server_id)
        .bind(token_id)
        .bind(client_ip)
        .fetch_one(&self.pool)
        .await?;

        // Log the event
        self.log_audit_event(
            Some(tunnel_id),
            AuditEventType::TunnelConnected,
            client_ip,
            serde_json::json!({ "subdomain": subdomain }),
        )
        .await
        .ok();

        Ok(record)
    }

    /// Unregister a tunnel (mark as disconnected)
    pub async fn unregister_tunnel(&self, tunnel_id: TunnelId) -> Result<()> {
        debug!("Unregistering tunnel {}", tunnel_id);
        
        sqlx::query(
            r#"
            UPDATE tunnels 
            SET disconnected_at = NOW()
            WHERE id = $1 AND disconnected_at IS NULL
            "#,
        )
        .bind(tunnel_id.0)
        .execute(&self.pool)
        .await?;

        self.log_audit_event(
            Some(tunnel_id),
            AuditEventType::TunnelDisconnected,
            None,
            serde_json::json!({}),
        )
        .await
        .ok();

        Ok(())
    }

    /// Find a tunnel by subdomain
    pub async fn find_by_subdomain(&self, subdomain: &str) -> Result<Option<TunnelRecord>> {
        let record = sqlx::query_as::<_, TunnelRecord>(
            r#"
            SELECT * FROM tunnels 
            WHERE subdomain = $1 AND disconnected_at IS NULL
            "#,
        )
        .bind(subdomain)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }

    /// Find a tunnel by ID
    pub async fn find_by_id(&self, tunnel_id: TunnelId) -> Result<Option<TunnelRecord>> {
        let record = sqlx::query_as::<_, TunnelRecord>(
            r#"
            SELECT * FROM tunnels 
            WHERE id = $1
            "#,
        )
        .bind(tunnel_id.0)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }

    /// Update the heartbeat timestamp for a tunnel
    pub async fn heartbeat(&self, tunnel_id: TunnelId) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tunnels 
            SET last_seen_at = NOW()
            WHERE id = $1 AND disconnected_at IS NULL
            "#,
        )
        .bind(tunnel_id.0)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Check if a subdomain is available (not in use and not reserved)
    pub async fn is_subdomain_available(&self, subdomain: &str) -> Result<bool> {
        // Check reserved subdomains
        let reserved: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT subdomain FROM reserved_subdomains WHERE subdomain = $1
            "#,
        )
        .bind(subdomain)
        .fetch_optional(&self.pool)
        .await?;

        if reserved.is_some() {
            return Ok(false);
        }

        // Check active tunnels
        let existing = self.find_by_subdomain(subdomain).await?;
        Ok(existing.is_none())
    }

    /// Get all active tunnels for this server
    pub async fn get_active_tunnels(&self) -> Result<Vec<TunnelRecord>> {
        let records = sqlx::query_as::<_, TunnelRecord>(
            r#"
            SELECT * FROM tunnels 
            WHERE server_id = $1 AND disconnected_at IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .bind(&self.server_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    /// Get count of active tunnels for this server
    pub async fn count_active_tunnels(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM tunnels 
            WHERE server_id = $1 AND disconnected_at IS NULL
            "#,
        )
        .bind(&self.server_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Get count of all active tunnels across all servers
    pub async fn count_all_active_tunnels(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM tunnels WHERE disconnected_at IS NULL
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Mark all tunnels for this server as disconnected (for graceful shutdown)
    pub async fn disconnect_all_server_tunnels(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE tunnels 
            SET disconnected_at = NOW()
            WHERE server_id = $1 AND disconnected_at IS NULL
            "#,
        )
        .bind(&self.server_id)
        .execute(&self.pool)
        .await?;

        let count = result.rows_affected();
        if count > 0 {
            info!("Marked {} tunnels as disconnected during shutdown", count);
        }

        Ok(count)
    }

    /// Log an audit event
    pub async fn log_audit_event(
        &self,
        tunnel_id: Option<TunnelId>,
        event_type: AuditEventType,
        client_ip: Option<&str>,
        details: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_log (tunnel_id, event_type, server_id, client_ip, details)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(tunnel_id.map(|t| t.0))
        .bind(event_type.as_str())
        .bind(&self.server_id)
        .bind(client_ip)
        .bind(details)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Record request statistics
    pub async fn record_request_stats(
        &self,
        tunnel_id: TunnelId,
        bytes_in: i64,
        bytes_out: i64,
        latency_ms: f64,
        is_error: bool,
    ) -> Result<()> {
        // This uses a simplified approach - in production you might want to aggregate
        let now = Utc::now();
        let period_start = now
            .date_naive()
            .and_hms_opt(now.hour(), now.minute() / 5 * 5, 0)
            .unwrap();
        let period_end = period_start + chrono::Duration::minutes(5);

        sqlx::query(
            r#"
            INSERT INTO request_stats (tunnel_id, period_start, period_end, request_count, bytes_in, bytes_out, error_count, avg_latency_ms)
            VALUES ($1, $2, $3, 1, $4, $5, $6, $7)
            ON CONFLICT ON CONSTRAINT request_stats_pkey DO UPDATE SET
                request_count = request_stats.request_count + 1,
                bytes_in = request_stats.bytes_in + EXCLUDED.bytes_in,
                bytes_out = request_stats.bytes_out + EXCLUDED.bytes_out,
                error_count = request_stats.error_count + EXCLUDED.error_count,
                avg_latency_ms = (request_stats.avg_latency_ms * request_stats.request_count + EXCLUDED.avg_latency_ms) / (request_stats.request_count + 1)
            "#,
        )
        .bind(tunnel_id.0)
        .bind(period_start.and_utc())
        .bind(period_end.and_utc())
        .bind(bytes_in)
        .bind(bytes_out)
        .bind(if is_error { 1_i64 } else { 0_i64 })
        .bind(latency_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Log but don't fail on stats recording errors
            warn!("Failed to record request stats: {}", e);
            e
        })?;

        Ok(())
    }

    /// Cleanup old disconnected tunnels
    pub async fn cleanup_old_tunnels(&self, retention_days: i32) -> Result<i64> {
        let (count,): (i32,) = sqlx::query_as("SELECT cleanup_old_tunnels($1)")
            .bind(retention_days)
            .fetch_one(&self.pool)
            .await?;

        if count > 0 {
            info!("Cleaned up {} old tunnel records", count);
        }

        Ok(count as i64)
    }

    /// Cleanup old audit logs
    pub async fn cleanup_old_audit_logs(&self, retention_days: i32) -> Result<i64> {
        let (count,): (i32,) = sqlx::query_as("SELECT cleanup_old_audit_logs($1)")
            .bind(retention_days)
            .fetch_one(&self.pool)
            .await?;

        if count > 0 {
            info!("Cleaned up {} old audit log entries", count);
        }

        Ok(count as i64)
    }

    // === Token Revocation ===

    /// Revoke a token.
    pub async fn revoke_token(
        &self,
        token_id: &str,
        revoked_by: Option<&str>,
        reason: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO revoked_tokens (token_id, revoked_by, reason, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (token_id) DO UPDATE SET
                revoked_at = NOW(),
                revoked_by = EXCLUDED.revoked_by,
                reason = EXCLUDED.reason,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(token_id)
        .bind(revoked_by)
        .bind(reason)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        info!("Token {} revoked", token_id);
        self.log_audit_event(
            None,
            AuditEventType::TokenRevoked,
            None,
            serde_json::json!({"token_id": token_id, "reason": reason}),
        )
        .await?;

        Ok(())
    }

    /// Check if a token is revoked.
    pub async fn is_token_revoked(&self, token_id: &str) -> Result<bool> {
        let result: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM revoked_tokens WHERE token_id = $1
            "#,
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|(count,)| count > 0).unwrap_or(false))
    }

    /// Unrevoke a token (remove from revocation list).
    pub async fn unrevoke_token(&self, token_id: &str) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM revoked_tokens WHERE token_id = $1
            "#,
        )
        .bind(token_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            info!("Token {} unrevoked", token_id);
        }

        Ok(result.rows_affected() > 0)
    }

    /// Cleanup expired revoked tokens.
    pub async fn cleanup_expired_revoked_tokens(&self) -> Result<i64> {
        let result = sqlx::query(
            r#"
            DELETE FROM revoked_tokens
            WHERE expires_at IS NOT NULL AND expires_at < NOW()
            "#,
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            info!("Cleaned up {} expired revoked tokens", result.rows_affected());
        }

        Ok(result.rows_affected() as i64)
    }

    /// Get the database pool for custom queries
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the server ID
    pub fn server_id(&self) -> &str {
        &self.server_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require a test database, so we'll keep these as integration tests
    // Run with: cargo test --features test-db -- --test-threads=1

    #[test]
    fn test_audit_event_type_as_str() {
        assert_eq!(
            AuditEventType::TunnelConnected.as_str(),
            "tunnel_connected"
        );
        assert_eq!(
            AuditEventType::TunnelDisconnected.as_str(),
            "tunnel_disconnected"
        );
        assert_eq!(AuditEventType::AuthFailure.as_str(), "auth_failure");
    }
}

