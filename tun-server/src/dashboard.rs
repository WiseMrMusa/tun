//! Built-in WebUI dashboard for monitoring tunnels.
//!
//! Provides a simple HTML dashboard that displays tunnel status,
//! metrics, and allows basic management operations.

use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

/// Dashboard HTML template.
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tun Server Dashboard</title>
    <style>
        :root {
            --bg-primary: #0f1419;
            --bg-secondary: #1a2634;
            --bg-tertiary: #243447;
            --text-primary: #e7e9ea;
            --text-secondary: #8899a6;
            --accent-primary: #1d9bf0;
            --accent-success: #00ba7c;
            --accent-warning: #ffad1f;
            --accent-danger: #f4212e;
            --border-color: #38444d;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            border-bottom: 1px solid var(--border-color);
            padding: 1.5rem 0;
            margin-bottom: 2rem;
        }
        
        header h1 {
            font-size: 1.75rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        header h1 span.logo {
            font-size: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            transition: transform 0.2s, border-color 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent-primary);
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            font-variant-numeric: tabular-nums;
        }
        
        .stat-value.success { color: var(--accent-success); }
        .stat-value.warning { color: var(--accent-warning); }
        .stat-value.danger { color: var(--accent-danger); }
        
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-tertiary);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-title {
            font-size: 1.125rem;
            font-weight: 600;
        }
        
        .refresh-btn {
            background: var(--accent-primary);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: opacity 0.2s;
        }
        
        .refresh-btn:hover {
            opacity: 0.9;
        }
        
        .tunnel-list {
            list-style: none;
        }
        
        .tunnel-item {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr auto;
            align-items: center;
            gap: 1rem;
        }
        
        .tunnel-item:last-child {
            border-bottom: none;
        }
        
        .tunnel-subdomain {
            font-weight: 600;
            color: var(--accent-primary);
        }
        
        .tunnel-id {
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
        }
        
        .status-badge.active {
            background: rgba(0, 186, 124, 0.15);
            color: var(--accent-success);
        }
        
        .status-badge::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: currentColor;
        }
        
        .empty-state {
            padding: 3rem;
            text-align: center;
            color: var(--text-secondary);
        }
        
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 1rem;
            opacity: 0.5;
        }
        
        @media (max-width: 768px) {
            .tunnel-item {
                grid-template-columns: 1fr;
                gap: 0.5rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr 1fr;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1><span class="logo">🚇</span> Tun Server Dashboard</h1>
        </div>
    </header>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Active Tunnels</div>
                <div class="stat-value success" id="tunnelCount">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Pending Requests</div>
                <div class="stat-value" id="pendingRequests">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value" id="totalRequests">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Uptime</div>
                <div class="stat-value" id="uptime">-</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Active Tunnels</h2>
                <button class="refresh-btn" onclick="refreshTunnels()">↻ Refresh</button>
            </div>
            <ul class="tunnel-list" id="tunnelList">
                <li class="empty-state">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                    <div>Loading tunnels...</div>
                </li>
            </ul>
        </div>
    </div>
    
    <script>
        async function refreshTunnels() {
            try {
                const response = await fetch('/api/tunnels');
                const tunnels = await response.json();
                
                document.getElementById('tunnelCount').textContent = tunnels.length;
                
                const list = document.getElementById('tunnelList');
                
                if (tunnels.length === 0) {
                    list.innerHTML = `
                        <li class="empty-state">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                            </svg>
                            <div>No active tunnels</div>
                        </li>
                    `;
                    return;
                }
                
                list.innerHTML = tunnels.map(tunnel => `
                    <li class="tunnel-item">
                        <div>
                            <div class="tunnel-subdomain">${tunnel.subdomain}</div>
                            <div class="tunnel-id">${tunnel.id}</div>
                        </div>
                        <div class="status-badge active">Connected</div>
                        <div>${tunnel.connected_since || 'N/A'}</div>
                        <div>${tunnel.client_ip || 'N/A'}</div>
                        <div>${tunnel.pending_requests || 0} pending</div>
                    </li>
                `).join('');
            } catch (error) {
                console.error('Failed to fetch tunnels:', error);
                document.getElementById('tunnelList').innerHTML = `
                    <li class="empty-state">
                        <div>Failed to load tunnels</div>
                    </li>
                `;
            }
        }
        
        function updateUptime() {
            const start = new Date();
            setInterval(() => {
                const diff = Math.floor((new Date() - start) / 1000);
                const hours = Math.floor(diff / 3600);
                const mins = Math.floor((diff % 3600) / 60);
                const secs = diff % 60;
                document.getElementById('uptime').textContent = 
                    `${hours}h ${mins}m ${secs}s`;
            }, 1000);
        }
        
        // Initialize
        refreshTunnels();
        updateUptime();
        
        // Auto-refresh every 30 seconds
        setInterval(refreshTunnels, 30000);
    </script>
</body>
</html>"#;

/// Create the dashboard router.
pub fn dashboard_router() -> Router {
    Router::new()
        .route("/", get(dashboard_handler))
        .route("/dashboard", get(dashboard_handler))
}

/// Serve the dashboard HTML.
async fn dashboard_handler() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_html_valid() {
        assert!(DASHBOARD_HTML.contains("<!DOCTYPE html>"));
        assert!(DASHBOARD_HTML.contains("</html>"));
        assert!(DASHBOARD_HTML.contains("Tun Server Dashboard"));
    }
}

