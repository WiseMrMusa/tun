//! TLS configuration and certificate management.

#![allow(dead_code)]

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// ALPN protocols for HTTP/2 and HTTP/1.1
pub static ALPN_H2_H1: &[&[u8]] = &[b"h2", b"http/1.1"];
pub static ALPN_H2: &[&[u8]] = &[b"h2"];
pub static ALPN_H1: &[&[u8]] = &[b"http/1.1"];

/// Load TLS configuration from certificate and key files.
/// Enables HTTP/2 and HTTP/1.1 via ALPN by default.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    load_tls_config_with_alpn(cert_path, key_path, ALPN_H2_H1)
}

/// Load TLS configuration with custom ALPN protocols.
pub fn load_tls_config_with_alpn(
    cert_path: &str,
    key_path: &str,
    alpn_protocols: &[&[u8]],
) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Set ALPN protocols for HTTP/2 negotiation
    config.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();

    info!(
        "TLS configuration loaded with ALPN protocols: {:?}",
        alpn_protocols.iter().map(|p| String::from_utf8_lossy(p)).collect::<Vec<_>>()
    );
    Ok(Arc::new(config))
}

/// Load TLS configuration for HTTP/2 only.
pub fn load_tls_config_h2(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    load_tls_config_with_alpn(cert_path, key_path, ALPN_H2)
}

/// Load certificates from a PEM file.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(Path::new(path))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .filter_map(|cert| cert.ok())
        .collect();

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path);
    }

    info!("Loaded {} certificate(s) from {}", certs.len(), path);
    Ok(certs)
}

/// Load a private key from a PEM file.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(Path::new(path))?;
    let mut reader = BufReader::new(file);

    let key = private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", path))?;

    info!("Loaded private key from {}", path);
    Ok(key)
}

