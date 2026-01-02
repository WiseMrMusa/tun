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

/// Load TLS configuration from certificate and key files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    info!("TLS configuration loaded successfully");
    Ok(Arc::new(config))
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

