//! Core types and protocols for the tun tunneling service.
//!
//! This crate provides shared functionality between the tunnel server and client,
//! including the wire protocol, authentication, and common utilities.

pub mod auth;
pub mod protocol;

pub use auth::{AuthToken, TokenValidator};
pub use protocol::{Message, MessageType, TunnelId};

