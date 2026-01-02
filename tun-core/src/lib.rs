//! Core types and protocols for the tun tunneling service.
//!
//! This crate provides shared functionality between the tunnel server and client,
//! including the wire protocol, authentication, and common utilities.

pub mod auth;
pub mod protocol;

pub use auth::{AuthError, AuthToken, TokenValidator, DEFAULT_TOKEN_TTL_SECONDS};
pub use protocol::{
    HttpMethod, HttpRequestData, HttpResponseData, Message, MessageType, Payload, RequestId,
    StreamChunkData, TunnelId, WebSocketFrameData, WebSocketOpcode,
};

