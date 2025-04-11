// Error handling module for DSM Storage Node
//
// This module defines error types and utility functions for error handling

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::io;
use std::result;
use thiserror::Error;

/// Result type for DSM Storage Node operations
pub type Result<T> = result::Result<T, StorageNodeError>;

/// Error type for DSM Storage Node operations
#[derive(Debug, Error)]
#[derive(Clone)]
pub enum StorageNodeError {
    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Internal error
    #[error("Internal error")]
    Internal,

    /// Configuration error
    #[error("Configuration error")]
    Configuration,

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Storage-related errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Encryption-related errors
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Distribution-related errors
    #[error("Distribution error: {0}")]
    Distribution(String),

    /// Node management-related errors
    #[error("Node management error: {0}")]
    NodeManagement(String),

    /// Staking-related errors
    #[error("Staking error: {0}")]
    Staking(String),

    /// Authentication-related errors
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Invalid state errors
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Database-related errors
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization-related errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Network-related errors
    #[error("Network error: {0}")]
    Network(String),

    /// IO errors
    #[error("IO error: {0}")]
    IO(String),

    /// JSON errors
    #[error("JSON error: {0}")]
    Json(String),

    /// SQLite errors
    #[error("SQLite error: {0}")]
    Sqlite(String),

    /// HTTP request errors
    #[error("Request error: {0}")]
    Request(String),

    /// Unknown errors
    #[error("Unknown error: {0}")]
    Unknown(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Task cancelled
    #[error("Task cancelled: {0}")]
    TaskCancelled(String),

    /// Task failed
    #[error("Task failed: {0}")]
    TaskFailed(String),

    /// Queue full
    #[error("Queue full: {0}")]
    QueueFull(String),

    /// Receive failure
    #[error("Receive failure: {0}")]
    ReceiveFailure(String),
}

/// Implement IntoResponse for StorageNodeError so it can be returned directly from handlers
impl IntoResponse for StorageNodeError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            StorageNodeError::Timeout => (StatusCode::REQUEST_TIMEOUT, "Operation timed out".to_string()),
            StorageNodeError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
            StorageNodeError::Configuration => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error".to_string()),
            StorageNodeError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            StorageNodeError::InvalidState(msg) => (StatusCode::BAD_REQUEST, msg),
            StorageNodeError::Authentication(msg) => (StatusCode::UNAUTHORIZED, msg),
            StorageNodeError::Storage(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::Encryption(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::Distribution(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::NodeManagement(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::Staking(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::Serialization(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::IO(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
            StorageNodeError::Json(err) => (StatusCode::BAD_REQUEST, err),
            StorageNodeError::Sqlite(err) => (StatusCode::INTERNAL_SERVER_ERROR, err),
            StorageNodeError::Request(err) => (StatusCode::BAD_GATEWAY, err),
            StorageNodeError::Network(err) => (StatusCode::BAD_GATEWAY, err),
            StorageNodeError::Unknown(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::RateLimitExceeded(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            StorageNodeError::TaskCancelled(msg) => (StatusCode::CONFLICT, msg),
            StorageNodeError::TaskFailed(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            StorageNodeError::QueueFull(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            StorageNodeError::ReceiveFailure(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": error_message
            }
        }));

        (status, body).into_response()
    }
}

// Implement conversion from rusqlite error to StorageNodeError
impl From<rusqlite::Error> for StorageNodeError {
    fn from(err: rusqlite::Error) -> Self {
        StorageNodeError::Sqlite(err.to_string())
    }
}

// Implement conversion from io::Error to StorageNodeError
impl From<io::Error> for StorageNodeError {
    fn from(err: io::Error) -> Self {
        StorageNodeError::IO(err.to_string())
    }
}

// Implement conversion from reqwest error to StorageNodeError
impl From<reqwest::Error> for StorageNodeError {
    fn from(err: reqwest::Error) -> Self {
        StorageNodeError::Request(err.to_string())
    }
}

// Implement conversion from toml serialization error to StorageNodeError
impl From<toml::ser::Error> for StorageNodeError {
    fn from(err: toml::ser::Error) -> Self {
        StorageNodeError::Serialization(err.to_string())
    }
}

// Implement conversion from toml deserialization error to StorageNodeError
impl From<toml::de::Error> for StorageNodeError {
    fn from(err: toml::de::Error) -> Self {
        StorageNodeError::Serialization(err.to_string())
    }
}

// Implement conversion from serde_json::Error to StorageNodeError
impl From<serde_json::Error> for StorageNodeError {
    fn from(err: serde_json::Error) -> Self {
        StorageNodeError::Json(err.to_string())
    }
}
