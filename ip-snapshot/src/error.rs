use thiserror::Error;
use std::io;

/// Core error types for the IP snapshot system
#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Geolocation error: {0}")]
    Geolocation(String),
    
    #[error("Fraud detection error: {0}")]
    FraudDetection(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),
    
    #[error("API error: {0}")]
    Api(String),
    
    #[error("Export error: {0}")]
    Export(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Integrity error: {0}")]
    Integrity(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// HTTP errors
#[derive(Error, Debug)]
pub enum HttpError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Too many requests: {0}")]
    TooManyRequests(String),
    
    #[error("Internal server error: {0}")]
    InternalServerError(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl From<HttpError> for SnapshotError {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::BadRequest(msg) => SnapshotError::Validation(msg),
            HttpError::Unauthorized(msg) => SnapshotError::Unauthorized(msg),
            HttpError::Forbidden(msg) => SnapshotError::Unauthorized(msg),
            HttpError::NotFound(msg) => SnapshotError::NotFound(msg),
            HttpError::TooManyRequests(msg) => SnapshotError::RateLimit(msg),
            HttpError::InternalServerError(msg) => SnapshotError::Internal(msg),
            HttpError::ServiceUnavailable(msg) => SnapshotError::Network(msg),
        }
    }
}

/// Export error types
#[derive(Error, Debug)]
pub enum ExportError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    
    #[error("Encoding error: {0}")]
    Encoding(String),
}

impl From<ExportError> for SnapshotError {
    fn from(error: ExportError) -> Self {
        match error {
            ExportError::InvalidFormat(msg) => SnapshotError::Export(msg),
            ExportError::Io(e) => SnapshotError::Io(e),
            ExportError::Serialization(e) => SnapshotError::Serialization(e),
            ExportError::Csv(e) => SnapshotError::Export(e.to_string()),
            ExportError::Encoding(msg) => SnapshotError::Export(msg),
        }
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, SnapshotError>;

/// HTTP response result alias
pub type HttpResult<T> = std::result::Result<T, HttpError>;
