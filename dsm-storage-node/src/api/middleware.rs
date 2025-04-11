// API middleware for DSM Storage Node
//
// This module implements middleware for the API server, including authentication,
// rate limiting, and request/response logging.

use crate::error::{Result, StorageNodeError};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{Response, IntoResponse},
};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Rate limiter for API requests
pub struct RateLimiter {
    /// Window size in seconds
    window_size: u64,
    /// Maximum requests per window
    max_requests: u32,
    /// Request counters by client IP
    counters: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(window_size: u64, max_requests: u32) -> Self {
        Self {
            window_size,
            max_requests,
            counters: Mutex::new(HashMap::new()),
        }
    }
    
    /// Increment request count and check rate limit
    pub fn check_rate_limit(&self, client_ip: &str) -> Result<()> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.window_size);
        
        let mut counters = self.counters.lock().unwrap();
        
        // Get or initialize counter for client IP
        let counter = counters
            .entry(client_ip.to_string())
            .or_insert_with(|| (now, 0));
            
        // Reset counter if window has elapsed
        if now.duration_since(counter.0) > window_duration {
            counter.0 = now;
            counter.1 = 0;
        }
        
        // Increment counter
        counter.1 += 1;
        
        // Check if rate limit exceeded
        if counter.1 > self.max_requests {
            return Err(StorageNodeError::RateLimitExceeded(format!(
                "Rate limit exceeded: {} requests per {} seconds",
                self.max_requests, self.window_size
            )));
        }
        
        Ok(())
    }}

/// Get client IP from request
fn get_client_ip(request: &Request<Body>) -> String {
    // Try to get X-Forwarded-For header
    if let Some(header) = request.headers().get("X-Forwarded-For") {
        if let Ok(value) = header.to_str() {
            if let Some(ip) = value.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }
    
    // Fallback to X-Real-IP header
    if let Some(header) = request.headers().get("X-Real-IP") {
        if let Ok(value) = header.to_str() {
            return value.to_string();
        }
    }
    
    // TODO: Get client IP from connection info when axum supports it
    
    // Fallback to unknown
    "unknown".to_string()
}

/// Verify token (placeholder implementation)
fn verify_token(token: &str) -> bool {
    // TODO: Implement token verification using DSM crypto
    // This is a placeholder implementation that accepts all tokens
    !token.is_empty()
}

/// Verify signature (placeholder implementation)
fn verify_signature(signature: &str) -> bool {
    // TODO: Implement signature verification using DSM crypto
    // This is a placeholder implementation that accepts all signatures
    !signature.is_empty()
}

/// Rate limiting middleware
pub async fn rate_limiting(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next<Body>,
) -> Response {
    // Get client IP from headers or connection info
    let client_ip = get_client_ip(&request);
    
    // Check rate limit
    if let Err(_) = limiter.check_rate_limit(&client_ip) {
        warn!("Rate limit exceeded for client {}", client_ip);
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }
    
    // Continue to next middleware or handler
    next.run(request).await
}

/// Authentication middleware
pub async fn authenticate(
    headers: HeaderMap,
    request: Request<Body>,
    next: Next<Body>,
) -> Response {
    // Extract authorization header
    let auth_header = headers.get("Authorization").map(|h| h.to_str().unwrap_or(""));
    
    match auth_header {
        Some(auth) => {
            // Parse authorization header
            let parts: Vec<&str> = auth.splitn(2, ' ').collect();
            if parts.len() != 2 {
                return (StatusCode::UNAUTHORIZED, "Invalid authorization format").into_response();
            }
            
            let auth_type = parts[0];
            let auth_value = parts[1];
            
            // Handle different auth types
            match auth_type {
                "Bearer" => {
                    // Handle token authentication
                    if !verify_token(auth_value) {
                        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
                    }
                },
                "Signature" => {
                    // Handle signature authentication
                    if !verify_signature(auth_value) {
                        return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
                    }
                },
                _ => {
                    return (StatusCode::UNAUTHORIZED, "Unsupported authentication type").into_response();
                }
            }
            
            // Continue to next middleware or handler
            next.run(request).await
        },
        None => {
            // No authentication provided
            (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
        }
    }
}

/// Request logging middleware
pub async fn log_request(
    request: Request<Body>,
    next: Next<Body>,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = Instant::now();
    
    let response = next.run(request).await;
    let duration = start.elapsed();
    
    debug!("Response: {} {} in {:?}", method, uri, duration);
    
    response
}
