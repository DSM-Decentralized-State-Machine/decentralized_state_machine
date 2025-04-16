use std::net::IpAddr;
use std::str::FromStr;
use std::task::{Context, Poll};
use axum::{
    extract::Extension,
    http::{Request, header},
    middleware::Next,
    response::Response,
};
use tower::{Layer, Service};
use tracing::debug;

/// Middleware for extracting the real IP address from various headers
/// This handles common proxy headers like X-Forwarded-For, X-Real-IP, etc.
pub async fn extract_real_ip<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Response {
    // IP extraction logic with header priority:
    // 1. X-Forwarded-For (first IP in comma-separated list)
    // 2. X-Real-IP
    // 3. CF-Connecting-IP (Cloudflare)
    // 4. True-Client-IP
    let real_ip = extract_ip_from_headers(&request);
    
    // Add real IP to request extensions
    request.extensions_mut().insert(real_ip);
    
    // Continue to the next middleware or handler
    next.run(request).await
}

/// Extract IP from headers based on a prioritized list
fn extract_ip_from_headers<B>(request: &Request<B>) -> Option<IpAddr> {
    // Extract from X-Forwarded-For (first IP in list)
    if let Some(forwarded) = request.headers().get(header::FORWARDED) {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Parse Forwarded header according to RFC 7239
            for part in forwarded_str.split(';') {
                if let Some(for_part) = part.trim().strip_prefix("for=") {
                    let for_ip = for_part.trim().trim_matches('"');
                    
                    // Remove port if present
                    let ip_str = if for_ip.starts_with('[') {
                        // IPv6 with possible port
                        if let Some(end_bracket) = for_ip.find(']') {
                            &for_ip[1..end_bracket]
                        } else {
                            for_ip
                        }
                    } else if let Some(colon_pos) = for_ip.rfind(':') {
                        // Possible IPv4 with port
                        if for_ip[0..colon_pos].contains('.') {
                            &for_ip[0..colon_pos]
                        } else {
                            for_ip
                        }
                    } else {
                        for_ip
                    };
                    
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        debug!("Extracted IP from Forwarded header: {}", ip);
                        return Some(ip);
                    }
                }
            }
        }
    }
    
    // Extract from X-Forwarded-For header (first IP in comma-separated list)
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                let trimmed = first_ip.trim();
                if let Ok(ip) = IpAddr::from_str(trimmed) {
                    debug!("Extracted IP from X-Forwarded-For header: {}", ip);
                    return Some(ip);
                }
            }
        }
    }
    
    // Extract from X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                debug!("Extracted IP from X-Real-IP header: {}", ip);
                return Some(ip);
            }
        }
    }
    
    // Extract from Cloudflare-specific header
    if let Some(cf_ip) = request.headers().get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_ip.to_str() {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                debug!("Extracted IP from CF-Connecting-IP header: {}", ip);
                return Some(ip);
            }
        }
    }
    
    // Extract from Akamai and others
    if let Some(true_client_ip) = request.headers().get("true-client-ip") {
        if let Ok(ip_str) = true_client_ip.to_str() {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                debug!("Extracted IP from True-Client-IP header: {}", ip);
                return Some(ip);
            }
        }
    }
    
    // No valid IP found in headers
    None
}

/// Layer that adds the extract_real_ip middleware
pub fn extract_real_ip_layer() -> ExtractRealIpLayer {
    ExtractRealIpLayer {}
}

/// Layer implementation for extract_real_ip middleware
#[derive(Clone)]
pub struct ExtractRealIpLayer;

impl<S> Layer<S> for ExtractRealIpLayer {
    type Service = ExtractRealIpService<S>;
    
    fn layer(&self, service: S) -> Self::Service {
        ExtractRealIpService { inner: service }
    }
}

/// Service implementation for extract_real_ip middleware
#[derive(Clone)]
pub struct ExtractRealIpService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for ExtractRealIpService<S>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    
    fn call(&mut self, req: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        
        Box::pin(async move {
            // Extract the real IP
            let real_ip = extract_ip_from_headers(&req);
            
            // Add it to request extensions
            let mut req = req;
            req.extensions_mut().insert(real_ip);
            
            // Continue with the request
            inner.call(req).await
        })
    }
}

/// Advanced IP validation middleware
/// This detects and handles suspicious IP patterns, including:
/// - Private IP ranges trying to appear public
/// - Known proxy/VPN ranges (optional, requires database)
/// - IPv6 to IPv4 mapped addresses
/// - Rate limiting by IP (delegates to rate_limit module)
pub async fn validate_client_ip<B>(
    Extension(_real_ip): Extension<Option<IpAddr>>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    // Implement validation logic here
    // For now, we just pass through all IPs
    
    next.run(request).await
}
