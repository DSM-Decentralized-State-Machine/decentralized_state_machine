use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::sync::Mutex;
use ratelimit_meter::{DirectRateLimiter, GCRA};
use once_cell::sync::Lazy;
use tracing::{debug, warn};

/// Global rate limiters for IP collections
static GLOBAL_RATE_LIMITERS: Lazy<GlobalRateLimiters> = Lazy::new(|| {
    GlobalRateLimiters::new()
});

/// Rate limiter types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitType {
    /// Rate limit for passive collection endpoints
    Collection,
    
    /// Rate limit for snapshot creation
    SnapshotCreation,
    
    /// Rate limit for admin operations
    AdminOperations,
}

/// Global rate limiters for all limit types
#[derive(Debug)]
pub struct GlobalRateLimiters {
    /// Rate limiting algorithm implementation
    _algorithm: Box<dyn std::fmt::Debug + Send + Sync>,
    /// Per-IP rate limiters for collection endpoints
    collection_limiters: Arc<DashMap<IpAddr, Arc<Mutex<DirectRateLimiter<GCRA>>>>>,
    
    /// Per-IP rate limiters for snapshot creation
    snapshot_limiters: Arc<DashMap<IpAddr, Arc<Mutex<DirectRateLimiter<GCRA>>>>>,
    
    /// Per-IP rate limiters for admin operations
    admin_limiters: Arc<DashMap<IpAddr, Arc<Mutex<DirectRateLimiter<GCRA>>>>>,
    
    /// Last cleanup time
    last_cleanup: Arc<Mutex<Instant>>,
}

impl GlobalRateLimiters {
    /// Create a new set of global rate limiters
    pub fn new() -> Self {
        Self {
            _algorithm: Box::new("GCRA"),
            collection_limiters: Arc::new(DashMap::new()),
            snapshot_limiters: Arc::new(DashMap::new()),
            admin_limiters: Arc::new(DashMap::new()),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    /// Get rate limiter for an IP and type
    pub fn get_limiter(
        &self,
        ip: IpAddr,
        limit_type: RateLimitType,
    ) -> Arc<Mutex<DirectRateLimiter<GCRA>>> {
        // Get the appropriate limiter map
        let limiters = match limit_type {
            RateLimitType::Collection => &self.collection_limiters,
            RateLimitType::SnapshotCreation => &self.snapshot_limiters,
            RateLimitType::AdminOperations => &self.admin_limiters,
        };
        
        // Get or create limiter for this IP
        limiters.entry(ip).or_insert_with(|| {
            // Create a new rate limiter with appropriate quota
            let quota = match limit_type {
                RateLimitType::Collection => (60, Duration::from_secs(60)),  // 1 per second
                RateLimitType::SnapshotCreation => (2, Duration::from_secs(60)),   // 2 per minute
                RateLimitType::AdminOperations => (30, Duration::from_secs(60)),  // 30 per minute
            };
            
            Arc::new(Mutex::new(DirectRateLimiter::<GCRA>::new(std::num::NonZero::new(quota.0).unwrap(), quota.1)))
        }).clone()
    }
    
    /// Check if an operation is rate limited
    pub async fn check_limit(
        &self,
        ip: IpAddr,
        limit_type: RateLimitType,
    ) -> bool {
        // Get the limiter
        let limiter = self.get_limiter(ip, limit_type);
        
        // Check rate limit
        let mut limiter_guard = limiter.lock().await;
        match limiter_guard.check() {
            Ok(_) => {
                // Not rate limited
                debug!("Rate limit check passed for IP {} (type: {:?})", ip, limit_type);
                true
            },
            Err(e) => {
                // Rate limited or other error
                warn!("Rate limited IP {} (type: {:?}): {:?}", ip, limit_type, e);
                false
            }
        }
    }
    
    /// Periodic cleanup of old limiters
    pub async fn cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock().await;
        let now = Instant::now();
        
        // Only clean up every hour
        if now.duration_since(*last_cleanup) < Duration::from_secs(3600) {
            return;
        }
        
        // Update cleanup time
        *last_cleanup = now;
        
        // Clean up collection limiters
        self.collection_limiters.retain(|_, _| {
            // For now, keep all limiters
            // In production, we'd implement a time-based expiration
            true
        });
        
        // Clean up snapshot limiters
        self.snapshot_limiters.retain(|_, _| true);
        
        // Clean up admin limiters
        self.admin_limiters.retain(|_, _| true);
        
        debug!("Rate limiter cleanup completed");
    }
}

/// Rate limiter middleware function
pub async fn check_rate_limit(
    ip: IpAddr,
    limit_type: RateLimitType,
) -> Result<(), String> {
    // Check rate limit
    let limiters = &GLOBAL_RATE_LIMITERS;
    
    if limiters.check_limit(ip, limit_type).await {
        Ok(())
    } else {
        Err(format!("Rate limit exceeded for IP {} (type: {:?})", ip, limit_type))
    }
}
