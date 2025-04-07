/// A module for time-related utilities.
///
/// Contains functions for working with timestamps, durations, and timeouts.
///
/// # Example   
///
///  ```rust
/// use dsm::utils::time::{now, duration};
///
/// let start = now();
/// let end = now();
/// let duration = duration(start, end);
/// println!("Duration: {} seconds", duration.as_secs());
///  ```
use std::time::{Duration, SystemTime, UNIX_EPOCH};
/// Returns the current timestamp in seconds since the epoch.
///
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns the duration between two timestamps.
///
/// # Arguments
///
/// * `start` - The starting timestamp.
/// * `end` - The ending timestamp.
pub fn duration(start: u64, end: u64) -> Duration {
    Duration::from_secs(end - start)
}
