//! System resource limits management
//!
//! Handles Unix file descriptor limits (ulimit) automatically for high concurrency scanning.

#[cfg(unix)]
use libc::{getrlimit, setrlimit, rlimit, RLIMIT_NOFILE};
use anyhow::Result;

/// Attempt to raise the process file descriptor limit (ulimit -n) to match
/// the requested concurrency (plus some safety overhead).
#[cfg(unix)]
pub fn try_raise_fd_limit(required_concurrency: usize) -> Result<()> {
    unsafe {
        let mut limits = rlimit { rlim_cur: 0, rlim_max: 0 };
        if getrlimit(RLIMIT_NOFILE, &mut limits) != 0 {
            return Err(anyhow::anyhow!("Failed to retrieve file descriptor limits (getrlimit)"));
        }

        // We need at least required_concurrency + extra padding for standard streams,
        // database connections, and libraries.
        let needed = (required_concurrency as u64) + 64;

        if limits.rlim_cur < needed {
            // Cap at hard limit
            let target_limit = needed.min(limits.rlim_max);
            
            let new_limits = rlimit {
                rlim_cur: target_limit,
                rlim_max: limits.rlim_max,
            };

            if setrlimit(RLIMIT_NOFILE, &new_limits) != 0 {
                // If it fails to set, warn the user if current soft limit is indeed insufficient
                if limits.rlim_cur < needed {
                    eprintln!(
                        "⚠️  Warning: Failed to automatically raise file descriptor limit to {}.\n\
                         Current soft limit: {}, Hard limit: {}.\n\
                         You may hit 'Too many open files' error under high concurrency.\n\
                         Consider running 'ulimit -n 65536' in your shell.",
                        needed, limits.rlim_cur, limits.rlim_max
                    );
                }
            } else {
                eprintln!(
                    "🔧 Automatically raised file descriptor limit: {} -> {}",
                    limits.rlim_cur, target_limit
                );
            }
        } else if needed > limits.rlim_max {
            eprintln!(
                "⚠️  Warning: Requested concurrency ({}) requires around {} file descriptors, \
                 but the system hard limit is {}.\n\
                 You may hit resource exhaustion errors. Consider adjusting system limits.",
                required_concurrency, needed, limits.rlim_max
            );
        }
    }
    Ok(())
}

/// No-op fallback for non-Unix operating systems.
#[cfg(not(unix))]
pub fn try_raise_fd_limit(_required_concurrency: usize) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raise_limits_success() {
        // Try requesting a small concurrency that should easily succeed
        let res = try_raise_fd_limit(10);
        assert!(res.is_ok());
    }
}

