//! Health checking for upstreams

use std::time::Duration;

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Path to check
    pub path: String,
    /// Check interval
    pub interval: Duration,
    /// Request timeout
    pub timeout: Duration,
    /// Failures before marking unhealthy
    pub threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/health".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            threshold: 3,
        }
    }
}

/// Health checker for upstream servers
pub struct HealthChecker {
    config: HealthCheckConfig,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        Self { config }
    }

    /// Start the health checker background task
    pub fn start(&self, pool: std::sync::Arc<crate::upstream::UpstreamPool>) {
        let config = self.config.clone();
        let pool = pool.clone();
        
        tracing::info!(
            "🚀 Starting health checker with interval {:?}",
            config.interval
        );
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.interval);
            
            loop {
                interval.tick().await;
                
                for upstream in pool.all() {
                    let addr = upstream.addr.clone();
                    let timeout = config.timeout;
                    
                    // Simple TCP check for now
                    // TODO: Implement proper HTTP check using config.path
                    let check = async move {
                        match tokio::time::timeout(
                            timeout,
                            tokio::net::TcpStream::connect(&addr)
                        ).await {
                            Ok(Ok(_)) => true,
                            _ => false,
                        }
                    };
                    
                    let is_healthy = check.await;
                    
                    // Update status
                    if is_healthy != upstream.is_healthy() {
                        upstream.set_healthy(is_healthy);
                        if is_healthy {
                            tracing::info!("✅ Upstream {} is now HEALTHY", upstream.addr);
                        } else {
                            tracing::warn!("❌ Upstream {} is now UNHEALTHY", upstream.addr);
                        }
                    }
                }
            }
        });
    }
}
