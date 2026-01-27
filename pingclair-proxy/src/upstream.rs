//! Upstream server management
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// Represents an upstream server
#[derive(Debug)]
pub struct Upstream {
    /// Server address
    pub addr: String,
    /// Weight for load balancing
    pub weight: u32,
    /// Whether the server is healthy
    pub healthy: AtomicBool,
    /// Active connections count
    pub active_connections: AtomicUsize,
}

impl Upstream {
    /// Create a new upstream
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            weight: 1,
            healthy: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
        }
    }

    /// Set the weight
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }
    
    /// Check if healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
    
    /// Set health status
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Relaxed);
    }
    
    /// Get active connection count
    pub fn connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
    
    /// Increment connection count
    pub fn inc_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Decrement connection count
    pub fn dec_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Pool of upstream servers
pub struct UpstreamPool {
    upstreams: Vec<Arc<Upstream>>,
}

impl UpstreamPool {
    /// Create a new upstream pool
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams: upstreams.into_iter().map(Arc::new).collect(),
        }
    }

    /// Get all healthy upstreams
    pub fn healthy(&self) -> Vec<Arc<Upstream>> {
        self.upstreams
            .iter()
            .filter(|u| u.is_healthy())
            .cloned()
            .collect()
    }

    /// Get all upstreams
    pub fn all(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }
}

