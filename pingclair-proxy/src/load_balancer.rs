//! Load Balancing for Pingclair
//!
//! Wraps Pingora's native `LoadBalancer` to provide a consistent interface for
//! various selection strategies and health checking integration.

use crate::upstream::Upstream;
use crate::health_check::HealthChecker;
use pingora_load_balancing::prelude::RoundRobin;
use pingora_load_balancing::LoadBalancer as NativeLoadBalancer;
use std::sync::Arc;

// MARK: - Types

/// Defines the available load balancing strategies.
#[derive(Debug, Clone, Copy, Default)]
pub enum Strategy {
    /// Distributes requests sequentially across all healthy upstreams.
    #[default]
    RoundRobin,
    /// Selects an upstream at random.
    Random,
}

/// A wrapper around Pingora's `LoadBalancer` to support dynamic strategy selection.
///
/// Currently standardizes on `RoundRobin` as the underlying implementation, but designed
/// to allow future expansion to other strategies via enum dispatch or trait objects.
pub struct LoadBalancer {
    /// The underlying native Pingora load balancer using Round Robin selection.
    native_load_balancer: Arc<NativeLoadBalancer<RoundRobin>>,
}

// MARK: - Implementation

impl LoadBalancer {
    /// Creates a new `LoadBalancer` instance with the specified upstreams and strategy.
    ///
    /// - Parameters:
    ///   - upstreams: A vector of `Upstream` (Backend) instances to balance traffic across.
    ///   - strategy: The selection strategy to use (currently fixed to RoundRobin logic).
    /// - Returns: A configured `LoadBalancer` instance.
    pub fn new(upstreams: Vec<Upstream>, _strategy: Strategy) -> Self {
        // Initialize the native load balancer with the provided upstreams.
        // We use `try_from_iter` to populate the backend list efficiently.
        let native_load_balancer: NativeLoadBalancer<RoundRobin> = 
            NativeLoadBalancer::try_from_iter(upstreams)
            .expect("Failed to initialize NativeLoadBalancer: Invalid upstream configuration");

        Self {
            native_load_balancer: Arc::new(native_load_balancer),
        }
    }

    /// Configures the health checker for this load balancer.
    ///
    /// - Parameter health_checker: The `HealthChecker` instance to use for monitoring upstream health.
    pub fn set_health_check(&mut self, health_checker: HealthChecker) {
        // Attempt to get a mutable reference to the native load balancer.
        // This is safe during initialization before the Arc is shared across threads.
        if let Some(load_balancer) = Arc::get_mut(&mut self.native_load_balancer) {
            load_balancer.set_health_check(Box::new(health_checker));
        } else {
            tracing::warn!("Failed to set health check: LoadBalancer is already shared");
        }
    }

    /// Sets the frequency of health checks.
    ///
    /// - Parameter frequency: The duration interval between health checks.
    pub fn set_health_check_frequency(&mut self, frequency: std::time::Duration) {
        if let Some(load_balancer) = Arc::get_mut(&mut self.native_load_balancer) {
            load_balancer.health_check_frequency = Some(frequency);
        } else {
             tracing::warn!("Failed to set health check frequency: LoadBalancer is already shared");
        }
    }
    
    /// Selects an upstream backend for a request.
    ///
    /// - Parameter key: An optional key for hash-based selection (ignored for Round Robin).
    /// - Returns: An optional `Upstream` if a healthy backend is available.
    pub fn select(&self, _key: Option<&[u8]>) -> Option<Upstream> {
        // RoundRobin strategy does not utilize the selection key.
        self.native_load_balancer.select(b"", 256)
    }
    
    /// Provides access to the underlying native Pingora load balancer.
    ///
    /// Useful for integrating with Pingora's background services.
    pub fn native(&self) -> &Arc<NativeLoadBalancer<RoundRobin>> {
        &self.native_load_balancer
    }
}
