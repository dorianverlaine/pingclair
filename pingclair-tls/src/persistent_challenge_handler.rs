//! Persistent ACME challenge handler that stores tokens to disk
//!
//! 💾 Ensures challenge tokens survive service restarts

use std::sync::Arc;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::fs;
use serde::{Deserialize, Serialize};
use tracing;

/// Token entry with expiration tracking
#[derive(Clone, Serialize, Deserialize)]
struct TokenEntry {
    key_authorization: String,
    /// Unix timestamp when this token was created
    created_at: u64,
}

/// Persistent challenge handler that stores tokens to disk
pub struct PersistentChallengeHandler {
    tokens: Arc<RwLock<std::collections::HashMap<String, TokenEntry>>>,
    storage_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct TokenStorage {
    tokens: std::collections::HashMap<String, TokenEntry>,
}

impl PersistentChallengeHandler {
    /// Create a new persistent challenge handler
    pub async fn new(storage_path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut tokens = std::collections::HashMap::new();
        
        // Load existing tokens from storage
        if storage_path.exists() {
            let content = fs::read_to_string(&storage_path).await?;
            if let Ok(stored) = serde_json::from_str::<TokenStorage>(&content) {
                tokens = stored.tokens;
                tracing::info!("💾 Loaded {} challenge tokens from persistent storage", tokens.len());
            }
        }
        
        // Ensure storage directory exists
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        let handler = Self {
            tokens: Arc::new(RwLock::new(tokens)),
            storage_path,
        };
        
        // Save current tokens to ensure file exists
        handler.save_tokens().await?;
        
        Ok(handler)
    }
    
    /// Get token for a given path
    pub async fn get_token(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).map(|entry| entry.key_authorization.clone())
    }

    /// Get current unix timestamp
    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs()
    }

    /// Store token to both memory and persistent storage
    async fn store_token(&self, token: String, key_auth: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut tokens = self.tokens.write().await;
            let entry = TokenEntry {
                key_authorization: key_auth,
                created_at: Self::current_time(),
            };
            tokens.insert(token.clone(), entry);
        }

        self.save_tokens().await?;
        tracing::info!("💾 Stored challenge token to persistent storage");
        Ok(())
    }
    
    /// Remove token from both memory and persistent storage
    async fn remove_token(&self, token: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut tokens = self.tokens.write().await;
            tokens.remove(token);
        }
        
        self.save_tokens().await?;
        Ok(())
    }
    
    /// Save tokens to persistent storage
    async fn save_tokens(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tokens = self.tokens.read().await;
        let storage = TokenStorage {
            tokens: tokens.clone(),
        };
        
        let json = serde_json::to_string(&storage)?;
        fs::write(&self.storage_path, json).await?;
        
        Ok(())
    }
    
    /// Clean up expired tokens (older than 24 hours) and save
    pub async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        const TOKEN_TTL_SECS: u64 = 24 * 3600; // 24 hours
        let current_time = Self::current_time();

        let removed_count = {
            let mut tokens = self.tokens.write().await;
            let before = tokens.len();
            tokens.retain(|_, entry| {
                current_time - entry.created_at < TOKEN_TTL_SECS
            });
            before - tokens.len()
        };

        if removed_count > 0 {
            self.save_tokens().await?;
            tracing::info!("🧹 Cleaned up {} expired challenge tokens", removed_count);
        }

        Ok(())
    }
}

impl Drop for PersistentChallengeHandler {
    fn drop(&mut self) {
        // Attempt to save tokens on shutdown
        // Note: This won't work for async operations in Drop, so we rely on explicit cleanup
        // In production, you'd want to handle graceful shutdown properly
    }
}

/// Implementation of the challenge handler trait
impl crate::acme::ChallengeHandler for PersistentChallengeHandler {
    fn deploy(&self, challenge: &crate::acme::ChallengeResponse) -> Result<(), crate::acme::AcmeError> {
        let handler = self.clone();
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handler.store_token(token, key_auth).await {
                tracing::error!("Failed to store challenge token: {}", e);
            }
        });
        
        Ok(())
    }
    
    fn cleanup(&self, challenge: &crate::acme::ChallengeResponse) -> Result<(), crate::acme::AcmeError> {
        let handler = self.clone();
        let token = challenge.token.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handler.remove_token(&token).await {
                tracing::error!("Failed to remove challenge token: {}", e);
            }
        });
        
        Ok(())
    }
    
    fn get_token(&self, token: &str) -> Option<String> {
        // Use a blocking call to get the token synchronously
        futures::executor::block_on(async {
            let tokens = self.tokens.read().await;
            tokens.get(token).map(|entry| entry.key_authorization.clone())
        })
    }
}

impl Clone for PersistentChallengeHandler {
    fn clone(&self) -> Self {
        Self {
            tokens: self.tokens.clone(),
            storage_path: self.storage_path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::ChallengeHandler; // Import the trait
    use tempfile::tempdir;
    use std::path::Path;

    #[tokio::test]
    async fn test_persistent_challenge_handler() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("challenge_tokens.json");
        
        let handler = PersistentChallengeHandler::new(storage_path.clone()).await.unwrap();
        
        let challenge = crate::acme::ChallengeResponse {
            domain: "example.com".to_string(),
            challenge_type: crate::acme::ChallengeType::Http01,
            token: "test-token".to_string(),
            key_authorization: "test-auth".to_string(),
        };
        
        // Deploy challenge
        handler.deploy(&challenge).unwrap();
        
        // Wait a bit for async operation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Verify token is stored - use async get_token
        let result = handler.get_token("test-token").await;
        assert_eq!(result, Some("test-auth".to_string()));
        
        // Cleanup challenge
        handler.cleanup(&challenge).unwrap();
        
        // Wait a bit for async operation
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Verify token is removed
        assert_eq!(handler.get_token("test-token").await, None);
    }
    
    #[tokio::test]
    async fn test_persistence_across_instances() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("challenge_tokens.json");
        
        // Create first handler and store a token
        {
            let handler = PersistentChallengeHandler::new(storage_path.clone()).await.unwrap();
            let challenge = crate::acme::ChallengeResponse {
                domain: "example.com".to_string(),
                challenge_type: crate::acme::ChallengeType::Http01,
                token: "persist-token".to_string(),
                key_authorization: "persist-auth".to_string(),
            };
            
            handler.deploy(&challenge).unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        
        // Create second handler and verify token persists
        {
            let handler = PersistentChallengeHandler::new(storage_path).await.unwrap();
            assert_eq!(handler.get_token("persist-token").await, Some("persist-auth".to_string()));
        }
    }
}
