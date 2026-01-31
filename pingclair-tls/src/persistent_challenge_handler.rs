//! Persistent Challenge Handler
//!
//! 💾 ACME Challenge Handler that persists tokens to disk.
//!
//! **Purpose:**
//! Ensures that pending HTTP-01 challenge tokens survive service restarts.
//! This is critical for reliable certificate issuance in production environments.

use std::sync::Arc;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::fs;
use serde::{Deserialize, Serialize};
use tracing;

// MARK: - internal Types

/// A stored ACME challenge token entry.
#[derive(Clone, Serialize, Deserialize)]
struct TokenEntry {
    /// The authorization key content expected by the ACME server.
    key_authorization: String,
    
    /// Timestamp of creation, used for garbage collection.
    created_at: u64,
}

/// The on-disk serialization format.
#[derive(Serialize, Deserialize)]
struct TokenStorage {
    tokens: std::collections::HashMap<String, TokenEntry>,
}

// MARK: - Challenge Handler

/// A thread-safe handler that persists HTTP-01 tokens to a JSON file.
pub struct PersistentChallengeHandler {
    /// In-memory cache of active tokens.
    tokens: Arc<RwLock<std::collections::HashMap<String, TokenEntry>>>,
    
    /// Path to the persistence file (e.g., `acme-challenges.json`).
    storage_path: PathBuf,
}

impl PersistentChallengeHandler {
    /// Creates a new persistent handler backed by the specified file path.
    ///
    /// Automatically loads existing tokens from disk if the file exists.
    pub async fn new(storage_path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut tokens = std::collections::HashMap::new();
        
        // 1. Load existing state
        if storage_path.exists() {
            match fs::read_to_string(&storage_path).await {
                Ok(content) => {
                    if let Ok(stored) = serde_json::from_str::<TokenStorage>(&content) {
                        tokens = stored.tokens;
                        tracing::info!("💾 Loaded {} persisted ACME tokens", tokens.len());
                    } else {
                        tracing::warn!("⚠️ Corrupt challenge file found, starting fresh");
                    }
                },
                Err(e) => {
                    tracing::warn!("⚠️ Failed to read challenge file: {}", e);
                }
            }
        }
        
        // 2. Ensure directory structure
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        let handler = Self {
            tokens: Arc::new(RwLock::new(tokens)),
            storage_path,
        };
        
        // 3. Initial save (verify write permissions)
        handler.save_tokens().await?;
        
        Ok(handler)
    }
    
    // MARK: - Internal Helpers

    /// Gets current Unix timestamp.
    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs()
    }

    /// Stores a token to memory and flushes to disk.
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
        tracing::debug!("💾 Persisted ACME token");
        Ok(())
    }
    
    /// Removes a token and updates disk state.
    async fn remove_token(&self, token: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut tokens = self.tokens.write().await;
            tokens.remove(token);
        }
        
        self.save_tokens().await?;
        tracing::debug!("🗑️ Removed ACME token");
        Ok(())
    }
    
    /// Serializes current state to JSON file.
    async fn save_tokens(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tokens = self.tokens.read().await;
        let storage = TokenStorage {
            tokens: tokens.clone(),
        };
        
        let json = serde_json::to_string(&storage)?;
        fs::write(&self.storage_path, json).await?;
        
        Ok(())
    }
    
    /// Garbage Collects expired tokens (Older than 24h).
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
            tracing::info!("🧹 GC: Cleaned {} expired challenge tokens", removed_count);
        }

        Ok(())
    }
    
    /// Public async accessor for token retrieval (internal use).
    pub async fn get_token_async(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).map(|entry| entry.key_authorization.clone())
    }
}

// MARK: - Trait Implementation

impl crate::acme::ChallengeHandler for PersistentChallengeHandler {
    fn deploy(&self, challenge: &crate::acme::ChallengeResponse) -> Result<(), crate::acme::AcmeError> {
        let handler = self.clone();
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization.clone();
        
        // IO operations must be spawned to avoid blocking
        tokio::spawn(async move {
            if let Err(e) = handler.store_token(token, key_auth).await {
                tracing::error!("❌ Failed to store persistent challenge: {}", e);
            }
        });
        
        Ok(())
    }
    
    fn cleanup(&self, challenge: &crate::acme::ChallengeResponse) -> Result<(), crate::acme::AcmeError> {
        let handler = self.clone();
        let token = challenge.token.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handler.remove_token(&token).await {
                tracing::error!("❌ Failed to remove persistent challenge: {}", e);
            }
        });
        
        Ok(())
    }
    
    fn get_token(&self, token: &str) -> Option<String> {
        // Sync wrapper for the async internal getter.
        // Required by the synchronous interface of `ChallengeHandler::get_token`
        // which is often called from synchronous router contexts.
        futures::executor::block_on(async {
            self.get_token_async(token).await
        })
    }
}

// MARK: - Clone

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
    use crate::acme::ChallengeHandler;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_persistent_storage() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("tokens.json");
        
        let handler = PersistentChallengeHandler::new(storage_path.clone()).await.unwrap();
        
        let challenge = crate::acme::ChallengeResponse {
            domain: "example.com".into(),
            challenge_type: crate::acme::ChallengeType::Http01,
            token: "token1".into(),
            key_authorization: "auth1".into(),
        };
        
        handler.deploy(&challenge).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        assert_eq!(handler.get_token("token1"), Some("auth1".into()));
        
        // Create new instance pointing to same file
        let handler2 = PersistentChallengeHandler::new(storage_path).await.unwrap();
        assert_eq!(handler2.get_token("token1"), Some("auth1".into()));
    }
}
