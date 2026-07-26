//! Persistent Challenge Handler
//!
//! 💾 ACME Challenge Handler that persists tokens to disk.
//!
//! **Purpose:**
//! Ensures that pending HTTP-01 challenge tokens survive service restarts.
//! This is critical for reliable certificate issuance in production environments.

use parking_lot::RwLock;
use std::sync::Arc;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

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

    /// 🔒 Serializes mutations with their durable snapshot publication.
    persist_lock: Arc<Mutex<()>>,
}

impl PersistentChallengeHandler {
    /// Creates a new persistent handler backed by the specified file path.
    ///
    /// Automatically loads existing tokens from disk if the file exists.
    pub async fn new(storage_path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut tokens = std::collections::HashMap::new();
        
        // 1. Load existing state
        if storage_path.exists() {
            match tokio::fs::read_to_string(&storage_path).await {
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
            tokio::fs::create_dir_all(parent).await?;
        }
        
        let handler = Self {
            tokens: Arc::new(RwLock::new(tokens)),
            storage_path,
            persist_lock: Arc::new(Mutex::new(())),
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
        let _persist_guard = self.persist_lock.lock().await;
        let entry = TokenEntry {
            key_authorization: key_auth,
            created_at: Self::current_time(),
        };
        let previous = self.tokens.write().insert(token.clone(), entry);

        if let Err(error) = self.persist_current().await {
            let mut tokens = self.tokens.write();
            if let Some(previous) = previous {
                tokens.insert(token, previous);
            } else {
                tokens.remove(&token);
            }
            return Err(error);
        }
        tracing::debug!("💾 Persisted ACME token");
        Ok(())
    }
    
    /// Removes a token and updates disk state.
    async fn remove_token(&self, token: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _persist_guard = self.persist_lock.lock().await;
        let previous = self.tokens.write().remove(token);

        if let Err(error) = self.persist_current().await {
            if let Some(previous) = previous {
                self.tokens.write().insert(token.to_string(), previous);
            }
            return Err(error);
        }
        tracing::debug!("🗑️ Removed ACME token");
        Ok(())
    }
    
    /// Serializes current state to JSON file.
    async fn save_tokens(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _persist_guard = self.persist_lock.lock().await;
        self.persist_current().await
    }

    /// 🔐 Publishes the current token snapshot through an atomic private file.
    async fn persist_current(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let storage = TokenStorage {
            tokens: self.tokens.read().clone(),
        };
        let json = serde_json::to_string(&storage)?;
        let storage_path = self.storage_path.clone();
        tokio::task::spawn_blocking(move || {
            crate::secure_file::write_private_file(&storage_path, json.as_bytes())
        })
        .await
        .map_err(|error| std::io::Error::other(format!("challenge writer failed: {error}")))??;
        Ok(())
    }
    
    /// Garbage Collects expired tokens (Older than 24h).
    pub async fn cleanup_expired(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        const TOKEN_TTL_SECS: u64 = 24 * 3600; // 24 hours
        let current_time = Self::current_time();

        let _persist_guard = self.persist_lock.lock().await;
        let original = self.tokens.read().clone();
        let removed_count = {
            let mut tokens = self.tokens.write();
            let before = tokens.len();
            tokens.retain(|_, entry| {
                current_time - entry.created_at < TOKEN_TTL_SECS
            });
            before - tokens.len()
        };

        if removed_count > 0 {
            if let Err(error) = self.persist_current().await {
                *self.tokens.write() = original;
                return Err(error);
            }
            tracing::info!("🧹 GC: Cleaned {} expired challenge tokens", removed_count);
        }

        Ok(())
    }
}

// MARK: - Trait Implementation

#[async_trait::async_trait]
impl crate::acme::ChallengeHandler for PersistentChallengeHandler {
    async fn deploy(&self, challenge: &crate::acme::ChallengeResponse) -> Result<(), crate::acme::AcmeError> {
        self.store_token(
            challenge.token.clone(),
            challenge.key_authorization.clone(),
        )
        .await
        .map_err(|error| {
            crate::acme::AcmeError::ChallengeFailed(format!(
                "Failed to persist HTTP-01 token: {error}"
            ))
        })
    }
    
    async fn cleanup(&self, challenge: &crate::acme::ChallengeResponse) -> Result<(), crate::acme::AcmeError> {
        self.remove_token(&challenge.token).await.map_err(|error| {
            crate::acme::AcmeError::ChallengeFailed(format!(
                "Failed to remove HTTP-01 token: {error}"
            ))
        })
    }
    
    fn get_token(&self, token: &str) -> Option<String> {
        self.tokens
            .read()
            .get(token)
            .map(|entry| entry.key_authorization.clone())
    }
}

// MARK: - Clone

impl Clone for PersistentChallengeHandler {
    fn clone(&self) -> Self {
        Self {
            tokens: self.tokens.clone(),
            storage_path: self.storage_path.clone(),
            persist_lock: self.persist_lock.clone(),
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
        
        handler.deploy(&challenge).await.unwrap();
        
        assert_eq!(handler.get_token("token1"), Some("auth1".into()));

        // 💾 A successful deploy is already durable when the future returns.
        let handler2 = PersistentChallengeHandler::new(storage_path.clone()).await.unwrap();
        assert_eq!(handler2.get_token("token1"), Some("auth1".into()));

        handler.cleanup(&challenge).await.unwrap();
        assert_eq!(handler.get_token("token1"), None);
        let handler3 = PersistentChallengeHandler::new(storage_path.clone()).await.unwrap();
        assert_eq!(handler3.get_token("token1"), None);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(storage_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn failed_persistence_rolls_back_the_visible_token() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("tokens.json");
        let handler = PersistentChallengeHandler::new(storage_path.clone()).await.unwrap();
        std::fs::remove_file(&storage_path).unwrap();
        std::fs::create_dir(&storage_path).unwrap();

        let challenge = crate::acme::ChallengeResponse {
            domain: "example.com".into(),
            challenge_type: crate::acme::ChallengeType::Http01,
            token: "token1".into(),
            key_authorization: "auth1".into(),
        };

        assert!(handler.deploy(&challenge).await.is_err());
        assert_eq!(handler.get_token("token1"), None);
    }
}
