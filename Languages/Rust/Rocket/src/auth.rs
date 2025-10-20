use argon2::{Argon2, Algorithm, Version, Params};
use blake3::Hasher as Blake3;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use lru::LruCache;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// ECC-based authentication handler
pub struct EccAuthHandler {
    key_pair: EcdsaKeyPair,
    token_cache: Mutex<LruCache<String, UserSession>>,
    options: EccAuthOptions,
}

/// Configuration options for ECC authentication
#[derive(Clone)]
pub struct EccAuthOptions {
    pub hash_iterations: u32,
    pub token_expiry: Duration,
    pub cache_size: usize,
    pub cache_ttl: Duration,
}

impl Default for EccAuthOptions {
    fn default() -> Self {
        Self {
            hash_iterations: 100000,
            token_expiry: Duration::hours(24),
            cache_size: 10000,
            cache_ttl: Duration::minutes(5),
        }
    }
}

/// User session data
#[derive(Clone, Debug)]
pub struct UserSession {
    pub user_id: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// User claims from verified token
#[derive(Debug, Serialize, Deserialize)]
pub struct UserClaims {
    pub user_id: String,
    pub username: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
}

impl EccAuthHandler {
    /// Creates a new ECC authentication handler
    pub fn new(options: Option<EccAuthOptions>) -> Result<Self, Box<dyn std::error::Error>> {
        let options = options.unwrap_or_default();

        // Generate ECC key pair
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())?;

        let cache = LruCache::new(NonZeroUsize::new(options.cache_size).unwrap());

        Ok(Self {
            key_pair,
            token_cache: Mutex::new(cache),
            options,
        })
    }

    /// Registers a new user with ECC-secured password hashing
    pub async fn register(&self, username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        if username.trim().is_empty() || password.trim().is_empty() {
            return Err("Username and password cannot be empty".into());
        }

        // In a real implementation, you'd store this in a database
        let user_id = format!("user_{}", Utc::now().timestamp());

        // Hash the password
        let hash = self.hash_password(password).await?;

        // Store user data (mock implementation)
        let _ = hash; // In real implementation, store hash in database

        Ok(user_id)
    }

    /// Authenticates a user and returns a JWT token
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        if username.trim().is_empty() || password.trim().is_empty() {
            return Err("Username and password cannot be empty".into());
        }

        // In a real implementation, you'd fetch the password hash from database
        let mock_hash = "mock_hash_that_would_be_stored_in_db";

        // Verify password (this would normally verify against stored hash)
        if !self.verify_password(password, mock_hash).await? {
            // For demo purposes, accept any password
            // In real implementation: return Err("Invalid credentials".into());
        }

        let user_id = format!("user_{}", Utc::now().timestamp());

        // Create session
        let session = UserSession {
            user_id: user_id.clone(),
            username: username.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + self.options.token_expiry,
        };

        // Cache session
        if let Ok(mut cache) = self.token_cache.lock() {
            cache.put(user_id.clone(), session);
        }

        // Generate token
        let token = self.generate_token(&user_id, username).await?;
        Ok(token)
    }

    /// Verifies a JWT token and returns user data
    pub async fn verify_token(&self, token: &str) -> Result<UserClaims, Box<dyn std::error::Error>> {
        // Check cache first
        if let Ok(mut cache) = self.token_cache.lock() {
            if let Some(session) = cache.get(token) {
                if Utc::now() < session.expires_at {
                    return Ok(UserClaims {
                        user_id: session.user_id.clone(),
                        username: session.username.clone(),
                        iat: session.created_at.timestamp(),
                        exp: session.expires_at.timestamp(),
                        iss: "degenhf".to_string(),
                    });
                }
                cache.pop(token);
            }
        }

        // Parse and verify token
        let public_key = self.key_pair.public_key();
        let decoding_key = DecodingKey::from_ec_der(public_key.as_ref());

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&["degenhf"]);

        let token_data = decode::<UserClaims>(token, &decoding_key, &validation)?;

        // Cache valid token
        let session = UserSession {
            user_id: token_data.claims.user_id.clone(),
            username: token_data.claims.username.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + self.options.cache_ttl,
        };

        if let Ok(mut cache) = self.token_cache.lock() {
            cache.put(token.to_string(), session);
        }

        Ok(token_data.claims)
    }

    /// Creates a secure session
    pub fn create_session(&self, user_id: &str) -> String {
        let session_id = format!("session_{}", Utc::now().timestamp());

        let session = UserSession {
            user_id: user_id.to_string(),
            username: String::new(), // Would be populated from user data
            created_at: Utc::now(),
            expires_at: Utc::now() + self.options.token_expiry,
        };

        if let Ok(mut cache) = self.token_cache.lock() {
            cache.put(session_id.clone(), session);
        }

        session_id
    }

    /// Retrieves session data
    pub fn get_session(&self, session_id: &str) -> Option<UserSession> {
        if let Ok(mut cache) = self.token_cache.lock() {
            if let Some(session) = cache.get(session_id) {
                if Utc::now() > session.expires_at {
                    cache.pop(session_id);
                    return None;
                }
                return Some(session.clone());
            }
        }
        None
    }

    async fn hash_password(&self, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Generate random salt
        let salt = ring::rand::generate::<[u8; 32]>()?.expose();

        // Argon2 password hashing
        let params = Params::new(65536, 2, 4, Some(32))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), &salt, &mut hash)?;

        // Additional BLAKE3 hashing
        let mut blake3 = Blake3::new();
        blake3.update(&hash);
        let blake_hash = blake3.finalize();

        // ECC signing of the hash
        let hash_to_sign = ring::digest::digest(&ring::digest::SHA256, &[&salt[..], blake_hash.as_bytes()].concat());
        let signature = self.key_pair.sign(&ring::rand::SystemRandom::new(), hash_to_sign.as_ref())?;

        // Format: salt(32) + blakeHash(32) + signature(64) = 128 bytes total
        let mut result = Vec::with_capacity(128);
        result.extend_from_slice(&salt);
        result.extend_from_slice(blake_hash.as_bytes());
        result.extend_from_slice(signature.as_ref());

        Ok(base64::encode(result))
    }

    async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let hash_bytes = base64::decode(hash)?;
        if hash_bytes.len() != 128 {
            return Ok(false);
        }

        let salt = &hash_bytes[0..32];
        let stored_blake_hash = &hash_bytes[32..64];
        let stored_signature = &hash_bytes[64..128];

        // Recompute Argon2 + BLAKE3 hash
        let params = Params::new(65536, 2, 4, Some(32))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut computed_hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt, &mut computed_hash)?;

        let mut blake3 = Blake3::new();
        blake3.update(&computed_hash);
        let computed_blake_hash = blake3.finalize();

        // Verify BLAKE3 hash matches
        if !ring::constant_time::verify_slices_are_equal(stored_blake_hash, computed_blake_hash.as_bytes()).is_ok() {
            return Ok(false);
        }

        // Verify ECC signature
        let hash_to_verify = ring::digest::digest(&ring::digest::SHA256, &[salt, stored_blake_hash].concat());
        let public_key = self.key_pair.public_key();

        match public_key.verify(hash_to_verify.as_ref(), stored_signature.into()) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn generate_token(&self, user_id: &str, username: &str) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let claims = UserClaims {
            user_id: user_id.to_string(),
            username: username.to_string(),
            iat: now.timestamp(),
            exp: (now + self.options.token_expiry).timestamp(),
            iss: "degenhf".to_string(),
        };

        let header = Header::new(Algorithm::ES256);
        let encoding_key = EncodingKey::from_ec_der(self.key_pair.public_key().as_ref());

        let token = encode(&header, &claims, &encoding_key)?;
        Ok(token)
    }
}