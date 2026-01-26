//! Cryptographic utilities for WireGuard key management

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use x25519_dalek::{PublicKey, StaticSecret};

/// WireGuard key pair
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl KeyPair {
    /// Generate a new WireGuard key pair using x25519
    pub fn generate() -> Self {
        // Generate random private key
        let secret = StaticSecret::random_from_rng(rand::thread_rng());

        // Derive public key from private key
        let public = PublicKey::from(&secret);

        // Encode as base64 (WireGuard format)
        let private_key = BASE64.encode(secret.as_bytes());
        let public_key = BASE64.encode(public.as_bytes());

        Self {
            private_key,
            public_key,
        }
    }

    /// Create KeyPair from existing private key (base64 encoded)
    pub fn from_private_key(private_key_b64: &str) -> Result<Self, &'static str> {
        let bytes = BASE64
            .decode(private_key_b64)
            .map_err(|_| "Invalid base64")?;

        if bytes.len() != 32 {
            return Err("Private key must be 32 bytes");
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        let secret = StaticSecret::from(key_bytes);
        let public = PublicKey::from(&secret);

        Ok(Self {
            private_key: private_key_b64.to_string(),
            public_key: BASE64.encode(public.as_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();

        // Keys should be base64 encoded 32 bytes = 44 chars (with padding)
        assert_eq!(kp.private_key.len(), 44);
        assert_eq!(kp.public_key.len(), 44);

        // Private and public keys should be different
        assert_ne!(kp.private_key, kp.public_key);
    }

    #[test]
    fn test_keypair_from_private_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::from_private_key(&kp1.private_key).unwrap();

        // Should derive the same public key
        assert_eq!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_deterministic_derivation() {
        // Same private key should always produce same public key
        let private = "YBKaGeYm2c8cJTEhSqWHXaEQEEGh5kF8JZvYL3MWOVU=";
        let kp1 = KeyPair::from_private_key(private).unwrap();
        let kp2 = KeyPair::from_private_key(private).unwrap();

        assert_eq!(kp1.public_key, kp2.public_key);
    }
}
