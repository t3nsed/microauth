//! Cryptographic operations and key management
//! 
//! This module handles all cryptographic operations in a way that's secure by default
//! and requires no cryptographic expertise from the library users.

use ring::aead::{self, UnboundKey, Nonce, NONCE_LEN, Aad, CHACHA20_POLY1305};
use ring::hkdf::{self, HKDF_SHA256};
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use crate::error::Error;

#[derive(Debug, Clone)]
/// Manages encryption keys and operations
pub struct CryptoManager {
    rng: SystemRandom,
    pub key: Vec<u8>,
}

impl CryptoManager {
    /// Create a new crypto manager
    pub fn new(key: Vec<u8>) -> Result<Self, Error> {
        if key.len() != 32 {
            return Err(Error::Crypto("Invalid key length".into()));
        }

        Ok(Self {
            rng: SystemRandom::new(),
            key,
        })
    }

    /// Create a new crypto manager from an existing key
    pub fn from_key(key: Vec<u8>) -> Result<Self, Error> {
        Self::new(key)
    }

    /// Generate a new key
    pub fn generate_key(&self) -> Result<Vec<u8>, Error> {
        let mut key = vec![0u8; 32];
        self.rng
            .fill(&mut key)
            .map_err(|_| Error::Crypto("Failed to generate key".into()))?;
        Ok(key)
    }

    /// Encrypt data using ChaCha20-Poly1305
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let salt = hkdf::Salt::new(HKDF_SHA256, &self.key);
        let prk = salt.extract(&[]);
        let okm = prk.expand(&[b"encryption"], HKDF_SHA256)
            .map_err(|_| Error::Crypto("Failed to expand key".into()))?;

        let mut key_bytes = vec![0u8; 32];
        okm.fill(&mut key_bytes)
            .map_err(|_| Error::Crypto("Failed to fill key bytes".into()))?;

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| Error::Crypto("Failed to create unbound key".into()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| Error::Crypto("Failed to generate nonce".into()))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = data.to_vec();
        let sealing_key = aead::LessSafeKey::new(unbound_key);
        
        sealing_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| Error::Crypto("Failed to seal data".into()))?;

        // Prepend nonce to encrypted data
        let mut result = Vec::with_capacity(NONCE_LEN + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);

        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
        if encrypted_data.len() < NONCE_LEN {
            return Err(Error::Crypto("Invalid encrypted data length".into()));
        }

        let salt = hkdf::Salt::new(HKDF_SHA256, &self.key);
        let prk = salt.extract(&[]);
        let okm = prk.expand(&[b"encryption"], HKDF_SHA256)
            .map_err(|_| Error::Crypto("Failed to expand key".into()))?;

        let mut key_bytes = vec![0u8; 32];
        okm.fill(&mut key_bytes)
            .map_err(|_| Error::Crypto("Failed to fill key bytes".into()))?;

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| Error::Crypto("Failed to create unbound key".into()))?;

        let nonce_bytes = encrypted_data[..NONCE_LEN].try_into()
            .map_err(|_| Error::Crypto("Failed to extract nonce".into()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = encrypted_data[NONCE_LEN..].to_vec();
        let opening_key = aead::LessSafeKey::new(unbound_key);
        
        opening_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| Error::Crypto("Failed to open data".into()))?;

        Ok(in_out)
    }

    pub fn export_key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_export_import() {
        let key = vec![0; 32];
        let manager = CryptoManager::new(key.clone()).unwrap();
        
        // Export key
        let encrypted = manager.encrypt(b"test data").unwrap();
        
        // Import key
        let manager2 = CryptoManager::new(key).unwrap();
        
        // Verify both can encrypt/decrypt
        let decrypted = manager2.decrypt(&encrypted).unwrap();
        assert_eq!(b"test data".as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_invalid_key_import() {
        let key = vec![0; 16];  // Too short
        let manager = CryptoManager::new(key).unwrap();
        assert!(manager.encrypt(b"test data").is_err());
    }

    #[test]
    fn test_crypto_manager_creation() {
        let manager = CryptoManager::new(vec![0; 32]).unwrap();
        assert!(manager.encrypt(b"test data").is_ok());
    }

    #[test]
    fn test_invalid_key_length() {
        let key = vec![0; 16];  // Too short
        let manager = CryptoManager::new(key).unwrap();
        assert!(manager.encrypt(b"test data").is_err());
    }

    #[test]
    fn test_encryption_decryption() {
        let manager = CryptoManager::new(vec![0; 32]).unwrap();
        
        let data = b"Hello, World!";
        let encrypted = manager.encrypt(data).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_data_produces_different_ciphertext() {
        let manager = CryptoManager::new(vec![0; 32]).unwrap();
        
        let data1 = b"Hello, World!";
        let data2 = b"Hello, World?";
        
        let encrypted1 = manager.encrypt(data1).unwrap();
        let encrypted2 = manager.encrypt(data1).unwrap();
        let encrypted3 = manager.encrypt(data2).unwrap();
        
        assert_ne!(encrypted1, encrypted2); // Same data should produce different ciphertext (due to random nonce)
        assert_ne!(encrypted1, encrypted3); // Different data should produce different ciphertext
    }

    #[test]
    fn test_invalid_ciphertext() {
        let manager = CryptoManager::new(vec![0; 32]).unwrap();
        
        let data = b"Hello, World!";
        let mut encrypted = manager.encrypt(data).unwrap();
        
        // Modify the ciphertext
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 1;
        }
        
        assert!(manager.decrypt(&encrypted).is_err());
    }
} 