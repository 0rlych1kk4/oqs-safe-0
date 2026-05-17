use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

#[cfg(feature = "aead")]
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

pub struct SecureSession {
    master: Zeroizing<Vec<u8>>,
}

impl SecureSession {
    pub fn new(master: Vec<u8>) -> Self {
        Self {
            master: Zeroizing::new(master),
        }
    }

    pub fn derive_key(&self, label: &[u8], len: usize) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, &self.master);

        let mut out = vec![0u8; len];
        hk.expand(label, &mut out).unwrap();

        out
    }

    pub fn derive_client_server_keys(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.derive_key(b"client", 32),
            self.derive_key(b"server", 32),
        )
    }

    #[cfg(feature = "aead")]
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SessionAeadError> {
        let key = self.derive_key(b"oqs-safe-session-aead-key", 32);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SessionAeadError::InvalidKey)?;

        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| SessionAeadError::EncryptionFailed)
    }

    #[cfg(feature = "aead")]
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SessionAeadError> {
        let key = self.derive_key(b"oqs-safe-session-aead-key", 32);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SessionAeadError::InvalidKey)?;

        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| SessionAeadError::DecryptionFailed)
    }
}

#[cfg(feature = "aead")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAeadError {
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
}

#[cfg(feature = "aead")]
impl core::fmt::Display for SessionAeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionAeadError::InvalidKey => write!(f, "invalid AEAD key"),
            SessionAeadError::EncryptionFailed => write!(f, "AEAD encryption failed"),
            SessionAeadError::DecryptionFailed => write!(f, "AEAD decryption failed"),
        }
    }
}

#[cfg(feature = "aead")]
impl std::error::Error for SessionAeadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_client_server_keys() {
        let session = SecureSession::new(vec![7u8; 32]);

        let (client_key, server_key) = session.derive_client_server_keys();

        assert_eq!(client_key.len(), 32);
        assert_eq!(server_key.len(), 32);
        assert_ne!(client_key, server_key);
    }

    #[test]
    fn derive_key_is_deterministic_for_same_label() {
        let session = SecureSession::new(vec![7u8; 32]);

        let key_a = session.derive_key(b"test-label", 32);
        let key_b = session.derive_key(b"test-label", 32);

        assert_eq!(key_a, key_b);
    }

    #[test]
    fn derive_key_changes_with_label() {
        let session = SecureSession::new(vec![7u8; 32]);

        let key_a = session.derive_key(b"label-a", 32);
        let key_b = session.derive_key(b"label-b", 32);

        assert_ne!(key_a, key_b);
    }

    #[cfg(feature = "aead")]
    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let session = SecureSession::new(vec![9u8; 32]);
        let nonce = [1u8; 12];
        let plaintext = b"post-quantum secure session message";
        let aad = b"oqs-safe-aead-test";

        let ciphertext = session
            .encrypt(&nonce, plaintext, aad)
            .expect("encryption should succeed");

        assert_ne!(ciphertext, plaintext);

        let decrypted = session
            .decrypt(&nonce, &ciphertext, aad)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "aead")]
    #[test]
    fn aead_decryption_fails_with_wrong_aad() {
        let session = SecureSession::new(vec![9u8; 32]);
        let nonce = [1u8; 12];
        let plaintext = b"post-quantum secure session message";

        let ciphertext = session
            .encrypt(&nonce, plaintext, b"correct-aad")
            .expect("encryption should succeed");

        let result = session.decrypt(&nonce, &ciphertext, b"wrong-aad");

        assert_eq!(result, Err(SessionAeadError::DecryptionFailed));
    }

    #[cfg(feature = "aead")]
    #[test]
    fn aead_decryption_fails_with_wrong_nonce() {
        let session = SecureSession::new(vec![9u8; 32]);
        let nonce = [1u8; 12];
        let wrong_nonce = [2u8; 12];
        let plaintext = b"post-quantum secure session message";
        let aad = b"oqs-safe-aead-test";

        let ciphertext = session
            .encrypt(&nonce, plaintext, aad)
            .expect("encryption should succeed");

        let result = session.decrypt(&wrong_nonce, &ciphertext, aad);

        assert_eq!(result, Err(SessionAeadError::DecryptionFailed));
    }

    #[cfg(feature = "aead")]
    #[test]
    fn aead_decryption_fails_with_different_session() {
        let sender_session = SecureSession::new(vec![9u8; 32]);
        let receiver_session = SecureSession::new(vec![8u8; 32]);
        let nonce = [1u8; 12];
        let plaintext = b"post-quantum secure session message";
        let aad = b"oqs-safe-aead-test";

        let ciphertext = sender_session
            .encrypt(&nonce, plaintext, aad)
            .expect("encryption should succeed");

        let result = receiver_session.decrypt(&nonce, &ciphertext, aad);

        assert_eq!(result, Err(SessionAeadError::DecryptionFailed));
    }
}
