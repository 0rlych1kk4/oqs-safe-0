use crate::{
    hybrid::derive_hybrid_secret,
    kem::{Kem, KemAlgorithm, KemInstance, SecretKey},
    session::SecureSession,
    OqsError,
};

use rand_core::OsRng;
#[cfg(not(feature = "liboqs"))]
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_CONTEXT: &[u8] = b"oqs-safe-v0.5.0-hybrid-handshake";

#[derive(Clone, Debug)]
pub struct ClientHello {
    pub client_x25519_public: Vec<u8>,
    pub client_kem_public: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ServerHello {
    pub server_x25519_public: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum HandshakeError {
    MissingClientState,
    MissingServerState,
    InvalidHandshakeState,
    CryptoError(OqsError),
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::MissingClientState => write!(f, "missing client handshake state"),
            HandshakeError::MissingServerState => write!(f, "missing server handshake state"),
            HandshakeError::InvalidHandshakeState => write!(f, "invalid handshake state"),
            HandshakeError::CryptoError(err) => write!(f, "cryptographic operation failed: {err}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<OqsError> for HandshakeError {
    fn from(value: OqsError) -> Self {
        HandshakeError::CryptoError(value)
    }
}

pub struct HybridClient {
    kem: KemInstance,
    state: Option<ClientHandshakeState>,
}

struct ClientHandshakeState {
    x25519_secret: StaticSecret,
    kem_secret: SecretKey,
}

impl HybridClient {
    pub fn new() -> Self {
        Self {
            kem: KemInstance::new(KemAlgorithm::MlKem768),
            state: None,
        }
    }

    pub fn with_algorithm(algorithm: KemAlgorithm) -> Self {
        Self {
            kem: KemInstance::new(algorithm),
            state: None,
        }
    }

    pub fn start_handshake(&mut self) -> Result<ClientHello, HandshakeError> {
        let client_x25519_secret = StaticSecret::random_from_rng(OsRng);
        let client_x25519_public = X25519PublicKey::from(&client_x25519_secret);

        let (client_kem_public, client_kem_secret) = self.kem.keypair()?;

        self.state = Some(ClientHandshakeState {
            x25519_secret: client_x25519_secret,
            kem_secret: client_kem_secret,
        });

        Ok(ClientHello {
            client_x25519_public: client_x25519_public.as_bytes().to_vec(),
            client_kem_public: client_kem_public.as_bytes().to_vec(),
        })
    }

    pub fn finish(&mut self, server_hello: ServerHello) -> Result<SecureSession, HandshakeError> {
        let state = self
            .state
            .take()
            .ok_or(HandshakeError::MissingClientState)?;

        if server_hello.server_x25519_public.len() != 32 || server_hello.kem_ciphertext.is_empty() {
            return Err(HandshakeError::InvalidHandshakeState);
        }

        let server_public_bytes: [u8; 32] = server_hello
            .server_x25519_public
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::InvalidHandshakeState)?;

        let server_x25519_public = X25519PublicKey::from(server_public_bytes);
        let classical_secret = state.x25519_secret.diffie_hellman(&server_x25519_public);

        let pqc_secret = client_pqc_secret(
            self.kem.algorithm(),
            &server_hello.kem_ciphertext,
            &state.kem_secret,
        )?;

        let hybrid_secret = derive_hybrid_secret(
            pqc_secret.as_slice(),
            classical_secret.as_bytes(),
            HANDSHAKE_CONTEXT,
        );

        Ok(SecureSession::new(hybrid_secret.as_bytes().to_vec()))
    }
}

impl Default for HybridClient {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HybridServer {
    kem: KemInstance,
    session: Option<SecureSession>,
}

impl HybridServer {
    pub fn new() -> Self {
        Self {
            kem: KemInstance::new(KemAlgorithm::MlKem768),
            session: None,
        }
    }

    pub fn with_algorithm(algorithm: KemAlgorithm) -> Self {
        Self {
            kem: KemInstance::new(algorithm),
            session: None,
        }
    }

    pub fn respond(&mut self, client_hello: ClientHello) -> Result<ServerHello, HandshakeError> {
        if client_hello.client_x25519_public.len() != 32
            || client_hello.client_kem_public.is_empty()
        {
            return Err(HandshakeError::InvalidHandshakeState);
        }

        let client_public_bytes: [u8; 32] = client_hello
            .client_x25519_public
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::InvalidHandshakeState)?;

        let client_x25519_public = X25519PublicKey::from(client_public_bytes);

        let server_x25519_secret = StaticSecret::random_from_rng(OsRng);
        let server_x25519_public = X25519PublicKey::from(&server_x25519_secret);

        let classical_secret = server_x25519_secret.diffie_hellman(&client_x25519_public);

        let (kem_ciphertext, pqc_secret) =
            server_pqc_secret(self.kem.algorithm(), &client_hello.client_kem_public)?;

        let hybrid_secret = derive_hybrid_secret(
            pqc_secret.as_slice(),
            classical_secret.as_bytes(),
            HANDSHAKE_CONTEXT,
        );

        self.session = Some(SecureSession::new(hybrid_secret.as_bytes().to_vec()));

        Ok(ServerHello {
            server_x25519_public: server_x25519_public.as_bytes().to_vec(),
            kem_ciphertext,
        })
    }

    pub fn session(&self) -> Result<&SecureSession, HandshakeError> {
        self.session
            .as_ref()
            .ok_or(HandshakeError::MissingServerState)
    }
}

impl Default for HybridServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "liboqs")]
fn server_pqc_secret(
    algorithm: KemAlgorithm,
    client_kem_public: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HandshakeError> {
    use crate::kem::PublicKey;

    let kem = KemInstance::new(algorithm);
    let client_public_key = PublicKey::new(algorithm, client_kem_public.to_vec());

    let (ciphertext, shared_secret) = kem.encapsulate(&client_public_key)?;

    Ok((
        ciphertext.as_bytes().to_vec(),
        shared_secret.as_bytes().to_vec(),
    ))
}

#[cfg(feature = "liboqs")]
fn client_pqc_secret(
    algorithm: KemAlgorithm,
    kem_ciphertext: &[u8],
    kem_secret: &SecretKey,
) -> Result<Vec<u8>, HandshakeError> {
    use crate::kem::Ciphertext;

    let kem = KemInstance::new(algorithm);
    let ciphertext = Ciphertext::new(algorithm, kem_ciphertext.to_vec());

    let shared_secret = kem.decapsulate(&ciphertext, kem_secret)?;

    Ok(shared_secret.as_bytes().to_vec())
}

#[cfg(not(feature = "liboqs"))]
fn server_pqc_secret(
    algorithm: KemAlgorithm,
    client_kem_public: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HandshakeError> {
    let ciphertext = mock_ciphertext(algorithm, client_kem_public);
    let shared_secret = mock_shared_secret(algorithm, &ciphertext);

    Ok((ciphertext, shared_secret))
}

#[cfg(not(feature = "liboqs"))]
fn client_pqc_secret(
    algorithm: KemAlgorithm,
    kem_ciphertext: &[u8],
    kem_secret: &SecretKey,
) -> Result<Vec<u8>, HandshakeError> {
    let _ = kem_secret;

    Ok(mock_shared_secret(algorithm, kem_ciphertext))
}

#[cfg(not(feature = "liboqs"))]
fn mock_ciphertext(algorithm: KemAlgorithm, client_kem_public: &[u8]) -> Vec<u8> {
    let mut ciphertext = vec![0u8; algorithm.ciphertext_len()];
    let mut counter = 0u64;
    let mut offset = 0usize;

    while offset < ciphertext.len() {
        let mut hasher = Sha256::new();
        hasher.update(b"oqs-safe-v0.5.0-mock-ciphertext");
        hasher.update(client_kem_public);
        hasher.update(counter.to_le_bytes());

        let block = hasher.finalize();
        let take = core::cmp::min(block.len(), ciphertext.len() - offset);

        ciphertext[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter += 1;
    }

    ciphertext
}

#[cfg(not(feature = "liboqs"))]
fn mock_shared_secret(algorithm: KemAlgorithm, kem_ciphertext: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.update(b"oqs-safe-v0.5.0-mock-pqc-secret");
    hasher.update(format!("{algorithm:?}").as_bytes());
    hasher.update(kem_ciphertext);

    hasher.finalize().to_vec()
}
