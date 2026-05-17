use crate::{
    hybrid::derive_hybrid_secret,
    kem::{Kem, KemAlgorithm, KemInstance, SecretKey},
    session::SecureSession,
    OqsError,
};

use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const HANDSHAKE_CONTEXT: &[u8] = b"oqs-safe-v0.5.0-hybrid-handshake";
const HANDSHAKE_TRANSCRIPT_DOMAIN: &[u8] = b"oqs-safe-v0.6.0-handshake-transcript";

#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Clone, Debug)]
pub struct ClientHello {
    pub client_x25519_public: Vec<u8>,
    pub client_kem_public: Vec<u8>,
}

#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(Clone, Debug)]
pub struct ServerHello {
    pub server_x25519_public: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

#[cfg(feature = "serialization")]
impl ClientHello {
    pub fn to_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
        bincode::serialize(self).map_err(|_| HandshakeError::InvalidHandshakeState)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        bincode::deserialize(bytes).map_err(|_| HandshakeError::InvalidHandshakeState)
    }
}

#[cfg(feature = "serialization")]
impl ServerHello {
    pub fn to_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
        bincode::serialize(self).map_err(|_| HandshakeError::InvalidHandshakeState)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        bincode::deserialize(bytes).map_err(|_| HandshakeError::InvalidHandshakeState)
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeTranscript {
    hasher: Sha256,
}

impl HandshakeTranscript {
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(HANDSHAKE_TRANSCRIPT_DOMAIN);
        Self { hasher }
    }

    pub fn update_labelled(&mut self, label: &[u8], data: &[u8]) {
        update_len_prefixed(&mut self.hasher, label);
        update_len_prefixed(&mut self.hasher, data);
    }

    pub fn update_algorithm(&mut self, algorithm: KemAlgorithm) {
        self.update_labelled(b"kem_algorithm", format!("{algorithm:?}").as_bytes());
    }

    pub fn update_client_hello(&mut self, client_hello: &ClientHello) {
        self.update_labelled(b"client_x25519_public", &client_hello.client_x25519_public);
        self.update_labelled(b"client_kem_public", &client_hello.client_kem_public);
    }

    pub fn update_server_hello(&mut self, server_hello: &ServerHello) {
        self.update_labelled(b"server_x25519_public", &server_hello.server_x25519_public);
        self.update_labelled(b"kem_ciphertext", &server_hello.kem_ciphertext);
    }

    pub fn finalize(self) -> [u8; 32] {
        let digest = self.hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

impl Default for HandshakeTranscript {
    fn default() -> Self {
        Self::new()
    }
}

fn update_len_prefixed(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u64).to_be_bytes());
    hasher.update(data);
}

fn transcript_bound_context(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut context = Vec::with_capacity(HANDSHAKE_CONTEXT.len() + transcript_hash.len());
    context.extend_from_slice(HANDSHAKE_CONTEXT);
    context.extend_from_slice(transcript_hash);
    context
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
    client_hello: ClientHello,
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

        let client_hello = ClientHello {
            client_x25519_public: client_x25519_public.as_bytes().to_vec(),
            client_kem_public: client_kem_public.as_bytes().to_vec(),
        };

        self.state = Some(ClientHandshakeState {
            x25519_secret: client_x25519_secret,
            kem_secret: client_kem_secret,
            client_hello: client_hello.clone(),
        });

        Ok(client_hello)
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

        let mut transcript = HandshakeTranscript::new();
        transcript.update_algorithm(self.kem.algorithm());
        transcript.update_client_hello(&state.client_hello);
        transcript.update_server_hello(&server_hello);
        let transcript_hash = transcript.finalize();

        let context = transcript_bound_context(&transcript_hash);

        let hybrid_secret = derive_hybrid_secret(
            pqc_secret.as_slice(),
            classical_secret.as_bytes(),
            context.as_slice(),
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

        let server_hello = ServerHello {
            server_x25519_public: server_x25519_public.as_bytes().to_vec(),
            kem_ciphertext,
        };

        let mut transcript = HandshakeTranscript::new();
        transcript.update_algorithm(self.kem.algorithm());
        transcript.update_client_hello(&client_hello);
        transcript.update_server_hello(&server_hello);
        let transcript_hash = transcript.finalize();

        let context = transcript_bound_context(&transcript_hash);

        let hybrid_secret = derive_hybrid_secret(
            pqc_secret.as_slice(),
            classical_secret.as_bytes(),
            context.as_slice(),
        );

        self.session = Some(SecureSession::new(hybrid_secret.as_bytes().to_vec()));

        Ok(server_hello)
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

#[cfg(test)]
mod transcript_tests {
    use super::*;

    #[test]
    fn same_transcript_inputs_produce_same_hash() {
        let client_hello = ClientHello {
            client_x25519_public: vec![1; 32],
            client_kem_public: vec![2; 1184],
        };

        let server_hello = ServerHello {
            server_x25519_public: vec![3; 32],
            kem_ciphertext: vec![4; 1088],
        };

        let mut t1 = HandshakeTranscript::new();
        t1.update_algorithm(KemAlgorithm::MlKem768);
        t1.update_client_hello(&client_hello);
        t1.update_server_hello(&server_hello);

        let mut t2 = HandshakeTranscript::new();
        t2.update_algorithm(KemAlgorithm::MlKem768);
        t2.update_client_hello(&client_hello);
        t2.update_server_hello(&server_hello);

        assert_eq!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn transcript_hash_changes_when_client_hello_changes() {
        let client_hello_a = ClientHello {
            client_x25519_public: vec![1; 32],
            client_kem_public: vec![2; 1184],
        };

        let client_hello_b = ClientHello {
            client_x25519_public: vec![9; 32],
            client_kem_public: vec![2; 1184],
        };

        let server_hello = ServerHello {
            server_x25519_public: vec![3; 32],
            kem_ciphertext: vec![4; 1088],
        };

        let mut t1 = HandshakeTranscript::new();
        t1.update_algorithm(KemAlgorithm::MlKem768);
        t1.update_client_hello(&client_hello_a);
        t1.update_server_hello(&server_hello);

        let mut t2 = HandshakeTranscript::new();
        t2.update_algorithm(KemAlgorithm::MlKem768);
        t2.update_client_hello(&client_hello_b);
        t2.update_server_hello(&server_hello);

        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn transcript_hash_changes_when_server_hello_changes() {
        let client_hello = ClientHello {
            client_x25519_public: vec![1; 32],
            client_kem_public: vec![2; 1184],
        };

        let server_hello_a = ServerHello {
            server_x25519_public: vec![3; 32],
            kem_ciphertext: vec![4; 1088],
        };

        let server_hello_b = ServerHello {
            server_x25519_public: vec![3; 32],
            kem_ciphertext: vec![8; 1088],
        };

        let mut t1 = HandshakeTranscript::new();
        t1.update_algorithm(KemAlgorithm::MlKem768);
        t1.update_client_hello(&client_hello);
        t1.update_server_hello(&server_hello_a);

        let mut t2 = HandshakeTranscript::new();
        t2.update_algorithm(KemAlgorithm::MlKem768);
        t2.update_client_hello(&client_hello);
        t2.update_server_hello(&server_hello_b);

        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn transcript_hash_changes_when_algorithm_changes() {
        let client_hello = ClientHello {
            client_x25519_public: vec![1; 32],
            client_kem_public: vec![2; 1184],
        };

        let server_hello = ServerHello {
            server_x25519_public: vec![3; 32],
            kem_ciphertext: vec![4; 1088],
        };

        let mut t1 = HandshakeTranscript::new();
        t1.update_algorithm(KemAlgorithm::MlKem512);
        t1.update_client_hello(&client_hello);
        t1.update_server_hello(&server_hello);

        let mut t2 = HandshakeTranscript::new();
        t2.update_algorithm(KemAlgorithm::MlKem768);
        t2.update_client_hello(&client_hello);
        t2.update_server_hello(&server_hello);

        assert_ne!(t1.finalize(), t2.finalize());
    }

    #[test]
    fn transcript_bound_context_is_deterministic() {
        let transcript_hash = [7u8; 32];

        let context_a = transcript_bound_context(&transcript_hash);
        let context_b = transcript_bound_context(&transcript_hash);

        assert_eq!(context_a, context_b);
        assert!(context_a.starts_with(HANDSHAKE_CONTEXT));
        assert!(context_a.ends_with(&transcript_hash));
    }
}

#[cfg(all(test, feature = "serialization"))]
mod serialization_tests {
    use super::*;

    #[test]
    fn client_hello_roundtrips_through_bytes() {
        let client_hello = ClientHello {
            client_x25519_public: vec![1; 32],
            client_kem_public: vec![2; 1184],
        };

        let encoded = client_hello
            .to_bytes()
            .expect("client hello should serialize");

        let decoded = ClientHello::from_bytes(&encoded).expect("client hello should deserialize");

        assert_eq!(
            decoded.client_x25519_public,
            client_hello.client_x25519_public
        );
        assert_eq!(decoded.client_kem_public, client_hello.client_kem_public);
    }

    #[test]
    fn server_hello_roundtrips_through_bytes() {
        let server_hello = ServerHello {
            server_x25519_public: vec![3; 32],
            kem_ciphertext: vec![4; 1088],
        };

        let encoded = server_hello
            .to_bytes()
            .expect("server hello should serialize");

        let decoded = ServerHello::from_bytes(&encoded).expect("server hello should deserialize");

        assert_eq!(
            decoded.server_x25519_public,
            server_hello.server_x25519_public
        );
        assert_eq!(decoded.kem_ciphertext, server_hello.kem_ciphertext);
    }

    #[test]
    fn invalid_client_hello_bytes_fail_to_deserialize() {
        let invalid = b"not-a-valid-client-hello";

        assert!(ClientHello::from_bytes(invalid).is_err());
    }

    #[test]
    fn invalid_server_hello_bytes_fail_to_deserialize() {
        let invalid = b"not-a-valid-server-hello";

        assert!(ServerHello::from_bytes(invalid).is_err());
    }
}
