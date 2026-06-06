use hkdf::Hkdf;
use oqs_safe::{
    hybrid::derive_hybrid_secret,
    kem::{Kem, KemAlgorithm, KemInstance},
    sig::{SigAlgorithm, SigInstance, SignatureScheme},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn derive_key(secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(b"oqs-safe-v0.7-authenticated-handshake"), secret);
    let mut okm = vec![0u8; out_len];

    hk.expand(label, &mut okm)
        .expect("HKDF expansion should succeed");

    okm
}

fn transcript_hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();

    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }

    hasher.finalize().to_vec()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("oqs-safe authenticated hybrid handshake example");
    println!("Version theme: v0.7.0 — Authenticated Hybrid Handshake");

    // ------------------------------------------------------------
    // 1. Classical X25519 key exchange
    // ------------------------------------------------------------

    let client_x25519_sk = StaticSecret::random_from_rng(OsRng);
    let client_x25519_pk = X25519PublicKey::from(&client_x25519_sk);

    let server_x25519_sk = StaticSecret::random_from_rng(OsRng);
    let server_x25519_pk = X25519PublicKey::from(&server_x25519_sk);

    let client_classical_secret = client_x25519_sk.diffie_hellman(&server_x25519_pk);
    let server_classical_secret = server_x25519_sk.diffie_hellman(&client_x25519_pk);

    assert_eq!(
        client_classical_secret.as_bytes(),
        server_classical_secret.as_bytes()
    );

    println!("X25519 exchange complete");

    // ------------------------------------------------------------
    // 2. Post-quantum ML-KEM key exchange
    // ------------------------------------------------------------

    let kem = KemInstance::new(KemAlgorithm::MlKem768);

    let (server_pq_pk, server_pq_sk) = kem.keypair()?;

    let (ciphertext, client_pq_secret) = kem.encapsulate(&server_pq_pk)?;
    let server_pq_secret = kem.decapsulate(&ciphertext, &server_pq_sk)?;

    println!(
        "ML-KEM exchange complete: algorithm={:?}, ciphertext_len={}",
        kem.algorithm(),
        ciphertext.len()
    );

    if client_pq_secret.as_bytes() == server_pq_secret.as_bytes() {
        println!("ML-KEM shared secrets match");
    } else {
        println!("ML-KEM shared secrets do not match in mock mode; this is expected");
    }

    // ------------------------------------------------------------
    // 3. Build transcript and bind handshake context
    // ------------------------------------------------------------

    let handshake_context = b"oqs-safe-v0.7-authenticated-hybrid-handshake";

    let transcript = transcript_hash(&[
        handshake_context,
        client_x25519_pk.as_bytes(),
        server_x25519_pk.as_bytes(),
        server_pq_pk.as_bytes(),
        ciphertext.as_bytes(),
    ]);

    println!("Transcript hash created: {} bytes", transcript.len());

    // ------------------------------------------------------------
    // 4. Authenticate the transcript using ML-DSA
    // ------------------------------------------------------------

    let sig_scheme = SigInstance::new(SigAlgorithm::MlDsa44);

    let (server_sig_pk, server_sig_sk) = sig_scheme.keypair()?;

    let transcript_signature = sig_scheme.sign(&server_sig_sk, &transcript)?;

    sig_scheme.verify(&server_sig_pk, &transcript, &transcript_signature)?;

    println!(
        "Transcript authentication complete: algorithm={:?}, signature_len={}",
        sig_scheme.algorithm(),
        transcript_signature.len()
    );

    // ------------------------------------------------------------
    // 5. Derive hybrid secrets
    // ------------------------------------------------------------

    let client_hybrid_secret = derive_hybrid_secret(
        client_pq_secret.as_bytes(),
        client_classical_secret.as_bytes(),
        &transcript,
    );

    let server_hybrid_secret = derive_hybrid_secret(
        server_pq_secret.as_bytes(),
        server_classical_secret.as_bytes(),
        &transcript,
    );

    println!(
        "Client hybrid secret length: {}",
        client_hybrid_secret.len()
    );

    println!(
        "Server hybrid secret length: {}",
        server_hybrid_secret.len()
    );

    // ------------------------------------------------------------
    // 6. Derive directional session keys
    // ------------------------------------------------------------

    let client_tx_key = derive_key(client_hybrid_secret.as_bytes(), b"client-to-server", 32);
    let client_rx_key = derive_key(client_hybrid_secret.as_bytes(), b"server-to-client", 32);

    let server_rx_key = derive_key(server_hybrid_secret.as_bytes(), b"client-to-server", 32);
    let server_tx_key = derive_key(server_hybrid_secret.as_bytes(), b"server-to-client", 32);

    println!("Client TX key prefix: {:02x?}", &client_tx_key[..4]);
    println!("Client RX key prefix: {:02x?}", &client_rx_key[..4]);
    println!("Server RX key prefix: {:02x?}", &server_rx_key[..4]);
    println!("Server TX key prefix: {:02x?}", &server_tx_key[..4]);

    if client_hybrid_secret.as_bytes() == server_hybrid_secret.as_bytes() {
        assert_eq!(client_tx_key, server_rx_key);
        assert_eq!(client_rx_key, server_tx_key);

        println!("Authenticated hybrid session established successfully");
    } else {
        println!("Hybrid session keys differ because the mock ML-KEM backend does not produce matching secrets");
        println!(
            "Run with the real liboqs backend for a true end-to-end authenticated session match"
        );
    }

    println!("Authenticated hybrid handshake example completed");

    Ok(())
}
