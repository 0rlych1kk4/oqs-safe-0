use oqs_safe::{
    hybrid::derive_hybrid_secret,
    kem::{Kem, KemAlgorithm, KemInstance},
};

use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("oqs-safe hybrid X25519 + ML-KEM example");

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

    // NOTE:
    // In mock mode, ML-KEM shared secrets may not match because the mock backend
    // generates random shared secrets. With the real liboqs backend, they should match.
    if client_pq_secret.as_bytes() == server_pq_secret.as_bytes() {
        println!("ML-KEM shared secrets match");
    } else {
        println!("ML-KEM shared secrets do not match in mock mode; this is expected");
    }

    // ------------------------------------------------------------
    // 3. Hybrid secret derivation
    // ------------------------------------------------------------

    let context = b"oqs-safe-v0.4-hybrid-x25519-mlkem768";

    let client_hybrid_secret = derive_hybrid_secret(
        client_pq_secret.as_bytes(),
        client_classical_secret.as_bytes(),
        context,
    );

    let server_hybrid_secret = derive_hybrid_secret(
        server_pq_secret.as_bytes(),
        server_classical_secret.as_bytes(),
        context,
    );

    println!(
        "Client hybrid secret length: {}",
        client_hybrid_secret.len()
    );

    println!(
        "Server hybrid secret length: {}",
        server_hybrid_secret.len()
    );

    if client_hybrid_secret.as_bytes() == server_hybrid_secret.as_bytes() {
        println!("Hybrid X25519 + ML-KEM shared secret established successfully");
    } else {
        println!("Hybrid secrets differ because the mock ML-KEM backend does not produce matching secrets");
        println!("Run with the real liboqs backend for a true end-to-end match");
    }

    Ok(())
}
