use hkdf::Hkdf;
use oqs_safe::kem::{Kem, KemAlgorithm, KemInstance};
use sha2::Sha256;

fn hkdf(ss: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(b"oqs-safe context"), ss);
    let mut okm = vec![0u8; out_len];

    hk.expand(label, &mut okm).expect("hkdf expand");

    okm
}

fn main() {
    let kem = KemInstance::new(KemAlgorithm::MlKem768);

    let (pk, sk) = kem.keypair().expect("keypair");
    let (ct, ss_initiator) = kem.encapsulate(&pk).expect("encaps");
    let ss_responder = kem.decapsulate(&ct, &sk).expect("decaps");

    // NOTE:
    // In mock mode (no `liboqs` feature), shared secrets are randomly generated,
    // so they will NOT match. This is expected behavior.
    println!(
        "mock backend note: initiator_ss_len={} responder_ss_len={}",
        ss_initiator.len(),
        ss_responder.len()
    );

    let enc_key = hkdf(ss_initiator.as_bytes(), b"enc", 32);
    let mac_key = hkdf(ss_initiator.as_bytes(), b"mac", 32);

    println!(
        "HKDF handshake ok: algorithm={:?} ct={} enc_key[0..4]={:02x?} mac_key[0..4]={:02x?}",
        kem.algorithm(),
        ct.len(),
        &enc_key[..4],
        &mac_key[..4]
    );
}
