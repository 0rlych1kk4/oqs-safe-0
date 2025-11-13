use hkdf::Hkdf;
use oqs_safe::kem::{Kem, Kyber768};
use sha2::Sha256;
use subtle::ConstantTimeEq;

fn hkdf(ss: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(b"oqs-safe context"), ss);
    let mut okm = vec![0u8; out_len];
    hk.expand(label, &mut okm).expect("hkdf expand");
    okm
}

fn main() {
    let (pk, sk) = Kyber768::keypair().expect("keypair");
    let (ct, ss_initiator) = Kyber768::encapsulate(&pk).expect("encaps");
    let ss_responder = Kyber768::decapsulate(&ct, &sk).expect("decaps");

    assert_eq!(
        ss_initiator
            .as_bytes()
            .ct_eq(ss_responder.as_bytes())
            .unwrap_u8(),
        1
    );

    let enc_key = hkdf(ss_initiator.as_bytes(), b"enc", 32);
    let mac_key = hkdf(ss_initiator.as_bytes(), b"mac", 32);

    println!(
        "ok: ct={} enc_key[0..4]={:02x?} mac_key[0..4]={:02x?}",
        ct.len(),
        &enc_key[..4],
        &mac_key[..4]
    );
}
