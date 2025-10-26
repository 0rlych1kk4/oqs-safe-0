use oqs_safe::{
    kem::{Kem, Kyber768},
    sig::{Dilithium2, SignatureScheme},
};

#[test]
fn kyber768_roundtrip() {
    let (pk, sk) = Kyber768::keypair().unwrap();
    let (ct, ss1) = Kyber768::encapsulate(&pk).unwrap();
    let ss2 = Kyber768::decapsulate(&ct, &sk).unwrap();

    assert_eq!(ss1.len(), ss2.len());
    // Size sanity checks (Kyber768)
    assert_eq!(ss1.len(), 32);
    assert_eq!(ct.len(), 1088);
    assert_eq!(pk.len(), 1184);
}

#[test]
fn dilithium2_sign_verify() {
    let (pk, sk) = Dilithium2::keypair().unwrap();
    let msg = b"hello pqc";
    let sig = Dilithium2::sign(&sk, msg).unwrap();
    Dilithium2::verify(&pk, msg, &sig).unwrap();
}

#[cfg(feature = "testing")]
#[test]
fn kyber768_rejects_bad_lengths() {
    use oqs_safe::kem::{Ciphertext, PublicKey, SecretKey};

    // wrong sizes must error (encapsulate expects pk=1184)
    let bad_pk  = PublicKey::from_bytes_unchecked(vec![0u8; 42]);
    assert!(Kyber768::encapsulate(&bad_pk).is_err());

    // decapsulate expects ct=1088, sk=2400
    let bad_ct  = Ciphertext::from_bytes_unchecked(vec![0u8; 123]);
    let bad_sk  = SecretKey::from_bytes_unchecked(vec![0u8; 456]);
    assert!(Kyber768::decapsulate(&bad_ct, &bad_sk).is_err());
}
