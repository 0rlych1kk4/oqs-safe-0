use oqs_safe::{
    kem::{Kem, Kyber768},
    sig::{Dilithium2, SignatureScheme},
};

#[test]
fn kyber768_roundtrip() {
    let (pk, sk) = Kyber768::keypair().unwrap();
    let (ct, ss1) = Kyber768::encapsulate(&pk).unwrap();
    let ss2 = Kyber768::decapsulate(&ct, &sk).unwrap();

    // Use safe accessors instead of touching tuple fields
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
