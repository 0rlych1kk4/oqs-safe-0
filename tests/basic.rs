use oqs_safe::{
    kem::{Kem, KemAlgorithm, KemInstance},
    sig::{SigAlgorithm, SigInstance, SignatureScheme},
};

#[test]
fn ml_kem_768_roundtrip() {
    let kem = KemInstance::new(KemAlgorithm::MlKem768);

    let (pk, sk) = kem.keypair().unwrap();
    let (ct, ss1) = kem.encapsulate(&pk).unwrap();
    let ss2 = kem.decapsulate(&ct, &sk).unwrap();

    assert_eq!(ss1.len(), ss2.len());

    // Size sanity checks for ML-KEM-768 / Kyber768
    assert_eq!(ss1.len(), 32);
    assert_eq!(ct.len(), 1088);
    assert_eq!(pk.len(), 1184);
}

#[test]
fn ml_dsa_44_sign_verify() {
    let sig_scheme = SigInstance::new(SigAlgorithm::MlDsa44);

    let (pk, sk) = sig_scheme.keypair().unwrap();

    let msg = b"hello pqc";
    let sig = sig_scheme.sign(&sk, msg).unwrap();

    sig_scheme.verify(&pk, msg, &sig).unwrap();

    // Size sanity checks for ML-DSA-44 / Dilithium2
    assert_eq!(pk.len(), 1312);
    assert_eq!(sig.len(), 2420);
}

#[cfg(feature = "testing")]
#[test]
fn kyber768_rejects_bad_lengths() {
    use oqs_safe::kem::{Ciphertext, PublicKey, SecretKey};

    // wrong sizes must error (encapsulate expects pk=1184)
    let bad_pk = PublicKey::from_bytes_unchecked(vec![0u8; 42]);
    assert!(Kyber768::encapsulate(&bad_pk).is_err());

    // decapsulate expects ct=1088, sk=2400
    let bad_ct = Ciphertext::from_bytes_unchecked(vec![0u8; 123]);
    let bad_sk = SecretKey::from_bytes_unchecked(vec![0u8; 456]);
    assert!(Kyber768::decapsulate(&bad_ct, &bad_sk).is_err());
}
