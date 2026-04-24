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
