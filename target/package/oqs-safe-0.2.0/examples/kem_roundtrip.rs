use oqs_safe::kem::{Kem, Kyber768};

fn main() {
    let (pk, sk) = Kyber768::keypair().expect("keypair");
    let (ct, ss1) = Kyber768::encapsulate(&pk).expect("encaps");
    let ss2 = Kyber768::decapsulate(&ct, &sk).expect("decaps");
    assert_eq!(ss1.len(), ss2.len());
    println!("KEM ok: pk={} ct={} ss={}", pk.len(), ct.len(), ss1.len());
}
