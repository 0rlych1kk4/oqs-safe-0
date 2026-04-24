use oqs_safe::kem::{Kem, KemAlgorithm, KemInstance};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kem = KemInstance::new(KemAlgorithm::MlKem768);

    let (pk, sk) = kem.keypair()?;

    let (ct, ss1) = kem.encapsulate(&pk)?;
    let ss2 = kem.decapsulate(&ct, &sk)?;

    assert_eq!(ss1.len(), ss2.len());

    println!(
        "KEM ok: algorithm={:?} pk={} ct={} ss={}",
        kem.algorithm(),
        pk.len(),
        ct.len(),
        ss1.len()
    );

    Ok(())
}
