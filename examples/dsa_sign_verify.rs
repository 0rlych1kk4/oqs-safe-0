use oqs_safe::sig::{SigAlgorithm, SigInstance, SignatureScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sig_scheme = SigInstance::new(SigAlgorithm::MlDsa44);

    let (pk, sk) = sig_scheme.keypair()?;

    let msg = b"hello pqc";
    let signature = sig_scheme.sign(&sk, msg)?;

    sig_scheme.verify(&pk, msg, &signature)?;

    println!(
        "SIG ok: algorithm={:?} pk={} sig={}",
        sig_scheme.algorithm(),
        pk.len(),
        signature.len()
    );

    Ok(())
}
