use oqs_safe::sig::{Dilithium2, SignatureScheme};

fn main() {
    let (pk, sk) = Dilithium2::keypair().expect("keypair");
    let msg = b"hello pqc";
    let sig = Dilithium2::sign(&sk, msg).expect("sign");
    Dilithium2::verify(&pk, msg, &sig).expect("verify");
    println!("SIG ok: pk={} sig={}", pk.len(), sig.len());
}
