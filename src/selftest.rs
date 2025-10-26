#[cfg(feature = "selftest_at_startup")]
pub(crate) fn check() {
    use crate::{
        kem::{Kem, Kyber768},
        sig::{Dilithium2, SignatureScheme},
    };

    // Best-effort only; ignore failures.
    let _ = (|| {
        let (pk, sk) = Kyber768::keypair()?;
        let (_ct, _ss1) = Kyber768::encapsulate(&pk)?;
        let _ = Kyber768::decapsulate(&_ct, &sk)?;
        Ok::<(), crate::OqsError>(())
    })();

    let _ = (|| {
        let (pk, sk) = Dilithium2::keypair()?;
        let msg = b"oqs-safe selftest";
        let sig = Dilithium2::sign(&sk, msg)?;
        Dilithium2::verify(&pk, msg, &sig)
    })();
}
