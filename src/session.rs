use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub struct SecureSession {
    master: Zeroizing<Vec<u8>>,
}

impl SecureSession {
    pub fn new(master: Vec<u8>) -> Self {
        Self {
            master: Zeroizing::new(master),
        }
    }

    pub fn derive_key(&self, label: &[u8], len: usize) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, &self.master);

        let mut out = vec![0u8; len];
        hk.expand(label, &mut out).unwrap();

        out
    }

    pub fn derive_client_server_keys(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.derive_key(b"client", 32),
            self.derive_key(b"server", 32),
        )
    }
}
