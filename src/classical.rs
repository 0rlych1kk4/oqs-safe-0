use x25519_dalek::{PublicKey, StaticSecret};

pub fn x25519_keypair() -> (PublicKey, StaticSecret) {
    let sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let pk = PublicKey::from(&sk);
    (pk, sk)
}

pub fn x25519_shared_secret(sk: &StaticSecret, pk: &PublicKey) -> [u8; 32] {
    sk.diffie_hellman(pk).to_bytes()
}
