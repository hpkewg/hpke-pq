#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

mod aead;
mod kdf;
mod kem;
pub mod test_vectors;

pub use aead::*;
pub use kdf::*;
pub use kem::*;

pub use concrete_hybrid_kem::kem::Ciphertext;
pub use concrete_hybrid_kem::kem::DecapsulationKey;
pub use concrete_hybrid_kem::kem::EncapsulationKey;

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|x| x.len()).sum();
    let mut out = Vec::with_capacity(len);

    for part in parts.iter() {
        out.extend_from_slice(part);
    }

    out
}

fn i2osp(n: usize, w: usize) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut v = vec![0; w];

    if b.len() < v.len() {
        let start = v.len() - b.len();
        v[start..].copy_from_slice(&b);
    } else {
        let start = b.len() - v.len();
        v.copy_from_slice(&b[start..]);
    }

    v
}

fn length_prefixed(x: &[u8]) -> Vec<u8> {
    concat(&[&i2osp(x.len(), 2), x])
}

pub trait Role {}

pub struct Sender;
impl Role for Sender {}

pub struct Receiver;
impl Role for Receiver {}

#[derive(Copy, Clone)]
pub enum Mode {
    Base,
    Psk,
}

impl From<Mode> for u8 {
    fn from(mode: Mode) -> u8 {
        match mode {
            Mode::Base => 0x00,
            Mode::Psk => 0x01,
        }
    }
}

pub struct Context<A, R>
where
    A: Aead,
    R: Role,
{
    pub key: Vec<u8>,
    pub base_nonce: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    seq: usize,
    _aead: core::marker::PhantomData<A>,
    _role: core::marker::PhantomData<R>,
}

impl<A, R> Context<A, R>
where
    A: Aead,
    R: Role,
{
    pub fn new(key: Vec<u8>, base_nonce: Vec<u8>, exporter_secret: Vec<u8>) -> Self {
        Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            _aead: core::marker::PhantomData,
            _role: core::marker::PhantomData,
        }
    }

    // TODO(RLB) Export could go here, but would we would need to make this type generic on the KDF
    // so that we have access to labeled_expand.  And maybe also the KEM so that we can compute a
    // suite_id.

    fn increment_seq(&mut self) {
        // This will never happen in practice, because integers are small
        /*
        if self.seq >= (1 << (8 * A::N_N)) - 1 {
            panic!("Message limit reached");
        }
        */

        // Instead, just check for integer overflow
        self.seq = self.seq.checked_add(1).unwrap();
    }

    pub fn compute_nonce(&self) -> Vec<u8> {
        let mut seq_bytes = i2osp(self.seq, A::N_N);
        for i in 0..A::N_N {
            seq_bytes[i] ^= self.base_nonce[i];
        }
        seq_bytes
    }
}

impl<A> Context<A, Sender>
where
    A: Aead,
{
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let nonce = self.compute_nonce();
        let ct = A::seal(&self.key, &nonce, aad, pt);
        self.increment_seq();
        ct
    }
}

impl<A> Context<A, Receiver>
where
    A: Aead,
{
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let nonce = self.compute_nonce();
        let pt = A::open(&self.key, &nonce, aad, ct);
        self.increment_seq();
        pt
    }
}

pub struct Instance<K, H, A>
where
    K: Kem,
    H: Kdf,
    A: Aead,
{
    _phantom: core::marker::PhantomData<(K, H, A)>,
}

impl<K, H, A> Instance<K, H, A>
where
    K: Kem,
    H: Kdf,
    A: Aead,
{
    pub fn suite_id() -> [u8; 10] {
        let mut suite_id = [0; 10];

        suite_id[0..4].copy_from_slice(b"HPKE");
        suite_id[4..6].copy_from_slice(&K::ID);
        suite_id[6..8].copy_from_slice(&H::ID);
        suite_id[8..10].copy_from_slice(&A::ID);

        suite_id
    }

    fn verify_psk_inputs(mode: Mode, psk: Option<&[u8]>, psk_id: Option<&[u8]>) {
        if psk.is_some() != psk_id.is_some() {
            panic!("Inconsistent PSK inputs");
        }

        if psk.is_some() && matches!(mode, Mode::Base) {
            panic!("PSK input provided when not needed");
        }

        if !psk.is_some() && matches!(mode, Mode::Psk) {
            panic!("Missing required PSK input");
        }
    }

    fn key_schedule<R: Role>(
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
    ) -> Context<A, R> {
        Self::verify_psk_inputs(mode, psk, psk_id);

        let psk = psk.unwrap_or_default();
        let psk_id = psk_id.unwrap_or_default();

        let (key, base_nonce, exporter_secret) = H::combine_secrets(
            &Self::suite_id(),
            mode,
            shared_secret,
            info,
            psk,
            psk_id,
            A::N_K,
            A::N_N,
        );

        Context::new(key, base_nonce, exporter_secret)
    }

    pub fn setup_base_s(
        rng: &mut impl rand::CryptoRng,
        pkR: &K::EncapsulationKey,
        info: &[u8],
    ) -> (Ciphertext, Context<A, Sender>) {
        let (shared_secret, enc) = K::encap(rng, pkR);
        (
            enc,
            Self::key_schedule(Mode::Base, &shared_secret, info, None, None),
        )
    }

    pub fn setup_base_r(
        enc: &Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
    ) -> Context<A, Receiver> {
        let shared_secret = K::decap(enc, skR);
        Self::key_schedule(Mode::Base, &shared_secret, info, None, None)
    }

    pub fn setup_psk_s(
        rng: &mut impl rand::CryptoRng,
        pkR: &K::EncapsulationKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> (Ciphertext, Context<A, Sender>) {
        let (shared_secret, enc) = K::encap(rng, pkR);
        (
            enc,
            Self::key_schedule(Mode::Psk, &shared_secret, info, Some(psk), Some(psk_id)),
        )
    }

    pub fn setup_psk_r(
        enc: &Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Context<A, Receiver> {
        let shared_secret = K::decap(enc, skR);
        Self::key_schedule(Mode::Psk, &shared_secret, info, Some(psk), Some(psk_id))
    }

    pub fn seal_base(
        rng: &mut impl rand::CryptoRng,
        pkR: &K::EncapsulationKey,
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> (Ciphertext, Vec<u8>) {
        let (enc, mut ctx) = Self::setup_base_s(rng, pkR, info);
        let ct = ctx.seal(aad, pt);
        (enc, ct)
    }

    pub fn open_base(
        enc: &Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Vec<u8> {
        let mut ctx = Self::setup_base_r(enc, skR, info);
        ctx.open(aad, ct)
    }

    pub fn seal_psk(
        rng: &mut impl rand::CryptoRng,
        pkR: &K::EncapsulationKey,
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> (Ciphertext, Vec<u8>) {
        let (enc, mut ctx) = Self::setup_psk_s(rng, pkR, info, psk, psk_id);
        let ct = ctx.seal(aad, pt);
        (enc, ct)
    }

    pub fn open_psk(
        enc: &Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Vec<u8> {
        let mut ctx = Self::setup_psk_r(enc, skR, info, psk, psk_id);
        ctx.open(aad, ct)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test<K, H, A>()
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        let mut rng = rand::rng();

        let info = b"And turning toward the window, should say";
        let aad = b"That is not it at all";
        let pt = b"That is not what I meant, at all";

        let psk = b"I should have been a pair of ragged claws";
        let psk_id = b"Scuttling across the floors of silent seas";

        let (dk, ek) = K::generate_key_pair(&mut rng);

        // Base
        let (enc, ct) = Instance::<K, H, A>::seal_base(&mut rng, &ek, info, aad, pt);
        assert_eq!(ct.len(), pt.len() + A::N_T);

        let pt_out = Instance::<K, H, A>::open_base(&enc, &dk, info, aad, &ct);
        assert_eq!(pt, pt_out.as_slice());

        // PSK
        let (enc, ct) = Instance::<K, H, A>::seal_psk(&mut rng, &ek, info, aad, pt, psk, psk_id);
        assert_eq!(ct.len(), pt.len() + A::N_T);

        let pt_out = Instance::<K, H, A>::open_psk(&enc, &dk, info, aad, &ct, psk, psk_id);
        assert_eq!(pt, pt_out.as_slice());
    }

    #[test]
    fn test_all() {
        test::<DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm>();
        test::<DhkemP384HkdfSha384, HkdfSha384, Aes256Gcm>();
        test::<DhkemP521HkdfSha512, HkdfSha512, Aes256Gcm>();
        test::<DhkemX25519HkdfSha256, HkdfSha256, ChaChaPoly>();
        test::<DhkemX448HkdfSha512, HkdfSha512, ChaChaPoly>();
        test::<MlKem768, HkdfSha256, Aes128Gcm>();

        test::<DhkemP256HkdfSha256, Shake128, Aes128Gcm>();
        test::<DhkemP384HkdfSha384, Shake256, Aes256Gcm>();
        test::<DhkemX25519HkdfSha256, TurboShake128, Aes128Gcm>();
        test::<DhkemX448HkdfSha512, TurboShake256, Aes256Gcm>();
    }
}
