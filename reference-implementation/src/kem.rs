#![allow(deprecated)] // XXX(RLB) Using old GenericArray, but it's required by the EC libraries

use crate::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf, OneStageKdf, Shake256Core};
use concrete_hybrid_kem::kem::{
    Ciphertext, DecapsulationKey, EncapsDerand, EncapsulationKey, SharedSecret,
};
use generic_array::GenericArray;

// A wrapper that implements CryptoRngCore from rand_core v0.6
struct OldRng<'a, T>(&'a mut T);

impl<'a, T> old_rand_core::CryptoRng for OldRng<'a, T> where T: rand::CryptoRng {}

impl<'a, T> old_rand_core::RngCore for OldRng<'a, T>
where
    T: rand::RngCore,
{
    fn next_u32(&mut self) -> u32 {
        rand::RngCore::next_u32(self.0)
    }

    fn next_u64(&mut self) -> u64 {
        rand::RngCore::next_u64(self.0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::RngCore::fill_bytes(self.0, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), old_rand_core::Error> {
        rand::RngCore::fill_bytes(self.0, dest);
        Ok(())
    }
}

pub trait Kem {
    const ID: [u8; 2];
    const SUITE_ID: &[u8] = &[0x4b, 0x45, 0x4d, Self::ID[0], Self::ID[1]];
    const N_SECRET: usize;
    const N_ENC: usize;
    const N_PK: usize;
    const N_SK: usize;
    const N_RANDOM: usize;

    type EncapsulationKey;
    type DecapsulationKey;

    fn generate_key_pair(
        rng: &mut impl rand::CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey);
    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey);
    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8>;
    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey;
    fn serialize_private_key(skX: &Self::DecapsulationKey) -> Vec<u8>;
    fn deserialize_private_key(skXm: &[u8]) -> Self::DecapsulationKey;

    fn encap(
        rng: &mut impl rand::CryptoRng,
        pkR: &Self::EncapsulationKey,
    ) -> (SharedSecret, Ciphertext);
    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (SharedSecret, Ciphertext);
    fn decap(enc: &Ciphertext, skR: &Self::DecapsulationKey) -> SharedSecret;
}

pub struct KemWithId<K, const ID: u16>(core::marker::PhantomData<K>);

impl<K, const ID: u16> Kem for KemWithId<K, ID>
where
    K: concrete_hybrid_kem::kem::Kem + EncapsDerand,
{
    const ID: [u8; 2] = ID.to_be_bytes();
    const N_SECRET: usize = K::SHARED_SECRET_SIZE;
    const N_ENC: usize = K::CIPHERTEXT_SIZE;
    const N_PK: usize = K::ENCAPSULATION_KEY_SIZE;
    const N_SK: usize = K::DECAPSULATION_KEY_SIZE;
    const N_RANDOM: usize = K::RANDOMNESS_SIZE;

    type EncapsulationKey = EncapsulationKey;
    type DecapsulationKey = DecapsulationKey;

    fn generate_key_pair(
        rng: &mut impl rand::CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (dk, ek, _info) = <K as concrete_hybrid_kem::kem::Kem>::generate_key_pair(rng);
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let seed = Shake256Core::labeled_derive(Self::SUITE_ID, ikm, b"DeriveKeyPair", b"", 32);
        let (dk, ek, _info) = <K as concrete_hybrid_kem::kem::Kem>::derive_key_pair(&seed);
        (dk, ek)
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        pkX.clone()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        EncapsulationKey::from(pkXm)
    }

    fn serialize_private_key(skX: &Self::DecapsulationKey) -> Vec<u8> {
        skX.clone()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::DecapsulationKey {
        DecapsulationKey::from(skXm)
    }

    fn encap(
        rng: &mut impl rand::CryptoRng,
        pkR: &Self::EncapsulationKey,
    ) -> (SharedSecret, Ciphertext) {
        <K as concrete_hybrid_kem::kem::Kem>::encaps(pkR, rng)
    }

    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (SharedSecret, Ciphertext) {
        <K as EncapsDerand>::encaps_derand(pkR, randomness)
    }

    fn decap(enc: &Ciphertext, skR: &Self::DecapsulationKey) -> SharedSecret {
        <K as concrete_hybrid_kem::kem::Kem>::decaps(skR, enc)
    }
}

pub struct MlKemWithId<K, const ID: u16>(core::marker::PhantomData<K>);

impl<K, const ID: u16> MlKemWithId<K, ID>
where
    K: concrete_hybrid_kem::kem::Kem + EncapsDerand,
{
    fn expand_decaps_key(
        dk: &[u8],
    ) -> (
        <Self as Kem>::DecapsulationKey,
        <Self as Kem>::EncapsulationKey,
    ) {
        assert_eq!(dk.len(), Self::N_SK);
        let (dk, ek, info) = K::derive_key_pair(dk);
        (dk, ek)
    }
}

impl<K, const ID: u16> Kem for MlKemWithId<K, ID>
where
    K: concrete_hybrid_kem::kem::Kem + EncapsDerand,
{
    const ID: [u8; 2] = ID.to_be_bytes();
    const N_SECRET: usize = K::SHARED_SECRET_SIZE;
    const N_ENC: usize = K::CIPHERTEXT_SIZE;
    const N_PK: usize = K::ENCAPSULATION_KEY_SIZE;
    const N_SK: usize = K::DECAPSULATION_KEY_SIZE;
    const N_RANDOM: usize = K::RANDOMNESS_SIZE;

    type EncapsulationKey = EncapsulationKey;
    type DecapsulationKey = DecapsulationKey;

    fn generate_key_pair(
        rng: &mut impl rand::CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        use rand::Rng;
        let mut dk = [0; 64];
        rng.fill(&mut dk);
        Self::expand_decaps_key(&dk)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Shake256Core::labeled_derive(Self::SUITE_ID, ikm, b"DeriveKeyPair", b"", 64);
        let (dk, ek, _info) = <K as concrete_hybrid_kem::kem::Kem>::derive_key_pair(&dk);
        (dk, ek)
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        pkX.clone()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        EncapsulationKey::from(pkXm)
    }

    fn serialize_private_key(skX: &Self::DecapsulationKey) -> Vec<u8> {
        skX.clone()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::DecapsulationKey {
        DecapsulationKey::from(skXm)
    }

    fn encap(
        rng: &mut impl rand::CryptoRng,
        pkR: &Self::EncapsulationKey,
    ) -> (SharedSecret, Ciphertext) {
        <K as concrete_hybrid_kem::kem::Kem>::encaps(pkR, rng)
    }

    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (SharedSecret, Ciphertext) {
        <K as EncapsDerand>::encaps_derand(pkR, randomness)
    }

    fn decap(enc: &Ciphertext, skR: &Self::DecapsulationKey) -> SharedSecret {
        let (exanded_dk, _ek, _info) = <K as concrete_hybrid_kem::kem::Kem>::derive_key_pair(skR);
        <K as concrete_hybrid_kem::kem::Kem>::decaps(&exanded_dk, enc)
    }
}

pub trait Curve {
    const N_ID: u16;
    const SUITE_ID: &[u8];
    const SCALAR_SIZE: usize;
    const POINT_SIZE: usize;
    const SECRET_SIZE: usize;

    type Scalar;
    type Point;

    fn generate_key_pair(rng: &mut impl rand::CryptoRng) -> (Self::Scalar, Self::Point);
    fn derive_key_pair<K: Kdf>(ikm: &[u8]) -> (Self::Scalar, Self::Point);
    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8>;
    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point;
    fn serialize_private_key(skX: &Self::Scalar) -> Vec<u8>;
    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar;

    fn base_mult(sk: &Self::Scalar) -> Self::Point;
    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8>;
}

pub struct P256;

impl Curve for P256 {
    const N_ID: u16 = 0x0010;
    const SUITE_ID: &[u8] = b"KEM\x00\x10";
    const SECRET_SIZE: usize = 32;
    const SCALAR_SIZE: usize = 32;
    const POINT_SIZE: usize = 65;

    type Scalar = p256::NonZeroScalar;
    type Point = p256::PublicKey;

    fn generate_key_pair(rng: &mut impl rand::CryptoRng) -> (Self::Scalar, Self::Point) {
        let dk = Self::Scalar::random(&mut OldRng(rng));
        let ek = Self::Point::from_secret_scalar(&dk);
        (dk, ek)
    }

    fn derive_key_pair<K: Kdf>(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        use hex_literal::hex;
        const BITMASK: u8 = 0xff;
        const ORDER: &[u8] =
            &hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

        for counter in 0u8..255 {
            let mut sk = K::derive_candidate(Self::SUITE_ID, ikm, counter, Self::SCALAR_SIZE);
            sk[0] &= BITMASK;
            if sk.as_slice() >= ORDER {
                continue;
            }

            let sk = Self::deserialize_private_key(&sk);
            let pk = Self::Point::from_secret_scalar(&sk);
            return (sk, pk);
        }

        panic!("DeriveKeyPair error");
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        p256::EncodedPoint::from(pkX).as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        p256::PublicKey::from_sec1_bytes(pkXm).unwrap()
    }

    fn serialize_private_key(skX: &Self::Scalar) -> Vec<u8> {
        let sk = p256::SecretKey::from(skX);
        sk.to_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        Self::Scalar::from_repr(*GenericArray::from_slice(skXm)).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        Self::Point::from_secret_scalar(&sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        p256::ecdh::diffie_hellman(sk, pk.as_affine())
            .raw_secret_bytes()
            .to_vec()
    }
}

pub struct P384;

impl Curve for P384 {
    const N_ID: u16 = 0x0011;
    const SUITE_ID: &[u8] = b"KEM\x00\x11";
    const SECRET_SIZE: usize = 48;
    const SCALAR_SIZE: usize = 48;
    const POINT_SIZE: usize = 97;

    type Scalar = p384::NonZeroScalar;
    type Point = p384::PublicKey;

    fn generate_key_pair(rng: &mut impl rand::CryptoRng) -> (Self::Scalar, Self::Point) {
        let dk = Self::Scalar::random(&mut OldRng(rng));
        let ek = Self::Point::from_secret_scalar(&dk);
        (dk, ek)
    }

    fn derive_key_pair<K: Kdf>(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        use hex_literal::hex;
        const BITMASK: u8 = 0xff;
        const ORDER: &[u8] = &hex!("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
                                   "581a0db248b0a77aecec196accc52973");

        for counter in 0u8..255 {
            let mut sk = K::derive_candidate(Self::SUITE_ID, ikm, counter, Self::SCALAR_SIZE);
            sk[0] &= BITMASK;
            if sk.as_slice() >= ORDER {
                continue;
            }

            let sk = Self::Scalar::from_repr(*GenericArray::from_slice(&sk)).unwrap();
            let pk = Self::Point::from_secret_scalar(&sk);
            return (sk, pk);
        }

        panic!("DeriveKeyPair error");
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        p384::EncodedPoint::from(pkX).as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        p384::PublicKey::from_sec1_bytes(pkXm).unwrap()
    }

    fn serialize_private_key(skX: &Self::Scalar) -> Vec<u8> {
        let sk = p384::SecretKey::from(skX);
        sk.to_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        Self::Scalar::from_repr(*GenericArray::from_slice(skXm)).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        Self::Point::from_secret_scalar(&sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        p256::ecdh::diffie_hellman(sk, pk.as_affine())
            .raw_secret_bytes()
            .to_vec()
    }
}

pub struct P521;

impl Curve for P521 {
    const N_ID: u16 = 0x0012;
    const SUITE_ID: &[u8] = b"KEM\x00\x12";
    const SECRET_SIZE: usize = 64;
    const SCALAR_SIZE: usize = 66;
    const POINT_SIZE: usize = 133;

    type Scalar = p521::NonZeroScalar;
    type Point = p521::PublicKey;

    fn generate_key_pair(rng: &mut impl rand::CryptoRng) -> (Self::Scalar, Self::Point) {
        let dk = Self::Scalar::random(&mut OldRng(rng));
        let ek = Self::Point::from_secret_scalar(&dk);
        (dk, ek)
    }

    fn derive_key_pair<K: Kdf>(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        use hex_literal::hex;
        const BITMASK: u8 = 0x01;
        const ORDER: &[u8] = &hex!("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                                   "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409");

        for counter in 0u8..255 {
            let mut sk = K::derive_candidate(Self::SUITE_ID, ikm, counter, Self::SCALAR_SIZE);
            sk[0] &= BITMASK;
            if sk.as_slice() >= ORDER {
                println!("sampled: {}", hex::encode(&sk));
                continue;
            }

            let sk = Self::Scalar::from_repr(*GenericArray::from_slice(&sk)).unwrap();
            let pk = Self::Point::from_secret_scalar(&sk);
            return (sk, pk);
        }

        panic!("DeriveKeyPair error");
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        p521::EncodedPoint::from(pkX).as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        p521::PublicKey::from_sec1_bytes(pkXm).unwrap()
    }

    fn serialize_private_key(skX: &Self::Scalar) -> Vec<u8> {
        let sk = p521::SecretKey::from(skX);
        sk.to_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        Self::Scalar::from_repr(*GenericArray::from_slice(skXm)).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        Self::Point::from_secret_scalar(&sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        p256::ecdh::diffie_hellman(sk, pk.as_affine())
            .raw_secret_bytes()
            .to_vec()
    }
}

pub struct X25519;

impl Curve for X25519 {
    const N_ID: u16 = 0x0020;
    const SUITE_ID: &[u8] = b"KEM\x00\x20";
    const SECRET_SIZE: usize = 32;
    const SCALAR_SIZE: usize = 32;
    const POINT_SIZE: usize = 32;

    type Scalar = x25519_dalek::StaticSecret;
    type Point = x25519_dalek::PublicKey;

    fn generate_key_pair(rng: &mut impl rand::CryptoRng) -> (Self::Scalar, Self::Point) {
        let dk = x25519_dalek::StaticSecret::random_from_rng(rng);
        let ek = x25519_dalek::PublicKey::from(&dk);
        (dk, ek)
    }

    fn derive_key_pair<K: Kdf>(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        let sk_vec = K::derive_sk(Self::SUITE_ID, ikm, Self::SCALAR_SIZE);

        let mut sk_arr = [0_u8; Self::SCALAR_SIZE];
        sk_arr.copy_from_slice(&sk_vec);

        let dk = x25519_dalek::StaticSecret::from(sk_arr);
        let ek = x25519_dalek::PublicKey::from(&dk);
        (dk, ek)
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        let mut pkXb = [0u8; Self::SCALAR_SIZE];
        pkXb.copy_from_slice(pkXm);
        pkXb.into()
    }

    fn serialize_private_key(skX: &Self::Scalar) -> Vec<u8> {
        skX.as_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        let mut skXb = [0u8; Self::POINT_SIZE];
        skXb.copy_from_slice(skXm);
        skXb.into()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        x25519_dalek::PublicKey::from(sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.diffie_hellman(pk).as_bytes().to_vec()
    }
}

pub struct X448;

impl Curve for X448 {
    const N_ID: u16 = 0x0021;
    const SUITE_ID: &[u8] = b"KEM\x00\x21";
    const SECRET_SIZE: usize = 64;
    const SCALAR_SIZE: usize = 56;
    const POINT_SIZE: usize = 56;

    type Scalar = x448::Secret;
    type Point = x448::PublicKey;

    fn generate_key_pair(rng: &mut impl rand::CryptoRng) -> (Self::Scalar, Self::Point) {
        // Can't use x448::Secret::new because of a trait mismatch
        let mut dk = [0; 56];
        rng.fill_bytes(&mut dk);
        let dk = x448::Secret::from(dk);
        let ek = x448::PublicKey::from(&dk);
        (dk, ek)
    }

    fn derive_key_pair<K: Kdf>(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        let sk_vec = K::derive_sk(Self::SUITE_ID, ikm, Self::SCALAR_SIZE);

        let mut sk_arr = [0_u8; Self::SCALAR_SIZE];
        sk_arr.copy_from_slice(&sk_vec);

        let dk = x448::Secret::from(sk_arr);
        let ek = x448::PublicKey::from(&dk);
        (dk, ek)
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        x448::PublicKey::from_bytes(pkXm).unwrap()
    }

    fn serialize_private_key(skX: &Self::Scalar) -> Vec<u8> {
        skX.as_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        x448::Secret::from_bytes(skXm).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        x448::PublicKey::from(sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.as_diffie_hellman(pk).unwrap().as_bytes().to_vec()
    }
}

pub struct Dhkem<C, K>
where
    C: Curve,
    K: Kdf,
{
    _phantom: core::marker::PhantomData<(C, K)>,
}

impl<C, K> Kem for Dhkem<C, K>
where
    C: Curve,
    K: Kdf,
{
    const ID: [u8; 2] = C::N_ID.to_be_bytes();

    const N_SECRET: usize = C::SECRET_SIZE;
    const N_ENC: usize = C::POINT_SIZE;
    const N_PK: usize = C::POINT_SIZE;
    const N_SK: usize = C::SCALAR_SIZE;
    const N_RANDOM: usize = C::SCALAR_SIZE;

    type EncapsulationKey = C::Point;
    type DecapsulationKey = C::Scalar;

    fn generate_key_pair(
        rng: &mut impl rand::CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        C::generate_key_pair(rng)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        C::derive_key_pair::<K>(ikm)
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        C::serialize_public_key(pkX)
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        C::deserialize_public_key(pkXm)
    }

    fn serialize_private_key(skX: &Self::DecapsulationKey) -> Vec<u8> {
        C::serialize_private_key(skX)
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::DecapsulationKey {
        C::deserialize_private_key(skXm)
    }

    fn encap(
        rng: &mut impl rand::CryptoRng,
        pkR: &Self::EncapsulationKey,
    ) -> (SharedSecret, Ciphertext) {
        use crate::concat;

        let (skE, pkE) = Self::generate_key_pair(rng);
        let dh = C::dh(&skE, pkR);
        let enc = Self::serialize_public_key(&pkE);

        let pkRm = Self::serialize_public_key(pkR);
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = K::extract_and_expand(C::SUITE_ID, &dh, &kem_context, Self::N_SECRET);
        (shared_secret, enc)
    }

    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (SharedSecret, Ciphertext) {
        use crate::concat;

        let (skE, pkE) = Self::derive_key_pair(randomness);
        let dh = C::dh(&skE, pkR);
        let enc = Self::serialize_public_key(&pkE);

        let pkRm = Self::serialize_public_key(pkR);
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = K::extract_and_expand(C::SUITE_ID, &dh, &kem_context, Self::N_SECRET);
        (shared_secret, enc)
    }

    fn decap(enc: &Ciphertext, skR: &Self::DecapsulationKey) -> SharedSecret {
        use crate::concat;

        let pkE = Self::deserialize_public_key(&enc);
        let dh = C::dh(skR, &pkE);

        let pkRm = Self::serialize_public_key(&C::base_mult(skR));
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = K::extract_and_expand(C::SUITE_ID, &dh, &kem_context, Self::N_SECRET);
        shared_secret
    }
}

pub type DhkemP256HkdfSha256 = Dhkem<P256, HkdfSha256>;
pub type DhkemP384HkdfSha384 = Dhkem<P384, HkdfSha384>;
pub type DhkemP521HkdfSha512 = Dhkem<P521, HkdfSha512>;
pub type DhkemX25519HkdfSha256 = Dhkem<X25519, HkdfSha256>;
pub type DhkemX448HkdfSha512 = Dhkem<X448, HkdfSha512>;

pub type MlKem512 = MlKemWithId<concrete_hybrid_kem::kem::MlKem512, 0x0040>;
pub type MlKem768 = MlKemWithId<concrete_hybrid_kem::kem::MlKem768, 0x0041>;
pub type MlKem1024 = MlKemWithId<concrete_hybrid_kem::kem::MlKem1024, 0x0042>;

pub type MlKem768P256 = KemWithId<concrete_hybrid_kem::MlKem768P256, 0x0050>;
pub type MlKem1024P384 = KemWithId<concrete_hybrid_kem::MlKem1024P384, 0x0051>;
pub type MlKem768X25519 = KemWithId<concrete_hybrid_kem::MlKem768X25519, 0x647a>;

#[cfg(test)]
mod test {
    use super::*;

    fn test<K>()
    where
        K: Kem,
    {
        let mut rng = rand::rng();
        let (dk, ek) = K::generate_key_pair(&mut rng);

        let ikm = [0xA0; 72];
        let (dk, ek) = K::derive_key_pair(&ikm);

        let ekm = K::serialize_public_key(&ek);
        assert_eq!(ekm.len(), K::N_PK);

        let (ss_s, ct) = K::encap(&mut rng, &ek);
        let ss_r = K::decap(&ct, &dk);
        assert_eq!(ss_s, ss_r);
        assert_eq!(ss_s.len(), K::N_SECRET);
    }

    #[test]
    fn test_all() {
        test::<DhkemP256HkdfSha256>();
        test::<DhkemP384HkdfSha384>();
        test::<DhkemP521HkdfSha512>();
        test::<DhkemX25519HkdfSha256>();
        test::<DhkemX448HkdfSha512>();
        test::<MlKem512>();
        test::<MlKem768>();
        test::<MlKem1024>();
        test::<MlKem768P256>();
        test::<MlKem768X25519>();
        test::<MlKem1024P384>();
    }
}
