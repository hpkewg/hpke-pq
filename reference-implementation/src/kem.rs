use crate::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf};

use concrete_hybrid_kem::utils::RngWrapper;

pub trait Kem {
    const ID: [u8; 2];
    const N_SECRET: usize;
    const N_ENC: usize;
    const N_PK: usize;
    const N_SK: usize;
    const N_SEED: usize;
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

    fn encap(rng: &mut impl rand::CryptoRng, pkR: &Self::EncapsulationKey) -> (Vec<u8>, Vec<u8>);
    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (Vec<u8>, Vec<u8>);
    fn decap(enc: &[u8], skR: &Self::DecapsulationKey) -> Vec<u8>;
}

pub struct KemWithId<K, const ID: u16>(core::marker::PhantomData<K>);

impl<K, const ID: u16> Kem for KemWithId<K, ID>
where
    K: concrete_hybrid_kem::Kem + concrete_hybrid_kem::EncapsDerand,
{
    const ID: [u8; 2] = ID.to_be_bytes();
    const N_SECRET: usize = K::SHARED_SECRET_LENGTH;
    const N_ENC: usize = K::CIPHERTEXT_LENGTH;
    const N_PK: usize = K::ENCAPSULATION_KEY_LENGTH;
    const N_SK: usize = K::DECAPSULATION_KEY_LENGTH;
    const N_SEED: usize = K::SEED_LENGTH;
    const N_RANDOM: usize = K::RANDOMNESS_LENGTH;

    type EncapsulationKey = <K as concrete_hybrid_kem::Kem>::EncapsulationKey;
    type DecapsulationKey = <K as concrete_hybrid_kem::Kem>::DecapsulationKey;

    fn generate_key_pair(
        rng: &mut impl rand::CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (ek, dk) = <K as concrete_hybrid_kem::Kem>::generate_key_pair(rng).unwrap();
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (ek, dk) = <K as concrete_hybrid_kem::Kem>::derive_key_pair(ikm).unwrap();
        (dk, ek)
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        use concrete_hybrid_kem::AsBytes;
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        Self::EncapsulationKey::from(pkXm)
    }

    fn serialize_private_key(skX: &Self::DecapsulationKey) -> Vec<u8> {
        use concrete_hybrid_kem::AsBytes;
        skX.as_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::DecapsulationKey {
        Self::DecapsulationKey::from(skXm)
    }

    fn encap(rng: &mut impl rand::CryptoRng, pkR: &Self::EncapsulationKey) -> (Vec<u8>, Vec<u8>) {
        use concrete_hybrid_kem::AsBytes;
        let (ct, ss) = <K as concrete_hybrid_kem::Kem>::encaps(pkR, rng).unwrap();
        (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
    }

    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use concrete_hybrid_kem::AsBytes;
        let (ct, ss) = <K as concrete_hybrid_kem::EncapsDerand>::encaps_derand(pkR, randomness).unwrap();
        (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
    }

    fn decap(enc: &[u8], skR: &Self::DecapsulationKey) -> Vec<u8> {
        use concrete_hybrid_kem::AsBytes;
        let enc = K::Ciphertext::from(enc);
        <K as concrete_hybrid_kem::Kem>::decaps(skR, &enc)
            .unwrap()
            .as_bytes()
            .to_vec()
    }
}

pub struct MlKemWithId<K, const ID: u16>(core::marker::PhantomData<K>);

impl<K, const ID: u16> Kem for MlKemWithId<K, ID>
where
    K: concrete_hybrid_kem::Kem + concrete_hybrid_kem::EncapsDerand,
{
    const ID: [u8; 2] = ID.to_be_bytes();
    const N_SECRET: usize = K::SHARED_SECRET_LENGTH;
    const N_ENC: usize = K::CIPHERTEXT_LENGTH;
    const N_PK: usize = K::ENCAPSULATION_KEY_LENGTH;
    const N_SK: usize = K::SEED_LENGTH; // Use seed length for ML-KEM per spec
    const N_SEED: usize = K::SEED_LENGTH;
    const N_RANDOM: usize = K::RANDOMNESS_LENGTH;

    type EncapsulationKey = <K as concrete_hybrid_kem::Kem>::EncapsulationKey;
    type DecapsulationKey = <K as concrete_hybrid_kem::Kem>::DecapsulationKey;

    fn generate_key_pair(
        rng: &mut impl rand::CryptoRng,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (ek, dk) = <K as concrete_hybrid_kem::Kem>::generate_key_pair(rng).unwrap();
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (ek, dk) = <K as concrete_hybrid_kem::Kem>::derive_key_pair(ikm).unwrap();
        (dk, ek)
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        use concrete_hybrid_kem::AsBytes;
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        Self::EncapsulationKey::from(pkXm)
    }

    fn serialize_private_key(skX: &Self::DecapsulationKey) -> Vec<u8> {
        use concrete_hybrid_kem::AsBytes;
        skX.as_bytes().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::DecapsulationKey {
        Self::DecapsulationKey::from(skXm)
    }

    fn encap(rng: &mut impl rand::CryptoRng, pkR: &Self::EncapsulationKey) -> (Vec<u8>, Vec<u8>) {
        use concrete_hybrid_kem::AsBytes;
        let (ct, ss) = <K as concrete_hybrid_kem::Kem>::encaps(pkR, rng).unwrap();
        (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
    }

    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use concrete_hybrid_kem::AsBytes;
        let (ct, ss) = <K as concrete_hybrid_kem::EncapsDerand>::encaps_derand(pkR, randomness).unwrap();
        (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
    }

    fn decap(enc: &[u8], skR: &Self::DecapsulationKey) -> Vec<u8> {
        use concrete_hybrid_kem::AsBytes;
        let enc = K::Ciphertext::from(enc);
        <K as concrete_hybrid_kem::Kem>::decaps(skR, &enc)
            .unwrap()
            .as_bytes()
            .to_vec()
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
        let dk = Self::Scalar::random(&mut RngWrapper(rng));
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
        sk.to_bytes().as_slice().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        let sk = generic_array::GenericArray::clone_from_slice(skXm);
        Self::Scalar::from_repr(sk).unwrap()
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
        let dk = Self::Scalar::random(&mut RngWrapper(rng));
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

            let sk_arr = generic_array::GenericArray::clone_from_slice(sk.as_slice());
            let sk = Self::Scalar::from_repr(sk_arr).unwrap();
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
        sk.to_bytes().as_slice().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        let sk = generic_array::GenericArray::clone_from_slice(skXm);
        Self::Scalar::from_repr(sk).unwrap()
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
        let dk = Self::Scalar::random(&mut RngWrapper(rng));
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

            let sk_arr = generic_array::GenericArray::clone_from_slice(sk.as_slice());
            let sk = Self::Scalar::from_repr(sk_arr).unwrap();
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
        sk.to_bytes().as_slice().to_vec()
    }

    fn deserialize_private_key(skXm: &[u8]) -> Self::Scalar {
        let sk = generic_array::GenericArray::clone_from_slice(skXm);
        Self::Scalar::from_repr(sk).unwrap()
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
        let dk = x25519_dalek::StaticSecret::random_from_rng(&mut RngWrapper(rng));
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
    const N_SEED: usize = C::SCALAR_SIZE;
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

    fn encap(rng: &mut impl rand::CryptoRng, pkR: &Self::EncapsulationKey) -> (Vec<u8>, Vec<u8>) {
        use crate::concat;

        let (skE, pkE) = Self::generate_key_pair(rng);
        let dh = C::dh(&skE, pkR);
        let enc = Self::serialize_public_key(&pkE);

        let pkRm = Self::serialize_public_key(pkR);
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = K::extract_and_expand(C::SUITE_ID, &dh, &kem_context, Self::N_SECRET);
        (shared_secret, enc)
    }

    fn encap_derand(pkR: &Self::EncapsulationKey, randomness: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use crate::concat;

        let (skE, pkE) = Self::derive_key_pair(randomness);
        let dh = C::dh(&skE, pkR);
        let enc = Self::serialize_public_key(&pkE);

        let pkRm = Self::serialize_public_key(pkR);
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = K::extract_and_expand(C::SUITE_ID, &dh, &kem_context, Self::N_SECRET);
        (shared_secret, enc)
    }

    fn decap(enc: &[u8], skR: &Self::DecapsulationKey) -> Vec<u8> {
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

pub type MlKem512 = MlKemWithId<concrete_hybrid_kem::MlKem512Kem, 0x0040>;
pub type MlKem768 = MlKemWithId<concrete_hybrid_kem::MlKem768Kem, 0x0041>;
pub type MlKem1024 = MlKemWithId<concrete_hybrid_kem::MlKem1024Kem, 0x0042>;

pub type QsfP256MlKem768 = KemWithId<concrete_hybrid_kem::QsfP256MlKem768Shake256Sha3256, 0x0050>;
pub type QsfP384MlKem1024 = KemWithId<concrete_hybrid_kem::QsfP384MlKem1024Shake256Sha3256, 0x0051>;
pub type QsfX25519MlKem768 =
    KemWithId<concrete_hybrid_kem::QsfX25519MlKem768Shake256Sha3256, 0x647a>;

#[cfg(test)]
mod test {
    use super::*;

    fn test<K>()
    where
        K: Kem,
    {
        let mut rng = rand::rng();

        let (dk, ek) = K::generate_key_pair(&mut rng);

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
        test::<QsfP256MlKem768>();
        test::<QsfX25519MlKem768>();
        test::<QsfP384MlKem1024>();
    }
}
