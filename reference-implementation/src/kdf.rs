pub trait OneStageKdf {
    const ID: [u8; 2];
    const N_H: usize;

    fn derive(ikm: &[u8], len: usize) -> Vec<u8>;

    fn labeled_derive(
        suite_id: &[u8],
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        use crate::{concat, i2osp, length_prefixed};

        let labeled_ikm = concat(&[
            ikm,
            b"HPKE_v1",
            suite_id,
            &length_prefixed(label),
            &i2osp(len, 2),
            context,
        ]);

        Self::derive(&labeled_ikm, len)
    }
}

pub trait TwoStageKdf {
    const ID: [u8; 2];
    const N_H: usize;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8>;
    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8>;

    fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
        use crate::concat;
        let labeled_ikm = concat(&[b"HPKE-v1", suite_id, label, ikm]);
        Self::extract(salt, &labeled_ikm)
    }

    fn labeled_expand(suite_id: &[u8], prk: &[u8], label: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        use crate::{concat, i2osp};
        let labeled_info = concat(&[&i2osp(L, 2), b"HPKE-v1", suite_id, label, info]);
        Self::expand(prk, &labeled_info, L)
    }
}

// This trait captures all of the functions with _OneStage and _TwoStage variants.
pub trait Kdf {
    const ID: [u8; 2];

    fn extract_and_expand(suite_id: &[u8], dh: &[u8], kem_context: &[u8], len: usize) -> Vec<u8>;

    fn combine_secrets(
        suite_id: &[u8],
        mode: crate::Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        key_size: usize,
        nonce_size: usize,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>);

    fn export(
        suite_id: &[u8],
        exporter_secret: &[u8],
        exporter_context: &[u8],
        len: usize,
    ) -> Vec<u8>;

    fn derive_candidate(suite_id: &[u8], ikm: &[u8], counter: u8, nsk: usize) -> Vec<u8>;

    fn derive_sk(suite_id: &[u8], ikm: &[u8], nsk: usize) -> Vec<u8>;
}

// This wrapper class reflects the _OneStage implementation of the Kdf methods
pub struct OneStage<K>(core::marker::PhantomData<K>);

impl<K> Kdf for OneStage<K>
where
    K: OneStageKdf,
{
    const ID: [u8; 2] = K::ID;

    fn extract_and_expand(suite_id: &[u8], dh: &[u8], kem_context: &[u8], len: usize) -> Vec<u8> {
        K::labeled_derive(suite_id, dh, b"shared_secret", kem_context, len)
    }

    fn combine_secrets(
        suite_id: &[u8],
        mode: crate::Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        key_size: usize,
        nonce_size: usize,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use crate::{concat, length_prefixed};

        let secrets = concat(&[&length_prefixed(psk), &length_prefixed(shared_secret)]);
        let context = concat(&[
            &[mode.into()],
            &length_prefixed(psk_id),
            &length_prefixed(info),
        ]);

        let secret_len = key_size + nonce_size + K::N_H;
        let secret = K::labeled_derive(suite_id, &secrets, b"secret", &context, secret_len);

        let (key, secret) = secret.split_at(key_size);
        let (base_nonce, exporter_secret) = secret.split_at(nonce_size);

        (key.to_vec(), base_nonce.to_vec(), exporter_secret.to_vec())
    }

    fn export(
        suite_id: &[u8],
        exporter_secret: &[u8],
        exporter_context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        K::labeled_derive(suite_id, exporter_secret, b"sec", exporter_context, len)
    }

    fn derive_candidate(suite_id: &[u8], ikm: &[u8], counter: u8, nsk: usize) -> Vec<u8> {
        K::labeled_derive(suite_id, ikm, b"candidate", &[counter], nsk)
    }

    fn derive_sk(suite_id: &[u8], ikm: &[u8], nsk: usize) -> Vec<u8> {
        K::labeled_derive(suite_id, ikm, b"sk", b"", nsk)
    }
}

pub struct TwoStage<K>(core::marker::PhantomData<K>);

impl<K> Kdf for TwoStage<K>
where
    K: TwoStageKdf,
{
    const ID: [u8; 2] = K::ID;

    fn extract_and_expand(suite_id: &[u8], dh: &[u8], kem_context: &[u8], len: usize) -> Vec<u8> {
        let eae_prk = K::labeled_extract(suite_id, b"", b"eae_prk", &dh);
        K::labeled_expand(suite_id, &eae_prk, b"shared_secret", &kem_context, len)
    }

    fn combine_secrets(
        suite_id: &[u8],
        mode: crate::Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        key_size: usize,
        nonce_size: usize,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use crate::concat;
        let psk_id_hash = K::labeled_extract(&suite_id, &[], b"psk_id_hash", psk_id);
        let info_hash = K::labeled_extract(&suite_id, &[], b"info_hash", info);
        let key_schedule_context = concat(&[&[u8::from(mode)], &psk_id_hash, &info_hash]);

        let secret = K::labeled_extract(&suite_id, shared_secret, b"secret", psk);

        let key = K::labeled_expand(&suite_id, &secret, b"key", &key_schedule_context, key_size);
        let base_nonce = K::labeled_expand(
            &suite_id,
            &secret,
            b"base_nonce",
            &key_schedule_context,
            nonce_size,
        );
        let exporter_secret =
            K::labeled_expand(&suite_id, &secret, b"exp", &key_schedule_context, K::N_H);

        (key, base_nonce, exporter_secret)
    }

    fn export(
        suite_id: &[u8],
        exporter_secret: &[u8],
        exporter_context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        K::labeled_expand(suite_id, exporter_secret, b"sec", exporter_context, len)
    }

    fn derive_candidate(suite_id: &[u8], ikm: &[u8], counter: u8, nsk: usize) -> Vec<u8> {
        let dkp_prk = K::labeled_extract(suite_id, b"", b"dkp_prk", ikm);
        K::labeled_expand(suite_id, &dkp_prk, b"candidate", &[counter], nsk)
    }

    fn derive_sk(suite_id: &[u8], ikm: &[u8], nsk: usize) -> Vec<u8> {
        let dkp_prk = K::labeled_extract(suite_id, b"", b"dkp_prk", ikm);
        K::labeled_expand(suite_id, &dkp_prk, b"sk", b"", nsk)
    }
}

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub struct Shake128Core;

impl OneStageKdf for Shake128Core {
    const ID: [u8; 2] = [0x00, 0x10];
    const N_H: usize = 32;

    fn derive(ikm: &[u8], len: usize) -> Vec<u8> {
        let mut state = sha3::Shake128::default();
        state.update(ikm);

        let mut out = vec![0; len];
        let mut reader = state.finalize_xof();
        reader.read(&mut out);
        out
    }
}

pub struct Shake256Core;

impl OneStageKdf for Shake256Core {
    const ID: [u8; 2] = [0x00, 0x10];
    const N_H: usize = 32;

    fn derive(ikm: &[u8], len: usize) -> Vec<u8> {
        let mut state = sha3::Shake256::default();
        state.update(ikm);

        let mut out = vec![0; len];
        let mut reader = state.finalize_xof();
        reader.read(&mut out);
        out
    }
}

pub struct TurboShake128Core;

impl OneStageKdf for TurboShake128Core {
    const ID: [u8; 2] = [0x00, 0x10];
    const N_H: usize = 32;

    fn derive(ikm: &[u8], len: usize) -> Vec<u8> {
        let core = sha3::TurboShake128Core::new(0x1f);
        let mut state = sha3::TurboShake128::from_core(core);

        state.update(ikm);

        let mut out = vec![0; len];
        let mut reader = state.finalize_xof();
        reader.read(&mut out);
        out
    }
}

pub struct TurboShake256Core;

impl OneStageKdf for TurboShake256Core {
    const ID: [u8; 2] = [0x00, 0x10];
    const N_H: usize = 32;

    fn derive(ikm: &[u8], len: usize) -> Vec<u8> {
        let core = sha3::TurboShake256Core::new(0x1f);
        let mut state = sha3::TurboShake256::from_core(core);

        state.update(ikm);

        let mut out = vec![0; len];
        let mut reader = state.finalize_xof();
        reader.read(&mut out);
        out
    }
}

pub struct HkdfSha256Core;

impl TwoStageKdf for HkdfSha256Core {
    const ID: [u8; 2] = [0x00, 0x01];
    const N_H: usize = 32;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        let mut okm = vec![0; L];
        let hk = Hkdf::<Sha256>::from_prk(prk).unwrap();
        hk.expand(info, &mut okm).unwrap();
        okm
    }
}

pub struct HkdfSha384Core;

impl TwoStageKdf for HkdfSha384Core {
    const ID: [u8; 2] = [0x00, 0x02];
    const N_H: usize = 48;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        let mut okm = vec![0; L];
        let hk = Hkdf::<Sha384>::from_prk(prk).unwrap();
        hk.expand(info, &mut okm).unwrap();
        okm
    }
}

pub struct HkdfSha512Core;

impl TwoStageKdf for HkdfSha512Core {
    const ID: [u8; 2] = [0x00, 0x03];
    const N_H: usize = 64;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        let mut okm = vec![0; L];
        let hk = Hkdf::<Sha512>::from_prk(prk).unwrap();
        hk.expand(info, &mut okm).unwrap();
        okm
    }
}

pub type Shake128 = OneStage<Shake128Core>;
pub type Shake256 = OneStage<Shake256Core>;
pub type TurboShake128 = OneStage<TurboShake128Core>;
pub type TurboShake256 = OneStage<TurboShake256Core>;
pub type HkdfSha256 = TwoStage<HkdfSha256Core>;
pub type HkdfSha384 = TwoStage<HkdfSha384Core>;
pub type HkdfSha512 = TwoStage<HkdfSha512Core>;
