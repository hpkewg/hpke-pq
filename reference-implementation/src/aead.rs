pub trait Aead {
    const ID: [u8; 2];
    const N_K: usize;
    const N_N: usize;
    const N_T: usize;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8>;
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8>;
}

use aead::{Aead as _, KeyInit};

pub struct Aes128Gcm;

impl Aead for Aes128Gcm {
    const ID: [u8; 2] = [0x00, 0x01];
    const N_K: usize = 16;
    const N_N: usize = 12;
    const N_T: usize = 16;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: pt };
        let cipher = aes_gcm::Aes128Gcm::new(key.into());
        cipher.encrypt(nonce.into(), payload).unwrap()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: ct };
        let cipher = aes_gcm::Aes128Gcm::new(key.into());
        cipher.decrypt(nonce.into(), payload).unwrap()
    }
}

pub struct Aes256Gcm;

impl Aead for Aes256Gcm {
    const ID: [u8; 2] = [0x00, 0x02];
    const N_K: usize = 32;
    const N_N: usize = 12;
    const N_T: usize = 16;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: pt };
        let cipher = aes_gcm::Aes256Gcm::new(key.into());
        cipher.encrypt(nonce.into(), payload).unwrap()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: ct };
        let cipher = aes_gcm::Aes256Gcm::new(key.into());
        cipher.decrypt(nonce.into(), payload).unwrap()
    }
}

pub struct ChaChaPoly;

impl Aead for ChaChaPoly {
    const ID: [u8; 2] = [0x00, 0x03];
    const N_K: usize = 32;
    const N_N: usize = 12;
    const N_T: usize = 16;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: pt };
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        cipher.encrypt(nonce.into(), payload).unwrap()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: ct };
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        cipher.decrypt(nonce.into(), payload).unwrap()
    }
}

pub struct ExportOnly;

impl Aead for ExportOnly {
    const ID: [u8; 2] = [0xff, 0xff];
    const N_K: usize = 0;
    const N_N: usize = 0;
    const N_T: usize = 0;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        unreachable!()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        unreachable!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test<A>()
    where
        A: Aead,
    {
        let key = vec![0xA0; A::N_K];
        let nonce = vec![0xB0; A::N_N];

        let aad = b"I have heard the mermaids singing, each to each";
        let pt = b"I do not think that they will sing to me";

        let ct = A::seal(&key, &nonce, aad, pt);
        assert_eq!(ct.len(), pt.len() + A::N_T);

        let pt_out = A::open(&key, &nonce, aad, &ct);
        assert_eq!(pt, pt_out.as_slice());
    }

    #[test]
    fn test_all() {
        test::<Aes128Gcm>();
        test::<Aes256Gcm>();
        test::<ChaChaPoly>();
    }
}
