use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use md5;
use ring::digest::SHA1;
use ring::hkdf;
use ring::hmac::SigningKey;

pub trait Cipher {
    fn key_length(&self) -> usize;
    fn iv_length(&self) -> usize;
    fn digest_length(&self) -> usize;

    fn bytes_to_key(&self, psk: &[u8]) -> Bytes {
        let iv_len = self.iv_length();
        let key_len = self.key_length();
        let digest_len = self.digest_length();

        let calc_loop = (iv_len + key_len + digest_len - 1) / digest_len;
        let mut result = BytesMut::with_capacity(calc_loop * digest_len);
        let mut vkey = BytesMut::with_capacity(digest_len + psk.len());

        for _ in 0..calc_loop {
            vkey.put(psk);

            let md5 = *md5::compute(vkey.clone());

            vkey = BytesMut::from(&md5[..]);
            result.put(&md5[..]);
        }

        result.truncate(key_len);
        result.freeze()
    }
}

pub trait AeadCipher: Cipher {
    fn derivate_sub_key(&self, psk: &[u8], salt: &[u8]) -> Bytes {
        let key_length = self.key_length();
        let key = self.bytes_to_key(psk);
        let salt = SigningKey::new(&SHA1, salt);

        let mut skey = BytesMut::with_capacity(key_length);
        hkdf::extract_and_expand(&salt, &key, b"ss-subkey", &mut skey);

        skey.freeze()
    }
}

pub trait StreamCipher: Cipher {}

pub struct Chacha20Poly1305Cipher;

impl Cipher for Chacha20Poly1305Cipher {
    fn key_length(&self) -> usize {
        32
    }

    fn iv_length(&self) -> usize {
        12
    }

    fn digest_length(&self) -> usize {
        16
    }
}

pub struct CipherBuilder;

impl CipherBuilder {}
