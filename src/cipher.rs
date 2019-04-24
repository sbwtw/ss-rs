use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use md5;
use ring::aead::*;
use ring::digest::SHA1;
use ring::hkdf;
use ring::hmac::SigningKey;

use std::sync::Arc;

use crate::chacha20poly1305::*;
use crate::shadowsocks::*;
use crate::Config;

pub trait Cipher {
    const KEY_LENGTH: usize;
    const IV_LENGTH: usize;

    fn bytes_to_key(&self, psk: &[u8]) -> Bytes {
        let iv_len = Self::IV_LENGTH;
        let key_len = Self::KEY_LENGTH;
        let digest_len = 16;

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

    fn derivate_sub_key(&self, psk: &[u8], salt: &[u8]) -> Bytes {
        let key_length = Self::KEY_LENGTH;
        let key = self.bytes_to_key(psk);
        let salt = SigningKey::new(&SHA1, salt);

        let mut skey = BytesMut::with_capacity(key_length);
        hkdf::extract_and_expand(&salt, &key, b"ss-subkey", &mut skey);

        skey.freeze()
    }

    fn sealing_iv(&self) -> &Vec<u8>;
    fn set_opening_iv(&mut self, _: &[u8]);

    fn encrypt_data(&mut self, _: &[u8]) -> Bytes;

    fn take_encryptor(&mut self) -> Box<ShadowsocksEncryptor>;
    fn take_decryptor(&mut self) -> Box<ShadowsocksDecryptor>;
}

pub struct Chacha20Poly1305Cipher {
    config: Arc<Config>,
    sealing_salt: Vec<u8>,
    encryptor: Option<Chacha20Poly1305Encryptor>,
    decryptor: Option<Chacha20Poly1305Decryptor>,
}

impl Chacha20Poly1305Cipher {
    pub fn new(config: Arc<Config>) -> Self {
        let mut r = Self {
            config,
            sealing_salt: b"01234567890123456789012345678901".to_vec(),
            encryptor: None,
            decryptor: None,
        };

        r.generate_encryptor();

        r
    }

    fn generate_encryptor(&mut self) {
        let encrypt_skey =
            self.derivate_sub_key(self.config.password.as_bytes(), &self.sealing_salt[..]);
        // TODO: Error handling
        let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &encrypt_skey[..]).unwrap();

        let encryptor = Chacha20Poly1305Encryptor::new(sealing_key);

        self.encryptor = Some(encryptor);
    }
}

impl Cipher for Chacha20Poly1305Cipher {
    const KEY_LENGTH: usize = 32;
    const IV_LENGTH: usize = 12;

    fn take_encryptor(&mut self) -> Box<ShadowsocksEncryptor> {
        Box::new(self.encryptor.take().unwrap())
    }
    fn take_decryptor(&mut self) -> Box<ShadowsocksDecryptor> {
        Box::new(self.decryptor.take().unwrap())
    }

    fn sealing_iv(&self) -> &Vec<u8> {
        &self.sealing_salt
    }

    fn encrypt_data(&mut self, request_addr: &[u8]) -> Bytes {
        self.encryptor
            .as_mut()
            .unwrap()
            .encrypt(request_addr)
            .unwrap()
    }

    fn set_opening_iv(&mut self, iv: &[u8]) {
        let decrypt_skey = self.derivate_sub_key(self.config.password.as_bytes(), iv);
        // TODO: Error handling
        let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &decrypt_skey[..]).unwrap();

        // wrap remote reader into secure channel
        let decryptor = Chacha20Poly1305Decryptor::new(opening_key);
        self.decryptor = Some(decryptor);
    }
}
