use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use rand::{thread_rng, Rng};
use ring::aead::*;

use std::sync::Arc;

use crate::cipher::*;
use crate::config::*;
use crate::shadowsocks::*;
use crate::utils::nonce_plus_one;

pub struct Chacha20Poly1305Cipher {
    config: Arc<ServerConfig>,
    sealing_salt: [u8; 32],
    encryptor: Option<Chacha20Poly1305Encryptor>,
    decryptor: Option<Chacha20Poly1305Decryptor>,
}

impl Chacha20Poly1305Cipher {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        let mut rng = thread_rng();
        let mut sealing_salt = [0; 32];
        rng.fill(&mut sealing_salt);

        let mut r = Self {
            config,
            sealing_salt,
            encryptor: None,
            decryptor: None,
        };

        r.generate_encryptor();

        r
    }

    fn generate_encryptor(&mut self) {
        let encrypt_skey =
            self.derivate_sub_key(self.config.password().as_bytes(), &self.sealing_salt[..]);
        // TODO: Error handling
        let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &encrypt_skey[..]).unwrap();

        let encryptor = Chacha20Poly1305Encryptor::new(sealing_key);

        self.encryptor = Some(encryptor);
    }
}

impl Cipher for Chacha20Poly1305Cipher {
    fn key_length(&self) -> usize {
        32
    }
    fn iv_length(&self) -> usize {
        12
    }
    fn first_reply_length(&self) -> usize {
        32
    }

    fn take_encryptor(&mut self) -> Box<dyn ShadowsocksEncryptor + Send> {
        Box::new(self.encryptor.take().unwrap())
    }
    fn take_decryptor(&mut self) -> Box<dyn ShadowsocksDecryptor + Send> {
        Box::new(self.decryptor.take().unwrap())
    }

    fn first_sending_block(&mut self, addr: &[u8]) -> Bytes {
        let encrypted_addr = self.encrypt_data(addr);

        let mut data = BytesMut::new();
        data.extend(&self.sealing_salt[..]);
        data.extend(encrypted_addr);

        data.freeze()
    }

    fn encrypt_data(&mut self, request_addr: &[u8]) -> Bytes {
        self.encryptor
            .as_mut()
            .unwrap()
            .encrypt(request_addr)
            .unwrap()
    }

    fn set_opening_iv(&mut self, iv: &[u8]) {
        let decrypt_skey = self.derivate_sub_key(self.config.password().as_bytes(), iv);
        // TODO: Error handling
        let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &decrypt_skey[..]).unwrap();

        // wrap remote reader into secure channel
        let decryptor = Chacha20Poly1305Decryptor::new(opening_key);
        self.decryptor = Some(decryptor);
    }
}

pub struct Chacha20Poly1305Encryptor {
    encrypt_skey: SealingKey,
    encrypt_nonce: [u8; 12],
}

pub struct Chacha20Poly1305Decryptor {
    decrypt_skey: OpeningKey,
    decrypt_nonce: [u8; 12],
    waitting_payload: Option<usize>,
}

impl Chacha20Poly1305Decryptor {
    pub fn new(skey: OpeningKey) -> Self {
        Self {
            decrypt_skey: skey,
            decrypt_nonce: [0u8; 12],
            waitting_payload: None,
        }
    }

    fn nonce(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.decrypt_nonce);
        nonce_plus_one(&mut self.decrypt_nonce);

        nonce
    }
}

impl Chacha20Poly1305Encryptor {
    pub fn new(skey: SealingKey) -> Self {
        Self {
            encrypt_skey: skey,
            encrypt_nonce: [0u8; 12],
        }
    }

    fn nonce(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.encrypt_nonce);
        nonce_plus_one(&mut self.encrypt_nonce);

        nonce
    }
}

impl ShadowsocksDecryptor for Chacha20Poly1305Decryptor {
    fn decrypt(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, failure::Error> {
        let tag_size = 16;

        loop {
            let wanted = self.waitting_payload.unwrap_or(2) + tag_size;

            if buf.len() < wanted {
                return Ok(None);
            }

            let mut data = buf.split_to(wanted);
            let nonce = self.nonce();
            let decrypted = open_in_place(&self.decrypt_skey, nonce, Aad::empty(), 0, &mut data)?;
            assert_eq!(decrypted.len(), wanted - tag_size);

            match self.waitting_payload.take() {
                Some(_) => return Ok(Some(Bytes::from(&decrypted[..]))),
                None => {
                    // decrypted is 16bits length of real payload
                    assert!(decrypted.len() == 2);
                    let payload_len = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;

                    // read real data
                    self.waitting_payload = Some(payload_len);
                }
            };
        }
    }
}

impl ShadowsocksEncryptor for Chacha20Poly1305Encryptor {
    fn encrypt(&mut self, data: &[u8]) -> Result<Bytes, failure::Error> {
        let payload_len = data.len() as u16;
        assert!(payload_len < 0x3fff);

        let mut len_payload = vec![0u8; 18];
        len_payload[0] = (payload_len >> 8) as u8;
        len_payload[1] = (payload_len & 0xff) as u8;

        let nonce = self.nonce();
        seal_in_place(
            &self.encrypt_skey,
            nonce,
            Aad::empty(),
            &mut len_payload,
            16,
        )?;

        let mut payload_encrypted = BytesMut::with_capacity(16 + data.len());
        payload_encrypted.put(&data[..]);
        payload_encrypted.put(vec![0u8; 16]);
        let nonce = self.nonce();
        seal_in_place(
            &self.encrypt_skey,
            nonce,
            Aad::empty(),
            &mut payload_encrypted,
            16,
        )?;

        let mut encrypted = BytesMut::with_capacity(len_payload.len() + payload_encrypted.len());
        encrypted.put(len_payload);
        encrypted.put(payload_encrypted);

        Ok(encrypted.freeze())
    }
}
