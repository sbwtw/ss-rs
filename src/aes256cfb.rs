use bytes::{Bytes, BytesMut};
use log::*;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{thread_rng, Rng};

use std::sync::Arc;

use crate::cipher::Cipher as ShadowsocksCipher;
use crate::config::*;
use crate::shadowsocks::*;

pub struct Aes256CfbCipher {
    config: Arc<ServerConfig>,
    skey: [u8; 32],
    encrypt_iv: [u8; 16],
    decrypt_iv: [u8; 16],
    encrypter: Option<Crypter>,
}

impl Aes256CfbCipher {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        let mut rng = thread_rng();
        let mut encrypt_iv = [0; 16];
        rng.fill(&mut encrypt_iv);

        let mut r = Self {
            config,
            skey: [0u8; 32],
            encrypt_iv,
            decrypt_iv: [0u8; 16],
            encrypter: None,
        };

        r.initialize();

        r
    }

    fn initialize(&mut self) {
        let skey = self.bytes_to_key(self.config.password().as_bytes());
        self.skey.copy_from_slice(&skey[..]);

        let cipher = Cipher::aes_256_cfb128();
        let encrypter =
            Crypter::new(cipher, Mode::Encrypt, &skey, Some(&self.encrypt_iv[..])).unwrap();
        self.encrypter = Some(encrypter);
    }
}

impl ShadowsocksCipher for Aes256CfbCipher {
    fn key_length(&self) -> usize {
        32
    }
    fn iv_length(&self) -> usize {
        16
    }
    fn first_reply_length(&self) -> usize {
        16
    }

    fn take_encryptor(&mut self) -> Box<dyn ShadowsocksEncryptor + Send> {
        Box::new(Aes256CfbEncryptor::new(self.encrypter.take().unwrap()))
    }
    fn take_decryptor(&mut self) -> Box<dyn ShadowsocksDecryptor + Send> {
        Box::new(Aes256CfbDecryptor::new(self.skey, self.decrypt_iv))
    }

    fn first_sending_block(&mut self, addr: &[u8]) -> Bytes {
        let encrypted_addr = self.encrypt_data(addr);

        let mut data = BytesMut::new();
        data.extend(&self.encrypt_iv[..]);
        data.extend(encrypted_addr);

        data.freeze()
    }

    fn encrypt_data(&mut self, request_addr: &[u8]) -> Bytes {
        let buffer_size = request_addr.len() + 1; // 1 for block size
        let mut buffer = vec![0; buffer_size];

        let size = self
            .encrypter
            .as_mut()
            .unwrap()
            .update(request_addr, &mut buffer)
            .unwrap();

        BytesMut::from(&buffer[..size]).freeze()
    }

    fn set_opening_iv(&mut self, iv: &[u8]) {
        trace!("got dec iv: {:x?}", iv);
        self.decrypt_iv.copy_from_slice(iv);
    }
}

pub struct Aes256CfbEncryptor {
    encrypter: Crypter,
}

pub struct Aes256CfbDecryptor {
    decrypter: Crypter,
}

impl Aes256CfbDecryptor {
    pub fn new(skey: [u8; 32], iv: [u8; 16]) -> Self {
        let cipher = Cipher::aes_256_cfb128();
        let decrypter = Crypter::new(cipher, Mode::Decrypt, &skey[..], Some(&iv[..])).unwrap();

        Self { decrypter }
    }
}

impl Aes256CfbEncryptor {
    pub fn new(encrypter: Crypter) -> Self {
        Self { encrypter }
    }
}

impl ShadowsocksDecryptor for Aes256CfbDecryptor {
    fn decrypt(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, failure::Error> {
        if buf.is_empty() {
            // TODO: need to finalized decrypter?

            return Ok(None);
        }

        let buffer_size = buf.len() + 1; // 1 for block size
        let mut buffer = vec![0; buffer_size];
        let size = self.decrypter.update(&buf[..], &mut buffer)?;

        buf.split_to(size);
        Ok(Some(BytesMut::from(&buffer[..size]).freeze()))
    }
}

impl ShadowsocksEncryptor for Aes256CfbEncryptor {
    fn encrypt(&mut self, data: &[u8]) -> Result<Bytes, failure::Error> {
        let buffer_size = data.len() + 1; // 1 for block size
        let mut buffer = vec![0; buffer_size];
        let size = self.encrypter.update(data, &mut buffer)?;

        Ok(BytesMut::from(&buffer[..size]).freeze())
    }
}
