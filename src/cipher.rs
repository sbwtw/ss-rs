use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use futures::Future;
use log::*;
use md5;
use ring::digest::SHA1;
use ring::hkdf;
use ring::hmac::SigningKey;
use tokio::net::TcpStream;
use tokio::prelude::*;

use std::io;
use std::sync::Arc;

use crate::aes256cfb::*;
use crate::chacha20poly1305::*;
use crate::config::*;
use crate::shadowsocks::*;

pub trait Cipher {
    fn key_length(&self) -> usize;
    fn iv_length(&self) -> usize;
    fn first_reply_length(&self) -> usize;

    fn bytes_to_key(&self, psk: &[u8]) -> Bytes {
        let iv_len = self.iv_length();
        let key_len = self.key_length();
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
        let key_length = self.key_length();
        let key = self.bytes_to_key(psk);
        let salt = SigningKey::new(&SHA1, salt);

        let mut skey = vec![0u8; key_length];
        hkdf::extract_and_expand(&salt, &key, b"ss-subkey", &mut skey);
        trace!("generate skey: {:x?}", skey);

        BytesMut::from(skey).freeze()
    }

    fn first_sending_block(&mut self, addr: &[u8]) -> Bytes;
    fn set_opening_iv(&mut self, _: &[u8]);

    fn encrypt_data(&mut self, _: &[u8]) -> Bytes;

    fn take_encryptor(&mut self) -> Box<dyn ShadowsocksEncryptor + Send>;
    fn take_decryptor(&mut self) -> Box<dyn ShadowsocksDecryptor + Send>;
}

pub struct CipherBuilder {
    config: Arc<ServerConfig>,
    request_addr: Option<Arc<Socks5Addr>>,
    cipher: Option<CipherWrapper>,
}

pub struct CipherWrapper {
    cipher: Box<dyn Cipher + Send>,
    sock: TcpStream,
}

impl Future for CipherBuilder {
    type Item = CipherWrapper;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::NotReady)
    }
}

impl CipherWrapper {
    pub fn into_inner(self) -> TcpStream {
        self.sock
    }
}

impl Cipher for CipherWrapper {
    fn key_length(&self) -> usize {
        self.cipher.key_length()
    }
    fn iv_length(&self) -> usize {
        self.cipher.iv_length()
    }
    fn first_reply_length(&self) -> usize {
        self.cipher.first_reply_length()
    }

    fn first_sending_block(&mut self, addr: &[u8]) -> Bytes {
        self.cipher.first_sending_block(addr)
    }
    fn set_opening_iv(&mut self, iv: &[u8]) {
        self.cipher.set_opening_iv(iv)
    }

    fn encrypt_data(&mut self, data: &[u8]) -> Bytes {
        self.cipher.encrypt_data(data)
    }

    fn take_encryptor(&mut self) -> Box<dyn ShadowsocksEncryptor + Send> {
        self.cipher.take_encryptor()
    }
    fn take_decryptor(&mut self) -> Box<dyn ShadowsocksDecryptor + Send> {
        self.cipher.take_decryptor()
    }
}

impl CipherBuilder {
    pub fn new(sock: TcpStream, config: Arc<ServerConfig>) -> Self {
        let cipher = match config.encrypt_method().as_ref() {
            "chacha20-ietf-poly1305" => CipherWrapper {
                cipher: Box::new(Chacha20Poly1305Cipher::new(config.clone())),
                sock,
            },
            "aes-256-cfb" => CipherWrapper {
                cipher: Box::new(Aes256CfbCipher::new(config.clone())),
                sock,
            },
            _ => panic!("Specificed cipher not supported!"),
        };

        Self {
            config,
            request_addr: None,
            cipher: Some(cipher),
        }
    }

    pub fn request_addr(mut self, request_addr: Arc<Socks5Addr>) -> Self {
        self.request_addr = Some(request_addr);

        self
    }
}
