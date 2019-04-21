use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use failure::Fail;
use futures::sink::Sink;
use futures::try_ready;
use futures::{Async, Future, Poll};
use log::*;
use md5;
use ring::aead::*;
use ring::digest::SHA1;
use ring::hkdf;
use ring::hmac::SigningKey;
use tokio::codec::{BytesCodec, Decoder, Encoder, Framed};
use tokio::io::{read_exact, write_all, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::stream::{SplitSink, SplitStream, Stream};
use tokio::prelude::*;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::shadowsocks::*;
use crate::utils::nonce_plus_one;

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
        loop {
            trace!(
                "undecrypt data: {}, waitting: {:?} {:x?}",
                buf.len(),
                self.waitting_payload,
                buf
            );
            let read_length = self.waitting_payload.unwrap_or(2);

            if buf.len() < read_length + 16 {
                return Ok(None);
            }

            let mut data = buf.split_to(read_length + 16);
            let nonce = self.nonce();
            let decrypted = open_in_place(&self.decrypt_skey, nonce, Aad::empty(), 0, &mut data)?;
            trace!("{:x?}", decrypted);

            match self.waitting_payload.take() {
                Some(_) => return Ok(Some(Bytes::from(&decrypted[..]))),
                None => {
                    assert!(decrypted.len() == 2);
                    let payload_len = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
                    trace!("Got payload len info: {}", payload_len);
                    self.waitting_payload = Some(payload_len);
                }
            };
        }
    }
}

impl ShadowsocksEncryptor for Chacha20Poly1305Encryptor {
    fn encrypt(&mut self, data: &[u8]) -> Result<Bytes, failure::Error> {
        trace!("ready to encrypt data: {:x?}", data);
        let payload_len = data.len() as u16;
        assert!(payload_len < 0x3fff);

        let mut len_payload = vec![0u8; 18];
        len_payload[0] = (payload_len >> 8) as u8;
        len_payload[1] = (payload_len & 0xff) as u8;

        let nonce = self.nonce();
        let out_len = seal_in_place(
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
        let out_len = seal_in_place(
            &self.encrypt_skey,
            nonce,
            Aad::empty(),
            &mut payload_encrypted,
            16,
        )?;

        let mut encrypted = BytesMut::with_capacity(len_payload.len() + payload_encrypted.len());
        encrypted.put(len_payload);
        encrypted.put(payload_encrypted);
        trace!("encrypted data: {:x?}", encrypted);

        Ok(encrypted.freeze())
    }
}
