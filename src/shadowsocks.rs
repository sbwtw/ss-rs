use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use futures::sink::Sink;
use futures::try_ready;
use futures::Async;
use tokio::prelude::*;

use std::io;
use std::net::IpAddr;

#[derive(Debug)]
pub enum Socks5Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug)]
pub struct Socks5Addr(pub Socks5Host, pub u16);

impl Socks5Addr {
    pub fn bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        match &self.0 {
            Socks5Host::Ip(ip) => match ip {
                IpAddr::V4(ipv4) => {
                    bytes.reserve(1 /* type */ + 4 /* max len of ipv6 */ + 2 /* port */);
                    bytes.put(b'\x01');
                    bytes.put(&ipv4.octets()[..]);
                }
                IpAddr::V6(ipv6) => {
                    bytes.reserve(1 /* type */ + 16 /* max len of ipv6 */ + 2 /* port */);
                    bytes.put(b'\x04');
                    bytes.put(&ipv6.octets()[..]);
                }
            },
            Socks5Host::Domain(domain) => {
                bytes.reserve(1 /* type */ + domain.len() + 2 /* port */);
                bytes.put(b'\x03'); // type
                bytes.put(domain.len() as u8);
                bytes.put(domain.as_bytes());
            }
        }

        bytes.put_u16_be(self.1);
        bytes
    }
}

pub trait ShadowsocksDecryptor {
    fn decrypt(&mut self, data: &mut BytesMut) -> Result<Option<Bytes>, failure::Error>;
}

pub trait ShadowsocksEncryptor {
    fn encrypt(&mut self, data: &[u8]) -> Result<Bytes, failure::Error>;
}

pub struct ShadowsocksSink<W, E> {
    writer: W,
    encryptor: E,
    buffered: BytesMut,
    encrypted: BytesMut,
}

pub struct ShadowsocksStream<R, D> {
    reader: R,
    decryptor: D,
    buffered: BytesMut,
}

impl<W: AsyncWrite, E: ShadowsocksEncryptor> ShadowsocksSink<W, E> {
    pub fn new(writer: W, encryptor: E) -> Self {
        Self {
            writer,
            encryptor,
            buffered: BytesMut::new(),
            encrypted: BytesMut::new(),
        }
    }
}

impl<R: AsyncRead, D: ShadowsocksDecryptor> ShadowsocksStream<R, D> {
    pub fn new(reader: R, decryptor: D) -> Self {
        Self {
            reader,
            decryptor,
            buffered: BytesMut::new(),
        }
    }
}

impl<W, E> Sink for ShadowsocksSink<W, E>
where
    W: AsyncWrite,
    E: ShadowsocksEncryptor,
{
    type SinkItem = BytesMut;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        item: Self::SinkItem,
    ) -> Result<AsyncSink<Self::SinkItem>, Self::SinkError> {
        // just buffered data. NOTE: maybe we should check buffered length?
        self.buffered.extend(item);

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, Self::SinkError> {
        if !self.buffered.is_empty() {
            let encrypted_data = self.encryptor.encrypt(&self.buffered).unwrap();
            self.encrypted.extend(encrypted_data);
            self.buffered.clear();
        }

        match self.writer.poll_write(&self.encrypted[..])? {
            Async::Ready(size) => {
                self.encrypted.split_to(size);
                if self.encrypted.is_empty() {
                    return self.writer.poll_flush();
                } else {
                    return Ok(Async::NotReady);
                }
            }
            Async::NotReady => {
                return Ok(Async::NotReady);
            }
        };
    }
}

impl<R, D> Stream for ShadowsocksStream<R, D>
where
    R: AsyncRead,
    D: ShadowsocksDecryptor,
{
    type Item = Bytes;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        let mut buffer = [0u8; 1024 * 4];

        let size = try_ready!(self.reader.poll_read(&mut buffer));
        if size == 0 {
            assert!(self.buffered.is_empty());
            return Ok(Async::Ready(None));
        }

        self.buffered.extend(&buffer[..size]);

        let mut decrypted = BytesMut::new();
        while let Some(data) = self.decryptor.decrypt(&mut self.buffered).unwrap() {
            decrypted.extend(data);
        }

        Ok(Async::Ready(Some(decrypted.freeze())))
    }
}
