use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
use futures::sink::Sink;
use futures::try_ready;
use futures::Async;
use tokio::prelude::*;

use std::fmt::{self, Formatter};
use std::io;
use std::net::IpAddr;

pub enum Socks5Host {
    Ip(IpAddr),
    Domain(String),
}

pub struct Socks5Addr(pub Socks5Host, pub u16);

impl fmt::Display for Socks5Host {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Socks5Host::Ip(ip) => write!(f, "{}", ip),
            Socks5Host::Domain(domain) => write!(f, "{}", domain),
        }
    }
}

impl fmt::Display for Socks5Addr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl Socks5Addr {
    pub fn bytes(&self) -> BytesMut {
        let mut bytes = BytesMut::new();

        match &self.0 {
            Socks5Host::Ip(ip) => match ip {
                IpAddr::V4(ipv4) => {
                    bytes.reserve(1 /* type */ + 4 /* max len of ipv4 */ + 2 /* port */);
                    bytes.put(b'\x01'); // type for ipv4
                    bytes.put(&ipv4.octets()[..]);
                }
                IpAddr::V6(ipv6) => {
                    bytes.reserve(1 /* type */ + 16 /* max len of ipv6 */ + 2 /* port */);
                    bytes.put(b'\x04'); // type for ipv6
                    bytes.put(&ipv6.octets()[..]);
                }
            },
            Socks5Host::Domain(domain) => {
                bytes.reserve(
                    1 /* type */ + 1 /* domain len */ + domain.len() + 2, /* port */
                );
                bytes.put(b'\x03'); // type for domain
                bytes.put(domain.len() as u8);
                bytes.put(domain.as_bytes());
            }
        }

        bytes.put_u16_be(self.1); // write port
        bytes
    }
}

pub trait ShadowsocksDecryptor {
    fn decrypt(&mut self, data: &mut BytesMut) -> Result<Option<Bytes>, failure::Error>;
}

pub trait ShadowsocksEncryptor {
    fn encrypt(&mut self, data: &mut BytesMut) -> Result<Bytes, failure::Error>;
}

pub struct ShadowsocksSink<W> {
    writer: W,
    encryptor: Box<dyn ShadowsocksEncryptor + Send>,
    buffered: BytesMut,
    encrypted: BytesMut,
}

pub struct ShadowsocksStream<R> {
    reader: R,
    decryptor: Box<dyn ShadowsocksDecryptor + Send>,
    buffered: BytesMut,
}

impl<W> ShadowsocksSink<W>
where
    W: AsyncWrite,
{
    pub fn new(writer: W, encryptor: Box<dyn ShadowsocksEncryptor + Send>) -> Self {
        Self {
            writer,
            encryptor,
            buffered: BytesMut::new(),
            encrypted: BytesMut::new(),
        }
    }
}

impl<R: AsyncRead> ShadowsocksStream<R> {
    pub fn new(reader: R, decryptor: Box<dyn ShadowsocksDecryptor + Send>) -> Self {
        Self {
            reader,
            decryptor,
            buffered: BytesMut::new(),
        }
    }
}

impl<W> Sink for ShadowsocksSink<W>
where
    W: AsyncWrite,
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
            let encrypted_data = self.encryptor.encrypt(&mut self.buffered).unwrap();
            self.encrypted.extend(encrypted_data);
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

impl<R> Stream for ShadowsocksStream<R>
where
    R: AsyncRead,
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
