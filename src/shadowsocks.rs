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
            Socks5Host::Ip(ip) => {
                unimplemented!();
            }
            Socks5Host::Domain(domain) => {
                bytes.reserve(2 /* type */ + domain.len() + 2 /* port */);
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

pub struct ShadowsocksWriter<W, E> {
    writer: W,
    encryptor: E,
    encrypted: BytesMut,
}

pub struct ShadowsocksReader<R, D> {
    reader: R,
    decryptor: D,
    buffer: BytesMut,
    decrypted: BytesMut,
    //read_buf1: [u8; 1024],
}

impl<R: AsyncRead, D: ShadowsocksDecryptor> ShadowsocksReader<R, D> {
    pub fn new(reader: R, decryptor: D) -> Self {
        Self {
            reader,
            decryptor,
            // TODO: capacity
            buffer: BytesMut::new(),
            decrypted: BytesMut::new(),
            //read_buf1: [0u8; 1024],
        }
    }
}

impl<W: AsyncWrite, E: ShadowsocksEncryptor> ShadowsocksWriter<W, E> {
    pub fn new(writer: W, encryptor: E) -> Self {
        Self {
            writer,
            encryptor,
            encrypted: BytesMut::new(),
        }
    }
}

impl<R: AsyncRead, D: ShadowsocksDecryptor> io::Read for ShadowsocksReader<R, D> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl<R: AsyncRead, D: ShadowsocksDecryptor> AsyncRead for ShadowsocksReader<R, D> {
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, io::Error> {
        let mut read_buf = [0u8; 4096];
        let mut buf_used = 0;

        loop {
            // have data to write
            trace!(
                "start poll, decrypted len = {}, buf_used = {}, buf_len: {}",
                self.decrypted.len(),
                buf_used,
                buf.len()
            );
            if self.decrypted.len() != 0 {
                let ready_len = std::cmp::min(buf.len() - buf_used, self.decrypted.len());
                trace!("ready len: {}", ready_len);
                let bytes = self.decrypted.split_to(ready_len);
                buf[buf_used..(buf_used + ready_len)].copy_from_slice(&bytes);
                trace!(
                    "copy finished, buf_used: {}, ready_len: {}, buf_len: {}",
                    buf_used,
                    ready_len,
                    buf.len()
                );

                if (buf_used + ready_len) == buf.len() {
                    // buffer is full, return
                    return Ok(Async::Ready(buf.len()));
                } else {
                    // buffer not full, wait
                    buf_used += ready_len;
                }
            }

            // read data
            match self.reader.poll_read(&mut read_buf[..])? {
                Async::Ready(0) => {
                    trace!("Read EOF");
                    // EOF
                    assert!(self.decrypted.len() == 0);
                    //assert!(buf_used == 0);

                    return Ok(Async::Ready(0));
                }
                Async::Ready(size) => {
                    trace!("Read {} bytes", size);
                    self.buffer.extend(&read_buf[..size]);
                }
                Async::NotReady => {
                    trace!("Read not ready, remain: {}", buf_used);
                    if buf_used != 0 {
                        return Ok(Async::Ready(buf_used));
                    }
                    return Ok(Async::NotReady);
                }
            }

            trace!("After read, buffer len: {}", self.buffer.len());
            while let Some(data) = self.decryptor.decrypt(&mut self.buffer).unwrap() {
                self.decrypted.extend(data);
                trace!("got decrypted data: {:?}", self.decrypted);
            }
            trace!("decrypted finish, total data: {}", self.decrypted.len());
        }
    }
}

impl<W: AsyncWrite, E: ShadowsocksEncryptor> io::Write for ShadowsocksWriter<W, E> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.writer.flush()
    }
}

impl<W: AsyncWrite, E: ShadowsocksEncryptor> AsyncWrite for ShadowsocksWriter<W, E> {
    fn poll_write(&mut self, buf: &[u8]) -> Result<Async<usize>, io::Error> {
        let buf_len = buf.len();

        self.encrypted.extend(self.encryptor.encrypt(buf).unwrap());

        match self.writer.poll_write(&self.encrypted[..])? {
            r @ Async::Ready(0) | r @ Async::NotReady => {
                trace!("write {:?}", r);
                return Ok(r);
            }
            Async::Ready(size) => {
                trace!("Write {} bytes", size);
                self.encrypted.split_to(size);

                return Ok(Async::Ready(buf_len));
            }
        }

        //we need more bytes!
        //if self.buffer.is_empty() {
        //TODO: Error handling
        //let encrypted = self.encryptor.encrypt(buf).unwrap();
        //self.buffer.extend(encrypted);
        //return Ok(Async::Ready(buf.len()));
        //}

        //match self.writer.poll_write(&self.buffer[..])? {
        //Async::Ready(0) => {
        //trace!("write EOF");
        //return Ok(Async::Ready(0));
        //}
        //Async::Ready(size) => {
        //self.buffer.split_to(size);
        //return Ok(Async::Ready(size));
        //}
        //Async::NotReady => {
        //return Ok(Async::NotReady);
        //}
        //};
    }

    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        self.writer.shutdown()
    }
}
