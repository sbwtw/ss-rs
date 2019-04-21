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

mod chacha20poly1305;
mod shadowsocks;
mod utils;

use chacha20poly1305::*;
use shadowsocks::*;
use utils::*;

#[derive(Debug, Fail)]
enum HandshakeError {
    #[fail(display = "Socks5 Version Error: 0x{:02x}", version)]
    VersionError { version: u8 },
    #[fail(
        display = "Only method type 0x00 is supported, server request one of {:x?}",
        supported
    )]
    MethodError { supported: Vec<u8> },
}

fn local_establish(
    sock: TcpStream,
) -> impl Future<Item = (TcpStream, Socks5Addr), Error = failure::Error> {
    trace!("Establish connection for {:?}", sock.peer_addr());

    // read socks version
    read_exact(sock, [0u8])
        .map_err(Into::into)
        .and_then(|(socket, buf)| {
            if buf[0] != 0x05 {
                Err(HandshakeError::VersionError { version: buf[0] }.into())
            } else {
                Ok(socket)
            }
        })
        // read method length
        .and_then(|socket| {
            read_exact(socket, [0u8])
                .map_err(Into::into)
                .and_then(|(socket, buf)| Ok((socket, buf[0] as usize)))
        })
        // read method list
        .and_then(|(socket, method_len)| {
            read_exact(socket, vec![0u8; method_len])
                .map_err(Into::into)
                .and_then(|(socket, buf)| {
                    if buf.contains(&0x00) {
                        Ok(socket)
                    } else {
                        Err(HandshakeError::MethodError { supported: buf }.into())
                    }
                })
        })
        // write method select response
        .and_then(|socket| write_all(socket, [0x05, 0x00]).map_err(Into::into))
        .and_then(|(socket, _)| {
            read_exact(socket, [0u8; 4])
                .map_err(Into::into)
                .and_then(|(socket, buf)| {
                    assert!(buf[0] == 0x05 && buf[1] == 0x01 && buf[2] == 0x00);
                    Ok((socket, buf[3]))
                })
        })
        .and_then(|(socket, atyp)| parse_addr(socket, atyp))
        .and_then(|(socket, addr)| {
            read_exact(socket, [0u8; 2])
                .map_err(Into::into)
                .and_then(move |(socket, buf)| {
                    let port = u16::from_be_bytes(buf);

                    Ok((socket, Socks5Addr(addr, port)))
                })
        })
}

fn remote_establish(
    config: Arc<ServerConfig>,
) -> impl Future<Item = TcpStream, Error = failure::Error> {
    TcpStream::connect(&config.addr).map_err(Into::into)
}

fn local_handshake(
    sock: TcpStream,
) -> impl Future<Item = (impl AsyncRead, impl AsyncWrite), Error = io::Error> {
    // fake data, client won't really use it!
    let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    write_all(sock, buf).and_then(|(sock, _)| Ok(sock.split()))
}

fn remote_handshake(
    sock: TcpStream,
    config: Arc<ServerConfig>,
    request_addr: Socks5Addr,
) -> impl Future<Item = (impl AsyncRead, impl AsyncWrite), Error = io::Error> {
    // TODO: move to other place
    let salt = Arc::new(*b"01234567890123456789012345678901");
    let encrypt_skey = derivate_sub_key(config.password.as_bytes(), &*salt.clone());
    trace!("enc skey: {:x?}", encrypt_skey);
    // TODO: Error handling
    let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &encrypt_skey[..]).unwrap();

    // write salt
    write_all(sock, *salt.clone())
        .and_then(|(sock, _)| Ok(sock.split()))
        .and_then(move |(r, w)| {
            // wrap remote writer into secure channel
            let encryptor = Chacha20Poly1305Encryptor::new(sealing_key);
            let secure_writer = ShadowsocksWriter::new(w, encryptor);

            // write request addr in secure channel
            write_all(secure_writer, request_addr.bytes()).and_then(move |(sw, _)| Ok((r, sw)))
        })
        .and_then(move |(r, sw)| {
            read_exact(r, [0u8; 32]).and_then(move |(r, salt)| {
                trace!("Got salt from remote server: {:x?}", salt);

                let decrypt_skey = derivate_sub_key(config.password.as_bytes(), &salt);
                trace!("dec skey: {:x?}", decrypt_skey);
                // TODO: Error handling
                let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &decrypt_skey[..]).unwrap();

                // wrap remote reader into secure channel
                let decryptor = Chacha20Poly1305Decryptor::new(opening_key);
                let secure_reader = ShadowsocksReader::new(r, decryptor);

                Ok((secure_reader, sw))
            })
        })
}
//fn local_handshake(socket: TcpStream) -> impl Future<Item = TcpStream, Error = failure::Error> {
//trace!("Handshake {:?}", socket.peer_addr());

//// read socks version
//read_exact(socket, [0u8])
//.map_err(|e| e.into())
//.and_then(|(socket, buf)| {
//if buf[0] != 0x05 {
//Err(HandshakeError::VersionError { version: buf[0] }.into())
//} else {
//Ok(socket)
//}
//})
//// read method length
//.and_then(|socket| {
//read_exact(socket, [0u8])
//.map_err(|e| e.into())
//.and_then(|(socket, buf)| Ok((socket, buf[0] as usize)))
//})
//// read method list
//.and_then(|(socket, method_len)| {
//read_exact(socket, vec![0u8; method_len])
//.map_err(|e| e.into())
//.and_then(|(socket, buf)| {
//if buf.contains(&0x00) {
//Ok(socket)
//} else {
//Err(HandshakeError::MethodError { supported: buf }.into())
//}
//})
//})
//// write method select response
//.and_then(|socket| write_all(socket, [0x05, 0x00]).map_err(|e| e.into()))
//.and_then(|(socket, _)| Ok(socket))
//}

fn parse_addr(
    socket: TcpStream,
    atyp: u8,
) -> Box<Future<Item = (TcpStream, Socks5Host), Error = failure::Error> + Send> {
    match atyp {
        // domain
        0x03 => Box::new(
            read_exact(socket, [0u8])
                .map_err(|e| e.into())
                .and_then(|(sock, buf)| Ok((sock, buf[0] as usize)))
                .and_then(|(sock, len)| read_exact(sock, vec![0u8; len]).map_err(|e| e.into()))
                .and_then(|(sock, buf)| {
                    let domain = std::str::from_utf8(&buf[..])?;

                    Ok((sock, Socks5Host::Domain(domain.to_string())))
                }),
        ),
        // Ipv4 Addr
        0x01 => Box::new(read_exact(socket, [0u8; 4]).map_err(|e| e.into()).and_then(
            |(socket, buf)| {
                let ip = Ipv4Addr::from(buf);

                Ok((socket, Socks5Host::Ip(IpAddr::V4(ip))))
            },
        )),
        // Ipv6 Addr
        0x04 => Box::new(
            read_exact(socket, [0u8; 16])
                .map_err(|e| e.into())
                .and_then(|(socket, buf)| {
                    let ip = Ipv6Addr::from(buf);

                    Ok((socket, Socks5Host::Ip(IpAddr::V6(ip))))
                }),
        ),
        _ => unreachable!(),
    }
}

//fn create_connection(
//socket: TcpStream,
//config: Arc<ServerConfig>,
//) -> impl Future<Item = (TcpStream, TcpStream, Socks5Addr), Error = failure::Error> {
//trace!("create_connection {:?}", socket.peer_addr());

//read_exact(socket, [0u8; 4])
//.map_err(|e| e.into())
//.and_then(|(socket, buf)| {
//assert!(buf[0] == 0x05 && buf[1] == 0x01 && buf[2] == 0x00);
//Ok((socket, buf[3]))
//})
//.and_then(|(socket, atyp)| parse_addr(socket, atyp))
//.and_then(|(socket, addr)| {
//read_exact(socket, [0u8; 2])
//.map_err(|e| e.into())
//.and_then(move |(socket, buf)| {
//let port = u16::from_be_bytes([buf[0], buf[1]]);
//Ok((socket, Socks5Addr(addr, port)))
//})
//})
//.and_then(move |(socket, addr)| {
//TcpStream::connect(&config.addr)
//.map_err(|e| e.into())
//.and_then(move |serv_socket| Ok((socket, serv_socket, addr)))
//})
//.and_then(|(sock, serv_sock, addr)| {
//// fake data, client won't really use it!
//let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//write_all(sock, buf)
//.map_err(|e| e.into())
//.map(move |(sock, _)| (sock, serv_sock, addr))
//})
//}

struct Transfer<S, T> {
    sink: S,
    stream: T,

    buf: BytesMut,
}

impl<S, T> Future for Transfer<S, T>
where
    S: AsyncWrite,
    T: AsyncRead,
{
    type Item = ();
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if self.buf.len() != 0 {
                trace!("buf len {}", self.buf.len());
                // write
                let wsize = try_ready!(self.sink.poll_write(&self.buf[..]));
                let _: () = try_ready!(self.sink.poll_flush());
                trace!("write size: {}", wsize);
                //self.buf.split_to(wsize);
                self.buf.clear();
            }

            let mut buf = [0u8; 1024];

            // read
            let size = try_ready!(self.stream.poll_read(&mut buf));
            trace!("read size: {}", size);
            if size == 0 {
                trace!("END!!!");
                return Ok(Async::Ready(()));
            } else {
                self.buf.extend(&buf[..size]);
            }
            trace!("buf after read: {}", self.buf.len());
        }

        panic!()
    }
}

impl<S, T> Transfer<S, T> {
    pub fn new(sink: S, stream: T) -> Self {
        Self {
            sink,
            stream,

            buf: BytesMut::new(),
        }
    }
}
//struct Transfer<S, T> {
//sink: S,
//stream: T,

//buf: Option<BytesMut>,
//}

//impl<S, T> Future for Transfer<S, T>
//where
//S: Sink<SinkItem = BytesMut, SinkError = failure::Error>,
//T: Stream<Item = BytesMut, Error = failure::Error>,
//{
//type Item = ();
//type Error = failure::Error;

//fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
//loop {
//// read
//if let Some(b) = try_ready!(self.stream.poll()) {
//match self.buf.as_mut() {
//Some(buf) => buf.extend(b),
//None => self.buf = Some(b),
//}
//} else {
//let _: () = try_ready!(self.sink.close());
//return Ok(Async::Ready(()));
//}

//// write
//if let Some(b) = self.buf.take() {
//match self.sink.start_send(b)? {
//AsyncSink::NotReady(b) => {
//self.buf = Some(b);
//}
//AsyncSink::Ready => {
//let _: () = try_ready!(self.sink.poll_complete());
//}
//}
//}
//}
//}
//}

//impl<S, T> Transfer<S, T> {
//pub fn new(sink: S, stream: T) -> Self {
//Self {
//sink,
//stream,

//buf: None,
//}
//}
//}

//struct BytesForward {}

//impl BytesForward {
//pub fn new() -> Self {
//Self {}
//}
//}

//impl Decoder for BytesForward {
//type Item = BytesMut;
//type Error = failure::Error;

//fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
//if buf.is_empty() {
//return Ok(None);
//}

//let len = buf.len();
//Ok(Some(buf.split_to(len)))
//}
//}

//impl Encoder for BytesForward {
//type Item = BytesMut;
//type Error = failure::Error;

//fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
//trace!("client Raw data: {} {:?}", data.len(), data);

//buf.reserve(data.len());
//buf.put(data);
//Ok(())
//}
//}

//struct Chacha20Poly1305Codec_ {
//server_config: Arc<ServerConfig>,
//encrypt_skey: [u8; 32],
//decrypt_skey: Option<OpeningKey>,
//encrypt_nonce: [u8; 12],
//decrypt_nonce: [u8; 12],
//waitting_decrypt: Option<usize>,
//}

//impl Chacha20Poly1305Codec_ {
//pub fn new(server_config: Arc<ServerConfig>) -> Self {
//let salt = *b"01234567890123456789012345678901";

//Self {
//server_config: server_config.clone(),
//encrypt_skey: derivate_sub_key(server_config.password.as_bytes(), &salt),
//decrypt_skey: None,
//encrypt_nonce: *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
//decrypt_nonce: [0u8; 12],
//waitting_decrypt: None,
//}
//}

//fn encrypt(&mut self, buf: &BytesMut) -> Result<Bytes, failure::Error> {
//let payload_len = buf.len() as u16;
//assert!(payload_len < 0x3fff);

//let mut len_payload = vec![0u8; 18];
//len_payload[0] = (payload_len >> 8) as u8;
//len_payload[1] = (payload_len & 0xff) as u8;

//let nonce = self.encrypt_nonce();
//let sealing_key =
//SealingKey::new(&CHACHA20_POLY1305, &self.encrypt_skey[..]).expect("sealing key error");
//let out_len = seal_in_place(&sealing_key, nonce, Aad::empty(), &mut len_payload, 16)?;

//let mut payload_encrypted = BytesMut::with_capacity(16 + buf.len());
//payload_encrypted.put(&buf[..]);
//payload_encrypted.put(vec![0u8; 16]);
//let nonce = self.encrypt_nonce();
//let out_len = seal_in_place(
//&sealing_key,
//nonce,
//Aad::empty(),
//&mut payload_encrypted,
//16,
//)?;

//let mut encrypted = BytesMut::with_capacity(len_payload.len() + payload_encrypted.len());
//encrypted.extend(len_payload);
//encrypted.extend(payload_encrypted);
//Ok(encrypted.freeze())
//}

//fn decrypt_nonce(&mut self) -> Nonce {
//let nonce = Nonce::assume_unique_for_key(self.decrypt_nonce);
//nonce_plus_one(&mut self.decrypt_nonce);

//nonce
//}

//fn encrypt_nonce(&mut self) -> Nonce {
//let nonce = Nonce::assume_unique_for_key(self.encrypt_nonce);
//nonce_plus_one(&mut self.encrypt_nonce);

//nonce
//}
//}

//impl Decoder for Chacha20Poly1305Codec_ {
//type Item = BytesMut;
//type Error = failure::Error;

//fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
//if buf.is_empty() {
//return Ok(None);
//}

//if self.decrypt_skey.is_none() {
//if buf.len() < 32 {
//return Ok(None);
//}

//let salt = buf.split_to(32);
//trace!("Got salt: {:x?}", salt);
//let skey = derivate_sub_key(&self.server_config.password.as_bytes()[..], &salt);
//trace!("derivate sub key: {:x?}", skey);
//let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &skey).unwrap();

//self.decrypt_skey = Some(opening_key);
//}

//if self.waitting_decrypt.is_none() {
//if buf.len() < 18 {
//return Ok(None);
//}

//let payload_len = {
//let mut b = buf.split_to(18);
//let nonce = self.decrypt_nonce();
//let open_key = self.decrypt_skey.as_mut().unwrap();
//let r = open_in_place(open_key, nonce, Aad::empty(), 0, &mut b).unwrap();
//u16::from_be_bytes([r[0], r[1]]) as usize
//};
//trace!("Got payload with len = {}", payload_len);

//self.waitting_decrypt = Some(payload_len);
//}

//let payload_len = self.waitting_decrypt.unwrap();
//if buf.len() < payload_len + 16 {
//return Ok(None);
//}
//self.waitting_decrypt = None;

//assert!(buf.len() >= payload_len + 16);
//let mut b = buf.split_to(payload_len + 16);
//let nonce = self.decrypt_nonce();
//let open_key = self.decrypt_skey.as_mut().unwrap();
//let r = open_in_place(open_key, nonce, Aad::empty(), 0, &mut b);

//Ok(Some(BytesMut::from(&r.unwrap()[..])))
//}
//}

//impl Encoder for Chacha20Poly1305Codec_ {
//type Item = BytesMut;
//type Error = failure::Error;

//fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
//trace!("Raw Data: {:?}", data);
//let data = self.encrypt(&data)?;
//trace!("Encrypted Data: {:?}", data);

//buf.reserve(data.len());
//buf.put(data);
//Ok(())
//}
//}

struct ServerConfig {
    addr: SocketAddr,
    password: String,
}

impl ServerConfig {
    pub fn new() -> Self {
        Self {
            addr: "172.96.230.37:8100".parse().unwrap(),
            password: "nT9kz6aoxG".to_string(),
            //addr: "[::]:5001".parse().unwrap(),
            //password: "123456".to_string(),
        }
    }
}

fn main() {
    env_logger::builder()
        .default_format_timestamp(false)
        .default_format_module_path(false)
        .init();

    let config = Arc::new(ServerConfig::new());
    let addr: SocketAddr = "[::]:5002".parse().unwrap();
    let f = TcpListener::bind(&addr)
        .unwrap()
        .incoming()
        .map_err(|e| error!("Incoming Error: {:?}", e))
        .for_each(move |socket| {
            trace!("Incoming from {:?}", addr);

            let config = config.clone();
            let remote = remote_establish(config.clone())
                .map_err(|e| error!("Establish connection to server failed: {:?}", e));
            let local = local_establish(socket)
                .map_err(|e| error!("Establish connection from local failed: {:?}", e));

            let serv =
                remote
                    .join(local)
                    .and_then(move |(remote_sock, (local_sock, request_addr))| {
                        info!("Relay Connection Established");

                        let remote = remote_handshake(remote_sock, config.clone(), request_addr)
                            .map_err(|e| error!("Handshake with server failed: {:?}", e));
                        let local = local_handshake(local_sock)
                            .map_err(|e| error!("Handshake with local failed: {:?}", e));

                        remote.join(local).and_then(
                            |((remote_read, remote_write), (local_read, local_write))| {
                                trace!("Join !!!");
                                let download = tokio::io::copy(remote_read, local_write);
                                let upload = tokio::io::copy(local_read, remote_write);

                                tokio::spawn(download.map_err(|_| ()).and_then(|_| Ok(())));
                                tokio::spawn(upload.map_err(|_| ()).and_then(|_| Ok(())));

                                Ok(())

                                //let download = Transfer::new(local_write, remote_read);
                                //let upload = Transfer::new(remote_write, local_read);
                                //tokio::spawn(download.map_err(|_| ()));
                                //tokio::spawn(upload.map_err(|_| ()));

                                //Ok(())
                                //upload
                                //.join(download)
                                //.map_err(|e| error!("Transfer error: {:?}", e))
                                //.and_then(|_| Ok(()))
                            },
                        )
                    });

            //let config1 = config.clone();
            //let config2 = config.clone();
            //let addr = socket.peer_addr();

            //let serv = local_handshake(socket)
            //.and_then(move |socket| create_connection(socket, config1.clone()))
            //.and_then(|(sock, serv_sock, addr)| {
            //write_all(serv_sock, b"01234567890123456789012345678901")
            //.map_err(|e| e.into())
            //.and_then(move |(serv_sock, _)| Ok((sock, serv_sock, addr)))
            //})
            //.and_then(move |(socket, serv_socket, addr)| {
            //let src_frame = BytesForward::new().framed(socket);
            //let dst_frame =
            //Chacha20Poly1305Codec_::new(config2.clone()).framed(serv_socket);

            //Ok((src_frame, dst_frame, addr))
            //})
            //.and_then(|(src_frame, mut dst_frame, addr)| {
            //let sl = src_frame.get_ref().local_addr().unwrap();
            //let sp = src_frame.get_ref().peer_addr().unwrap();
            //let dl = dst_frame.get_ref().local_addr().unwrap();
            //let dp = dst_frame.get_ref().peer_addr().unwrap();
            //info!(
            //"Relay {:?}: {:?} -> {:?} -> {:?} -> {:?}",
            //addr, sl, sp, dl, dp
            //);

            //dst_frame.start_send(addr.bytes()).unwrap();

            //let (src_sink, src_stream) = src_frame.split();
            //let (dst_sink, dst_stream) = dst_frame.split();

            //let download = Transfer::new(src_sink, dst_stream);
            //let upload = Transfer::new(dst_sink, src_stream);

            //upload.join(download).map(move |_| {
            //trace!("Relay END {:?} -> {:?} -> {:?} -> {:?}", sl, sp, dl, dp);
            //})
            //})
            //.map_err(move |e| error!("Server Error: {:?} {}", addr, e));

            tokio::spawn(serv)
        });

    tokio::run(f);
}
