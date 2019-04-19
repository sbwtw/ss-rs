use bytes::buf::BufMut;
use bytes::{Bytes, BytesMut};
//use chacha20_poly1305_aead::*;
use failure::Fail;
use futures::sink::Sink;
use futures::sync::mpsc;
use futures::try_ready;
use futures::{Async, Future, Poll};
use log::*;
use ring::aead::*;
use ring::digest::SHA1;
use ring::hkdf;
use ring::hmac::SigningKey;
use tokio::codec::{BytesCodec, Decoder, Encoder, Framed};
use tokio::io::{read_exact, write_all, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::stream::{SplitSink, SplitStream, Stream};
use tokio::prelude::*;

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

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

fn handshake(socket: TcpStream) -> impl Future<Item = TcpStream, Error = failure::Error> {
    trace!("Handshake {:?}", socket.peer_addr());

    // read socks version
    read_exact(socket, [0u8])
        .map_err(|e| e.into())
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
                .map_err(|e| e.into())
                .and_then(|(socket, buf)| Ok((socket, buf[0] as usize)))
        })
        // read method list
        .and_then(|(socket, method_len)| {
            read_exact(socket, vec![0u8; method_len])
                .map_err(|e| e.into())
                .and_then(|(socket, buf)| {
                    if buf.contains(&0x00) {
                        Ok(socket)
                    } else {
                        Err(HandshakeError::MethodError { supported: buf }.into())
                    }
                })
        })
        // write method select response
        .and_then(|socket| write_all(socket, [0x05, 0x00]).map_err(|e| e.into()))
        .and_then(|(socket, _)| Ok(socket))
}

fn parse_ip(
    socket: TcpStream,
    atyp: u8,
) -> Box<Future<Item = (TcpStream, IpAddr), Error = failure::Error> + Send> {
    match atyp {
        // domain
        0x03 => {
            Box::new(
                read_exact(socket, [0u8])
                    .map_err(|e| e.into())
                    .and_then(|(sock, buf)| Ok((sock, buf[0] as usize)))
                    .and_then(|(sock, len)| read_exact(sock, vec![0u8; len]).map_err(|e| e.into()))
                    .and_then(|(sock, buf)| {
                        // TODO: domain dns resolve
                        println!("read buf: ->{}<-", std::str::from_utf8(&buf[..]).unwrap());
                        Ok((sock, "127.0.0.1".parse().unwrap()))
                    }),
            )
        }
        // Ipv4 Addr
        0x01 => Box::new(read_exact(socket, [0u8; 4]).map_err(|e| e.into()).and_then(
            |(socket, buf)| {
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                Ok((socket, IpAddr::V4(ip)))
            },
        )),
        // Ipv6 Addr
        0x04 => Box::new(
            read_exact(socket, [0u8; 16])
                .map_err(|e| e.into())
                .and_then(|(socket, buf)| {
                    let a = u16::from_be_bytes([buf[0], buf[1]]);
                    let b = u16::from_be_bytes([buf[2], buf[3]]);
                    let c = u16::from_be_bytes([buf[4], buf[5]]);
                    let d = u16::from_be_bytes([buf[6], buf[7]]);
                    let e = u16::from_be_bytes([buf[8], buf[9]]);
                    let f = u16::from_be_bytes([buf[10], buf[11]]);
                    let g = u16::from_be_bytes([buf[12], buf[13]]);
                    let h = u16::from_be_bytes([buf[14], buf[15]]);

                    let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                    Ok((socket, IpAddr::V6(ip)))
                }),
        ),
        _ => unreachable!(),
    }
}

//fn proxy_handshake(
//remote_sock: TcpStream,
//) -> impl Future<Item = (ReadHalf<TcpStream>, WriteHalf<TcpStream>), Error = failure::Error> {
//trace!("proxy handshake {:?}", remote_sock.peer_addr());

//let (sr, sw) = remote_sock.split();
//unimplemented!()
//let sr = read_exact(sr, vec![0u8; 1]).map_err(|e| e.into());
//let sw = write_all(sw, salt)
//.and_then(move |(sw, _)| write_all(sw, data.to_vec()))
//.map_err(|e| e.into());

//sr.join(sw).map(|((sr, bufw), (sw, bufr))| {
//println!("bufw: {:?}", bufw);
//println!("bufr: {:?}", bufr);

//sr.unsplit(sw)
//})

//write_all(remote_sock, salt)
//.map_err(|e| e.into())
//.and_then(|(sock, s)| {
//println!("proxy handshake: {:?} {:?}", sock.peer_addr(), s);
//Ok(sock)
//})
//.and_then(|sock| {
//write_all(sock, b"\x01h\x10\xf9\xf9\x01\xbb")
//.map_err(|e| e.into())
//.and_then(|(sock, s)| {
//println!("send {:?} {:?}", sock.peer_addr(), s);
//Ok(sock)
//})
//})
//.and_then(|sock| {
//println!("start read remote salt");
//read_exact(sock, [0u8; 32])
//.map_err(|e| e.into())
//.and_then(|(sock, buf)| {
//println!("read from remote {:?} {:?}", sock.peer_addr(), buf);

//Ok(sock)
//})
//})
//}

fn create_connection(
    socket: TcpStream,
    config: Arc<ServerConfig>,
) -> impl Future<Item = (TcpStream, TcpStream, SocketAddr), Error = failure::Error> {
    trace!("create_connection {:?}", socket.peer_addr());

    read_exact(socket, [0u8; 4])
        .map_err(|e| e.into())
        .and_then(|(socket, buf)| {
            assert!(buf[0] == 0x05 && buf[1] == 0x01 && buf[2] == 0x00);
            Ok((socket, buf[3]))
        })
        .and_then(|(socket, atyp)| parse_ip(socket, atyp))
        .and_then(|(socket, ip)| {
            read_exact(socket, [0u8; 2])
                .map_err(|e| e.into())
                .and_then(move |(socket, buf)| {
                    let port = u16::from_be_bytes([buf[0], buf[1]]);
                    Ok((socket, SocketAddr::new(ip, port)))
                })
        })
        .and_then(move |(socket, addr)| {
            TcpStream::connect(&config.addr)
                .map_err(|e| e.into())
                .and_then(move |serv_socket| Ok((socket, serv_socket, addr)))
        })
        .and_then(|(sock, serv_sock, addr)| {
            // fake data, client won't really use it!
            let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            write_all(sock, buf)
                .map_err(|e| e.into())
                .map(move |(sock, _)| (sock, serv_sock, addr))
        })
}

struct Transfer<S, T> {
    sink: S,
    stream: T,

    buf: Option<BytesMut>,
}

impl<S, T> Future for Transfer<S, T>
where
    S: Sink<SinkItem = BytesMut, SinkError = failure::Error>,
    T: Stream<Item = BytesMut, Error = failure::Error>,
{
    type Item = ();
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            // read
            if let Some(b) = try_ready!(self.stream.poll()) {
                match self.buf.as_mut() {
                    Some(buf) => buf.extend(b),
                    None => self.buf = Some(b),
                }
            } else {
                let _: () = try_ready!(self.sink.close());
                return Ok(Async::Ready(()));
            }

            // write
            if let Some(b) = self.buf.take() {
                match self.sink.start_send(b)? {
                    AsyncSink::NotReady(b) => {
                        self.buf = Some(b);
                    }
                    AsyncSink::Ready => {
                        let _: () = try_ready!(self.sink.poll_complete());
                    }
                }
            }
        }
    }
}

impl<S, T> Transfer<S, T> {
    pub fn new(sink: S, stream: T) -> Self {
        Self {
            sink,
            stream,

            buf: None,
        }
    }
}

struct Decrypter {}

impl Decrypter {
    pub fn new() -> Self {
        Self {}
    }
}

impl Decoder for Decrypter {
    type Item = BytesMut;
    type Error = failure::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        //trace!("Decrypter decode: {} {:?}", buf.len(), buf);

        let len = buf.len();
        Ok(Some(buf.split_to(len)))
    }
}

impl Encoder for Decrypter {
    type Item = BytesMut;
    type Error = failure::Error;

    fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        //trace!("Decrypter encode: {} {:?}", data.len(), data);

        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}

struct Encrypter {
    initialized: bool,
    server_config: Arc<ServerConfig>,
    buffer: BytesMut,
    salt: [u8; 32],
    nonce: [u8; 12],
}

impl Encrypter {
    pub fn new(server_config: Arc<ServerConfig>) -> Self {
        Self {
            initialized: false,
            server_config,
            buffer: BytesMut::new(),
            salt: *b"01234567890123456789012345678901",
            nonce: *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        }
    }

    fn handshake(&mut self, buf: &BytesMut) -> Bytes {
        //let skey = self.derivate_sub_key();
        let buf = b"\x01\x00\x00\x00\x00\x00\x00";
        let skey = b"\xa74\xa7\x91\xa9\xf4\xfb=\x0c\xad\xc9\\H\xa0\xa7\x19\xac}\xd7\xd2\xab\xfe\xd4\x9f\x95{K\x82\xb8\xef\xdf\x97";
        trace!("skey {:x?}", skey);

        let payload_len = buf.len() as u16;
        //let payload_len_buf = vec![(payload_len & 0xff >> 8) as u8, payload_len as u8];
        let mut len_payload = vec![0u8; 18];
        len_payload[1] = payload_len as u8;
        len_payload[0] = (payload_len & 0xff >> 8) as u8;

        let sealing_key =
            SealingKey::new(&CHACHA20_POLY1305, &skey[..]).expect("sealing key error");
        let out_len = seal_in_place(
            &sealing_key,
            self.nonce(),
            Aad::empty(),
            &mut len_payload,
            16,
        )
        .expect("seal error");
        println!("seal len {}", out_len);
        println!("seal result {:02x?}", len_payload);

        // decrypt
        //let open_key = OpeningKey::new(&CHACHA20_POLY1305, &skey[..]).expect("open key error");
        //let nonce = Nonce::assume_unique_for_key(self.nonce);
        //let text = open_in_place(&open_key, nonce, Aad::empty(), 0, &mut len_payload).unwrap();
        //println!("open: {:x?}", text);

        let mut payload_encrypted = BytesMut::with_capacity(16 + buf.len());
        payload_encrypted.put(&buf[..]);
        payload_encrypted.put(vec![0u8; 16]);
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        let out_len = seal_in_place(
            &sealing_key,
            self.nonce(),
            Aad::empty(),
            &mut payload_encrypted,
            16,
        )
        .unwrap();
        println!("seal len {}", out_len);
        println!("seal result {:02x?}", payload_encrypted);
        //let mut encrypted_payload = vec![];
        //let payload_tag = encrypt(&skey, &self.nonce, &[], buf, &mut encrypted_payload).unwrap();

        //println!("{}: {:?}", tag.len(), tag);
        let mut handshake = BytesMut::new();
        handshake.extend(&self.salt);
        handshake.extend(len_payload);
        handshake.extend(payload_encrypted);
        //handshake.extend(encrypted_len);
        //handshake.extend(&len_tag);
        //handshake.extend(encrypted_payload);
        //handshake.extend(&payload_tag);

        handshake.freeze()
    }

    fn derivate_sub_key(&self) -> Bytes {
        let salt = SigningKey::new(&SHA1, &self.salt);
        let psk = &self.server_config.password;
        let mut skey = vec![0u8; 32];

        hkdf::extract_and_expand(&salt, psk.as_bytes(), b"ss-subkey", &mut skey);

        Bytes::from(skey)
    }

    fn nonce(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.nonce);

        // plus 1 after each use
        for i in 0..self.nonce.len() {
            match self.nonce[i] {
                b'\xff' => self.nonce[i] = b'\x00',
                _ => {
                    self.nonce[i] += 1;
                    break;
                }
            }
        }

        nonce
    }
}

impl Decoder for Encrypter {
    type Item = BytesMut;
    type Error = failure::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        //trace!("Encrypter decode: {} {:?}", buf.len(), buf);

        let len = buf.len();
        Ok(Some(buf.split_to(len)))
    }
}

impl Encoder for Encrypter {
    type Item = BytesMut;
    type Error = failure::Error;

    fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Encrypter encode: {} {:?}", data.len(), data);

        let data = if !self.initialized {
            self.initialized = true;
            self.handshake(&data)
        } else {
            data.freeze()
        };

        trace!("Encrypter encode result: {} {:?}", data.len(), data);

        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}

struct ServerConfig {
    addr: SocketAddr,
    password: String,
}

impl ServerConfig {
    pub fn new() -> Self {
        Self {
            //addr: "172.96.230.37:8100".parse().unwrap(),
            //password: "nT9kz6aoxG".to_string(),
            addr: "[::]:5001".parse().unwrap(),
            password: "123456".to_string(),
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

            let config1 = config.clone();
            let config2 = config.clone();
            let addr = socket.peer_addr();

            let serv = handshake(socket)
                .and_then(move |socket| create_connection(socket, config1.clone()))
                //.and_then(|(sock, serv_sock)| {
                //proxy_handshake(serv_sock).and_then(move |serv_sock| Ok((sock, serv_sock)))
                //})
                .and_then(move |(socket, serv_socket, addr)| {
                    let sl = socket.local_addr().unwrap();
                    let sp = socket.peer_addr().unwrap();
                    let dl = serv_socket.local_addr().unwrap();
                    let dp = serv_socket.peer_addr().unwrap();
                    info!(
                        "Relay {:?}: {:?} -> {:?} -> {:?} -> {:?}",
                        addr, sl, sp, dl, dp
                    );

                    let src_frame = Decrypter::new().framed(socket);
                    let dst_frame = Encrypter::new(config2.clone()).framed(serv_socket);
                    let (src_sink, src_stream) = src_frame.split();
                    let (dst_sink, dst_stream) = dst_frame.split();

                    //let a = src_stream.forward(dst_sink);
                    //let b = dst_stream.forward(src_sink);

                    //tokio::spawn(a.map_err(|_| ()).and_then(|_| Ok(())));
                    //tokio::spawn(b.map_err(|_| ()).and_then(|_| Ok(())));
                    //Ok(())

                    //let src = Arc::new(socket);
                    //let dst = Arc::new(serv_socket);
                    let download = Transfer::new(src_sink, dst_stream);
                    let upload = Transfer::new(dst_sink, src_stream);
                    //let upload = Transfer::new(src.clone(), dst.clone());
                    //let download = Transfer::new(dst.clone(), src.clone());
                    //tokio::spawn(upload.map_err(|e| println!("upload error: {}", e)));
                    //tokio::spawn(download.map_err(|e| println!("upload error: {}", e)));

                    upload.join(download).map(move |_| {
                        trace!("Relay END {:?} -> {:?} -> {:?} -> {:?}", sl, sp, dl, dp);
                    })
                })
                .map_err(move |e| error!("Server Error: {:?} {}", addr, e));

            tokio::spawn(serv)
        });

    tokio::run(f);
}
