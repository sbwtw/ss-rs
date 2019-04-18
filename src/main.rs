use bytes::buf::BufMut;
use bytes::BytesMut;
use failure::Fail;
use futures::sink::Sink;
use futures::sync::mpsc;
use futures::try_ready;
use futures::{Async, Future, Poll};
use log::*;
use tokio::codec::{BytesCodec, Decoder, Encoder, Framed};
use tokio::io::{read_exact, write_all};
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
        0x03 => unimplemented!(),
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

fn create_connection(
    socket: TcpStream,
) -> impl Future<Item = (TcpStream, TcpStream), Error = failure::Error> {
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
        .and_then(|(socket, addr)| {
            TcpStream::connect(&addr)
                .map_err(|e| e.into())
                .and_then(move |serv_socket| Ok((socket, serv_socket)))
        })
        .and_then(|(sock, serv_sock)| {
            // fake data, client won't really use it!
            let buf = vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            write_all(sock, buf)
                .map_err(|e| e.into())
                .map(move |(sock, _)| (sock, serv_sock))
        })
}

struct Transfer<S: Sink, T: Stream> {
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
                    Some(buf) => buf.put(b),
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

impl<S: Sink, T: Stream> Transfer<S, T> {
    pub fn new(sink: S, stream: T) -> Self {
        Self {
            sink,
            stream,

            buf: None,
        }
    }
}

struct BytesForward(());

impl BytesForward {
    pub fn new() -> Self {
        BytesForward(())
    }
}

impl Decoder for BytesForward {
    type Item = BytesMut;
    type Error = failure::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() > 0 {
            let len = buf.len();
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for BytesForward {
    type Item = BytesMut;
    type Error = failure::Error;

    fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}
fn main() {
    env_logger::builder()
        .default_format_timestamp(false)
        .default_format_module_path(false)
        .init();

    let addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
    let f = TcpListener::bind(&addr)
        .unwrap()
        .incoming()
        .map_err(|e| error!("Incoming Error: {:?}", e))
        .for_each(move |socket| {
            let addr = socket.peer_addr();
            trace!("Incoming from {:?}", addr);

            let serv = handshake(socket)
                .and_then(|socket| create_connection(socket))
                .and_then(|(socket, serv_socket)| {
                    let sl = socket.local_addr();
                    let sp = socket.peer_addr();
                    let dl = serv_socket.local_addr();
                    let dp = serv_socket.peer_addr();
                    info!("Relay {:?} -> {:?} -> {:?} -> {:?}", sl, sp, dl, dp);

                    let src_frame = BytesForward::new().framed(socket);
                    let dst_frame = BytesForward::new().framed(serv_socket);
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
