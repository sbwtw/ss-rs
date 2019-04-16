
use futures::{Future, Async, Poll};
use futures::try_ready;
use futures::sync::mpsc;
use futures::sink::Sink;
use tokio::prelude::*;
use tokio::prelude::stream::Stream;
use tokio::io::{read_exact, write_all};
use tokio::net::{TcpListener, TcpStream};
use tokio::codec::{Encoder, Decoder, Framed};
use bytes::BytesMut;
use bytes::buf::BufMut;
use failure::Fail;

use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

#[derive(Debug, Fail)]
enum HandshakeError {
    #[fail(display = "Socks5 Version Error: 0x{:02x}", version)]
    VersionError {
        version: u8,
    },
    #[fail(display = "Only method type 0x00 is supported, server request one of {:x?}", supported)]
    MethodError {
        supported: Vec<u8>,
    },
}

fn handshake(socket: TcpStream) -> impl Future<Item = TcpStream, Error = failure::Error> {
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
            .and_then(|(socket, buf)| {
                Ok((socket, buf[0] as usize))
            })
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
    .and_then(|socket| {
        write_all(socket, [0x05, 0x00])
            .map_err(|e| e.into())
    })
    .and_then(|(socket, _)| {
        Ok(socket)
    })
}

fn create_connection(socket: TcpStream) -> impl Future<Item = (TcpStream, TcpStream), Error = failure::Error> {
    read_exact(socket, [0u8; 4])
        .map_err(|e| e.into())
        .and_then(|(socket, buf)| {
            assert!(buf[0] == 0x05 && buf[1] == 0x01 && buf[2] == 0x00);
            Ok((socket, buf[3]))
        })
    .and_then(|(socket, atyp)| {
        match atyp {
            0x01 => {
                read_exact(socket, [0u8; 4])
                    .map_err(|e| e.into())
                    .and_then(|(socket, buf)| {
                        let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                        Ok((socket, IpAddr::V4(ip)))
                    })
            }
            _ => panic!(),
        }
    })
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
}

struct Transfer {
}

impl Future for Transfer {
    type Item = ();
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::Ready(()))
    }
}

impl Transfer {
    pub fn new(socket: TcpStream, serv_socket: TcpStream) -> Self {
        println!("relay {:?} --> {:?} --> {:?} --> {:?}", socket.local_addr(), socket.peer_addr(), serv_socket.local_addr(), serv_socket.peer_addr());

        Self {
        }
    }
}

fn main() {
    let addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
    let f = TcpListener::bind(&addr)
        .unwrap()
        .incoming()
        .map_err(|e| println!("Incoming Error: {:?}", e))
        .for_each(move |socket| {

        let serv = handshake(socket)
            .and_then(|socket| {
                create_connection(socket)
            })
            .and_then(|(socket, serv_socket)| {
                Transfer::new(socket, serv_socket)
            })
            .map_err(|e| println!("Server Error: {}", e));

        tokio::spawn(serv)
    });

    tokio::run(f);
}

