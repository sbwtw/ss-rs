
use futures::{Future, Async, Poll};
use futures::try_ready;
use futures::sync::mpsc;
use futures::sink::Sink;
use tokio::prelude::AsyncWrite;
use tokio::prelude::stream::Stream;
use tokio::net::{TcpListener, TcpStream};
use tokio::codec::{Encoder, Decoder, Framed};
use bytes::BytesMut;
use bytes::buf::BufMut;

use std::net::{SocketAddr, IpAddr};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::cell::Cell;

#[derive(Clone, Debug)]
enum RequestAddr {
    Domain(String),
    Ipv4(u32),
    //Ipv6([u32; 4]),
}

#[derive(Clone, Debug)]
struct Request {
    ver: u8,
    cmd: u8,
    _rsv: u8,
    atyp: u8,
    dst_port: u16,
    dst_addr: RequestAddr,
}

impl Request {
    fn new(buf: &mut BytesMut) -> Option<Self> {
        let ver = buf[0];
        let cmd = buf[1];
        let _rsv = buf[2];
        let atyp = buf[3];

        let dst_addr = match atyp {
            0x01 => {
                let ip = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let _ = buf.split_to(4);
                RequestAddr::Ipv4(ip)
            },
            0x03 => {
                let len = buf[4] as usize;
                let _ = buf.split_to(5);
                let domain = buf.split_to(len);
                let domain = std::str::from_utf8(&domain[..]).unwrap();
                RequestAddr::Domain(domain.to_string())
            },
            //0x04 => {},

            _ => { println!("ERROR when parse request"); return None; }
        };

        let dst_port = u16::from_be_bytes([buf[0], buf[1]]);

        Some(Self {
            ver,
            cmd,
            _rsv,
            atyp,
            dst_addr,
            dst_port,
        })
    }
}

#[derive(Clone, Debug)]
enum SocksMsgV5 {
    Handshake,
    Request(Request),
    Forward(BytesMut),
}

enum State {
    Init,
    Handshake,
    Forward,
}

struct SocksCodecV5 {
    state: State,
}

impl SocksCodecV5 {
    pub fn new() -> Self {
        Self {
            state: State::Init,
        }
    }
}

impl Encoder for SocksCodecV5 {
    type Item = Vec<u8>;
    type Error = failure::Error;

    fn encode(&mut self, src: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.reserve(src.len());
        buf.put(&src[..]);
        Ok(())
    }
}

impl Decoder for SocksCodecV5 {
    type Item = SocksMsgV5;
    type Error = failure::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() == 0 {
            return Ok(None);
        }

        match self.state {
            State::Init => {
                buf.clear();
                self.state = State::Handshake;
                Ok(Some(SocksMsgV5::Handshake))
            },
            State::Handshake => {
                if let Some(r) = Request::new(buf) {
                    self.state = State::Forward;
                    buf.clear();
                    Ok(Some(SocksMsgV5::Request(r)))
                } else {
                    panic!()
                }
            },
            _ => {
                Ok(Some(SocksMsgV5::Forward(buf.take())))
            }
        }
    }
}

struct Shared {
    peers: HashMap<SocketAddr, mpsc::UnboundedSender<String>>,
}

impl Shared {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }
}

struct Client {
    sender: mpsc::UnboundedSender<SocketAddr>,
    receiver: mpsc::UnboundedReceiver<SocketAddr>,
    shared: Arc<Mutex<Shared>>,
    framed: Cell<Framed<TcpStream, SocksCodecV5>>,
}

impl Client {
    pub fn new(socket: TcpStream, shared: Arc<Mutex<Shared>>) -> Self {

        //let addr = socket.peer_addr().unwrap();
        let (tx, rx) = mpsc::unbounded();
        let framed = SocksCodecV5::new().framed(socket);
        //shared.lock().unwrap().peers.insert(addr, tx);

        Self {
            sender: tx,
            receiver: rx,
            shared,
            framed: Cell::new(framed),
        }
    }

    //fn peer_addr(&self) -> SocketAddr {
        //self.framed.get_ref().peer_addr().unwrap()
    //}
}

impl Drop for Client {
    fn drop(&mut self) {
        //let addr = self.peer_addr();
        //self.shared.lock().unwrap().peers.remove(&addr);
    }
}

impl Future for Client {
    type Item = ();
    type Error = failure::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        //let peer_addr = self.peer_addr();

        // read from channel and write to socket
        while let Async::Ready(r) = self.receiver.poll().unwrap() {
            match r {
                Some(s) => {
                    let mut buf: Vec<u8> = vec![0x05, 0x00, 0x00, 0x01];
                    match s.ip() {
                        IpAddr::V4(ipv4) => {
                            buf.append(&mut ipv4.octets().to_vec());
                        },
                        _ => { panic!(); },
                    }
                    let port: u16 = s.port();
                    buf.push(((port >> 8) & 0xff) as u8);
                    buf.push(((port     ) & 0xff) as u8);
                    println!("Transfer addr: {:?}", s);
                    self.framed.get_mut().start_send(buf)?;
                    self.framed.get_mut().poll_complete()?;
                },
                _ => {},
            }
        }

        while let Async::Ready(item) = self.framed.get_mut().poll()? {
            match item {
                Some(SocksMsgV5::Handshake) => {
                    self.framed.get_mut().start_send(vec![b'\x05', b'\x00'])?;
                },
                Some(SocksMsgV5::Request(r)) => {
                    println!("Request: {:?}", r);
                    let tx = self.sender.clone();
                    let socket = self.framed.take().into_inner();
                    let transfer = TcpStream::connect(&"61.135.169.121:80".parse().unwrap()).map(move |socket| {
                        tx.unbounded_send(socket.local_addr().unwrap()).unwrap();
                    });

                    tokio::spawn(transfer.map_err(|_| ()));
                    return Ok(Async::Ready(()));
                },
                Some(SocksMsgV5::Forward(buf)) => {
                    println!("Forward: {:?}", buf);
                }
                _ => {
                    println!("ERROR when recv");
                    return Ok(Async::Ready(()));
                }
            }

            self.framed.get_mut().poll_complete()?;
        }

        Ok(Async::NotReady)
    }
}

//struct Transfer {
    //socket: TcpStream,
//}

//impl Transfer {
    //pub fn new(req: &Request) -> Self {
        //let socket = TcpStream::connect("61.135.169.121:80");

        //Self {
            //socket,
        //}
    //}
//}

fn main() {
    let shared = Arc::new(Mutex::new(Shared::new()));

    let addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
    let f = TcpListener::bind(&addr)
        .unwrap()
        .incoming()
        .map_err(|e| println!("Incoming Error: {:?}", e))
        .for_each(move |socket| {
        println!("NEW connection: {:?}", socket.peer_addr());

        let peer = Client::new(socket, shared.clone());

        tokio::spawn(peer.map_err(|e| println!("Client Error: {:?}", e)))
    });

    tokio::run(f);
}

