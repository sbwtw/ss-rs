//use tokio::io::read_exact;
//use tokio::net::TcpStream;
//use tokio::prelude::*;

pub fn nonce_plus_one(nonce: &mut [u8]) {
    for i in 0..nonce.len() {
        match nonce[i] {
            b'\xff' => nonce[i] = b'\x00',
            _ => {
                nonce[i] += 1;
                break;
            }
        }
    }
}

