use serde_derive::Deserialize;

use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    server_addr: SocketAddr,
    encrypt_method: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    bind_addr: SocketAddr,
    server: Vec<ServerConfig>,
}
