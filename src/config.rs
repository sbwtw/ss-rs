use serde::de::Deserializer;
use serde::Deserialize;
use serde_derive::Deserialize;

use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};

fn parse_socket_addr<'de, D>(d: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d)
        .map(|s: Option<&'de str>| s.unwrap().to_socket_addrs().unwrap().next().unwrap())
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(deserialize_with = "parse_socket_addr")]
    server_addr: SocketAddr,
    encrypt_method: String,
    password: String,
}

impl ServerConfig {
    pub fn addr(&self) -> &SocketAddr {
        &self.server_addr
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn encrypt_method(&self) -> &str {
        &self.encrypt_method
    }
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    #[serde(deserialize_with = "parse_socket_addr")]
    bind_addr: SocketAddr,
    server: Vec<ServerConfig>,
}

impl ClientConfig {
    pub fn from_file(f: &mut File) -> Result<ClientConfig, failure::Error> {
        let mut buf = String::new();
        f.read_to_string(&mut buf)?;

        toml::from_str(&buf).map_err(Into::into)
    }

    pub fn bind_addr(&self) -> &SocketAddr {
        &self.bind_addr
    }

    pub fn server_list(&self) -> &Vec<ServerConfig> {
        &self.server
    }
}
