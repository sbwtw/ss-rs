# ss-rs [![Build Status](https://travis-ci.org/sbwtw/ss-rs.svg)](https://travis-ci.org/sbwtw/ss-rs) [![Build Status](https://ci.appveyor.com/api/projects/status/github/sbwtw/ss-rs?svg=true)](https://ci.appveyor.com/project/sbwtw/ss-rs)
Shadowsocks client implements in Rust.

## Usage
`ss-rs` is using `toml` as configuration file:
```
ss-rs -c config.toml
```
The templates of config file can be found in: [example_config.toml](example_config.toml).

Multiple servers is supported and will be pick according to network quality.
```
# Local bind address
bind_addr = "localhost:1080"

# Server 1 settings
[[server]]
password = "your_server_pass"
server_addr = "example.com:2000"
encrypt_method = "chacha20-ietf-poly1305"

# Server 2 settings
[[server]]
password = "your_server_pass"
server_addr = "example.com:2001"
encrypt_method = "aes-256-cfb"
```

## Build
build with cargo
```
cargo build --release
```

## Supported Ciphers
### AEAD Ciphers
- `chacha20-ietf-poly1305` Provide by [ring](https://github.com/briansmith/ring)
### Stream Ciphers
- `aes-256-cfb` Provide by [rust-openssl](https://github.com/sfackler/rust-openssl)

## LICENSE
This project is licensed under the [MIT](LICENSE) license.
