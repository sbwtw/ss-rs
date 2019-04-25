# ss-rs
Shadowsocks client implements in Rust.

## Usage
```
ss-rs --pwd "password" --svr "10.0.0.1:1080" --listen "[::]:1090" --cipher "chacha20-ietf-poly1305"
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
