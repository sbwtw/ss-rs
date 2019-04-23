# ss-rs
Shadowsocks client implements in Rust.

# Usage
```
ss-rs --pwd "password" --svr "10.0.0.1:1080" --listen "[::]:1090" --cipher "chacha20-ietf-poly1305"
```

# Supported Ciphers
### AEAD Ciphers
`chacha20-ietf-poly1305`

# LICENSE
This project is licensed under the [MIT](LICENSE) license.
