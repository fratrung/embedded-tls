
## Ed25519 Support for Embedded-TLS

[![CI](https://github.com/drogue-iot/embedded-tls/actions/workflows/ci.yaml/badge.svg)](https://github.com/drogue-iot/embedded-tls/actions/workflows/ci.yaml)
[![crates.io](https://img.shields.io/crates/v/embedded-tls.svg)](https://crates.io/crates/embedded-tls)
[![docs.rs](https://docs.rs/embedded-tls/badge.svg)](https://docs.rs/embedded-tls)
[![Matrix](https://img.shields.io/matrix/drogue-iot:matrix.org)](https://matrix.to/#/#drogue-iot:matrix.org)

This fork extends [`embedded-tls`](https://github.com/drogue-iot/embedded-tls) by adding support for **Ed25519** signatures in TLS 1.3.  
It introduces a new **`Ed25519Provider`** and a custom **`Ed25519Verifier`** that handle certificate parsing, verification, and signature generation in **`no_std` embedded environments**.

Embedded-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The Rust crate was formerly known as `drogue-tls`. The
implementation is work in progress, but the [example clients](https://github.com/drogue-iot/embedded-tls/tree/main/examples) should work against the [rustls](https://github.com/ctz/rustls) echo server.

The client supports both async and blocking modes. By default, the `std` feature is enabled, but can be disabled for bare metal usage.

To use the async mode, import `embedded_tls::*`. To use the blocking mode, import `embedded_tls::blocking::*`.

Some features and extensions are not yet implemented, have a look at [open issues](https://github.com/drogue-iot/embedded-tls/issues).

Only supports writing/receiving one frame at a time, hence using a frame buffer larger than 16k is not currently needed.  You may use a lower frame buffer size, but there is no guarantee that it will be able to parse any TLS 1.3 frame.

## Community

* [Drogue IoT Matrix Chat Room](https://matrix.to/#/#drogue-iot:matrix.org)
* We have bi-weekly calls at 9:00 AM (GMT). [Check the calendar](https://calendar.google.com/calendar/u/0/embed?src=ofuctjec399jr6kara7n0uidqg@group.calendar.google.com&pli=1) to see which week we are having the next call, and feel free to join!
* [Drogue IoT Forum](https://discourse.drogue.io/)
* [Drogue IoT YouTube channel](https://www.youtube.com/channel/UC7GZUy2hKidvY6V_3QZfCcA)
* [Follow us on Twitter!](https://twitter.com/DrogueIoT)

---

## Motivation

Ed25519 is a modern elliptic-curve signature scheme widely adopted for IoT, embedded, and constrained devices thanks to its:

- Small key size (32-byte public keys, 64-byte signatures) 
- High performance and low memory footprint 
- Strong security properties 

This makes it a natural fit for embedded TLS deployments where efficiency and security are critical.

---

## What was added

### Ed25519 Provider
Implements the `CryptoProvider` trait to enable client-side signing with Ed25519 private keys:

- Loads keys from **PKCS#8 DER** format
- Provides a `DalekSigner` wrapper around [`ed25519-dalek`](https://docs.rs/ed25519-dalek) 
- Exposes `SignatureScheme::Ed25519` to the TLS handshake 
- Built on top of the [**RustCrypto**](https://github.com/RustCrypto) ecosystem, ensuring a portable and **`no_std`-compatible** implementation 

### Ed25519 Verifier
Implements the `TlsVerifier` trait to verify server certificates and signatures:

- Parses X.509 Ed25519 certificates (`1.3.101.112` OID) 
- Validates the certificate chain against a CA 
- Computes and stores the TLS transcript hash 
- Verifies the `CertificateVerify` handshake message according to [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3) 

---

## Example usage

```rust
use embedded_tls::{TlsConfig, Ed25519Provider, Certificate, TlsContext};
use rand_core::OsRng;
use embedded_tls::cipher_suites::Aes128GcmSha256;

// Load certificates and keys (DER format)
let ca_cert: &[u8] = include_bytes!("ca.der");
let client_cert: &[u8] = include_bytes!("client.der");
let client_key: &[u8] = include_bytes!("client-key.der");

// Create TLS config
let config = TlsConfig::new()
    .with_ca(Certificate::X509(ca_cert))
    .with_cert(Certificate::X509(client_cert))
    .with_priv_key(client_key);

// Use Ed25519 provider with AES128-GCM-SHA256
let provider = Ed25519Provider::new::<Aes128GcmSha256>(OsRng);

// Create TLS context
let mut ctx = TlsContext::new(&config, provider);

```

## ✅ Status

- [x] Handshake with Ed25519 server certificates 
- [x] Certificate verification (CA + server leaf) 
- [x] CertificateVerify message verification 
- [x] Client authentication with Ed25519 private keys 
- [x] Fully `no_std` compatible thanks to **RustCrypto crates** 

---

## ⚠️ Limitations

This fork adds Ed25519 support, but it also inherits the general limitations of `embedded-tls` and introduces some specific constraints:

- **TLS 1.3 only** – no support for TLS 1.2 or earlier versions.  
- **Certificate chain** – currently only validates a single CA certificate against the server leaf. Full certificate chain verification (intermediate CAs, CRLs, OCSP) is **not implemented**.  
- **Ed25519 only** – no support for other signature algorithms (RSA, ECDSA, etc.).  
- **Transcript hash** – fixed to SHA-256 through the chosen cipher suite (`Aes128GcmSha256`). Other hash algorithms (e.g. SHA-384) are not supported.  
- **Single-frame processing** – only one TLS frame can be written or received at a time; large frames >16KB are not guaranteed to work.  
- **Heapless buffers** – buffer sizes for certificate parsing and transcript storage are statically limited (`heapless::Vec`). Very large certificates or unusual encodings may fail.  
- **Experimental** – this fork is tested against controlled environments (e.g. Rustls server with Ed25519 certs). Interoperability with a wide range of TLS servers has not been validated.  
- **Resource usage** – Ed25519 verification (`ed25519-dalek`) can be relatively heavy on small MCUs (RAM/stack/time). Benchmarks on your target hardware are recommended.  

---

## ⚠️ Notes

- This implementation is **experimental** and designed for **resource-constrained devices**.  
- Relies on [`ed25519-dalek`](https://docs.rs/ed25519-dalek) and the [RustCrypto](https://github.com/RustCrypto) suite for hashing and cryptography.  
<<<<<<< HEAD
=======

>>>>>>> 576e8c2a0f206f8c33f656ea6e5ab89bcdd3fe63
---
