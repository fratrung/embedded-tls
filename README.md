
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

Ed25519 is widely used in IoT and constrained devices because of its:

- Small key size (32-byte public keys, 64-byte signatures) 
- High performance and low memory footprint 
- Strong security guarantees   

This makes it a natural fit for embedded TLS deployments where efficiency and security are critical.

---

## What was added

### Ed25519 Provider
Implements the `CryptoProvider` trait to enable client-side signing with Ed25519 private keys:

- Loads keys from **PKCS#8 DER** format
- Wraps [`ed25519-dalek`](https://docs.rs/ed25519-dalek) with a safe API (`DalekSigner`)
- Fully **`no_std` compatible** thanks to the [RustCrypto](https://github.com/RustCrypto) ecosystem

### Ed25519 Verifier
The verification logic is fully encapsulated inside the `Ed25519Provider`.  
Internally, the provider embeds an `Ed25519Verifier` which implements the `TlsVerifier` trait, so the user never has to instantiate or interact with it directly.  

This integration allows `Ed25519Provider` to transparently handle:

- Parsing of X.509 Ed25519 certificates (`1.3.101.112` OID)  
- Validation of the server certificate against the trusted CA  
- Transcript hash computation and storage  
- Verification of the `CertificateVerify` handshake message (RFC 8446, TLS 1.3)  

In practice, configuring the `Ed25519Provider` is enough. Certificate parsing and signature verification are performed automatically during the TLS handshake.

---

## Example usage (ESP32-C3)

```rust

use esp_hal::rng::Rng;
use rand_core::{RngCore, CryptoRng};

use embedded_tls::{TlsConfig, Ed25519Provider, Certificate, TlsContext};
use embedded_tls::cipher_suites::Aes128GcmSha256;



// -----------------------------------------------------------------------------
// Esp32-C3 RNG Wrapper
// -----------------------------------------------------------------------------
// embedded-tls is designed for `no_std` environments and requires an RNG that
// implements the `RngCore` and `CryptoRng` traits.
// The ESP32 hardware RNG (`esp-hal::rng::Rng`) does not directly implement them,
// therefore a wrapper is created to provide the required traits.
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct Esp32c3RngWrapper(Rng);

impl From<Rng> for Esp32c3RngWrapper {
    fn from(rng: Rng) -> Self {
        Self(rng)
    }
}

impl RngCore for Esp32c3RngWrapper {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }

    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(4) {
            let bytes = self.next_u32().to_le_bytes();
            let (head, _) = bytes.split_at(chunk.len());
            chunk.copy_from_slice(head);
        }
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Esp32c3RngWrapper {}

// ESP32 peripherals and the hardware RNG are initialized.
let peripherals = esp_hal::init(
        esp_hal::Config::default().with_cpu_clock(CpuClock::max()),
    );
let rng = Rng::new(peripherals.RNG);
let mut hal_rng = Esp32c3RngWrapper::from(rng);

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
let provider = Ed25519Provider::new::<Aes128GcmSha256>(&mut hal_rng);

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

## 🧪 Validation and Testing

The implementation has been validated on real hardware using an **ESP32-C3** target.  
Dedicated firmware and client code are available in a separate repository, each with its own README that explains how the client was built, integrated, and tested:

- [ESP32-C3 Firmware (README)](https://github.com/wasmbed/wasmbed/blob/valeriot30%2Bfratrung/firmware-esp32c3/crates/wasmbed-firmware-esp32c3/README.md)  
- [bare-metal #[no_std] TLS Client (README)](https://github.com/wasmbed/wasmbed/blob/valeriot30%2Bfratrung/firmware-esp32c3/crates/wasmbed-protocol-client/README.md)  

These resources complement the library by providing a concrete usage scenario, including compilation, flashing, and runtime testing of the TLS client with **Ed25519 support**.

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

