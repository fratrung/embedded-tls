use core::marker::PhantomData;

use crate::TlsError;
use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::handshake::certificate::{CertificateEntryRef, CertificateRef};
pub use crate::handshake::certificate_verify::CertificateVerifyRef;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use ecdsa::elliptic_curve::SecretKey;
use generic_array::ArrayLength;
use heapless::Vec;
use p256::ecdsa::SigningKey;
use rand_core::CryptoRngCore;
pub use sha2::Sha256;

pub use sha2::Sha384;
use typenum::{Sum, U10, U12, U16, U32};

pub use crate::extensions::extension_data::max_fragment_length::MaxFragmentLength;

pub const TLS_RECORD_OVERHEAD: usize = 128;

// longest label is 12b -> buf <= 2 + 1 + 6 + longest + 1 + hash_out = hash_out + 22
type LongestLabel = U12;
type LabelOverhead = U10;
type LabelBuffer<CipherSuite> = Sum<
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize,
    Sum<LongestLabel, LabelOverhead>,
>;

/// Represents a TLS 1.3 cipher suite
pub trait TlsCipherSuite {
    const CODE_POINT: u16;
    type Cipher: KeyInit<KeySize = Self::KeyLen> + AeadInPlace<NonceSize = Self::IvLen>;
    type KeyLen: ArrayLength<u8>;
    type IvLen: ArrayLength<u8>;

    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
    type LabelBufferSize: ArrayLength<u8>;
}

pub struct Aes128GcmSha256;
impl TlsCipherSuite for Aes128GcmSha256 {
    const CODE_POINT: u16 = CipherSuite::TlsAes128GcmSha256 as u16;
    type Cipher = Aes128Gcm;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = Sha256;
    type LabelBufferSize = LabelBuffer<Self>;
}

pub struct Aes256GcmSha384;
impl TlsCipherSuite for Aes256GcmSha384 {
    const CODE_POINT: u16 = CipherSuite::TlsAes256GcmSha384 as u16;
    type Cipher = Aes256Gcm;
    type KeyLen = U32;
    type IvLen = U12;

    type Hash = Sha384;
    type LabelBufferSize = LabelBuffer<Self>;
}

/// A TLS 1.3 verifier.
///
/// The verifier is responsible for verifying certificates and signatures. Since certificate verification is
/// an expensive process, this trait allows clients to choose how much verification should take place,
/// and also to skip the verification if the server is verified through other means (I.e. a pre-shared key).
pub trait TlsVerifier<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    /// Host verification is enabled by passing a server hostname.
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), crate::TlsError>;

    /// Verify a certificate.
    ///
    /// The handshake transcript up to this point and the server certificate is provided
    /// for the implementation
    /// to use.
    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        ca: &Option<Certificate>,
        cert: CertificateRef,
    ) -> Result<(), TlsError>;

    /// Verify the certificate signature.
    ///
    /// The signature verification uses the transcript and certificate provided earlier to decode the provided signature.
    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), crate::TlsError>;
}

pub struct NoVerify;

impl<CipherSuite> TlsVerifier<CipherSuite> for NoVerify
where
    CipherSuite: TlsCipherSuite,
{
    fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), crate::TlsError> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        _transcript: &CipherSuite::Hash,
        _ca: &Option<Certificate>,
        _cert: CertificateRef,
    ) -> Result<(), TlsError> {
        Ok(())
    }

    fn verify_signature(&mut self, _verify: CertificateVerifyRef) -> Result<(), crate::TlsError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "TlsConfig does nothing unless consumed"]
pub struct TlsConfig<'a> {
    pub(crate) server_name: Option<&'a str>,
    pub(crate) psk: Option<(&'a [u8], Vec<&'a [u8], 4>)>,
    pub(crate) signature_schemes: Vec<SignatureScheme, 19>,
    pub(crate) named_groups: Vec<NamedGroup, 16>,
    pub(crate) max_fragment_length: Option<MaxFragmentLength>,
    pub(crate) ca: Option<Certificate<'a>>,
    pub(crate) cert: Option<Certificate<'a>>,
    pub(crate) priv_key: &'a [u8],
}

pub trait TlsClock {
    fn now() -> Option<u64>;
}

pub struct NoClock;

impl TlsClock for NoClock {
    fn now() -> Option<u64> {
        None
    }
}

pub trait CryptoProvider {
    type CipherSuite: TlsCipherSuite;
    type Signature: AsRef<[u8]>;

    fn rng(&mut self) -> impl CryptoRngCore;

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, crate::TlsError> {
        Err::<&mut NoVerify, _>(crate::TlsError::Unimplemented)
    }

    /// Decode and validate a private signing key from `key_der`.
    fn signer(
        &mut self,
        _key_der: &[u8],
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), crate::TlsError>
    {
        Err::<(NoSign, _), crate::TlsError>(crate::TlsError::Unimplemented)
    }
}

impl<T: CryptoProvider> CryptoProvider for &mut T {
    type CipherSuite = T::CipherSuite;

    type Signature = T::Signature;

    fn rng(&mut self) -> impl CryptoRngCore {
        T::rng(self)
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, crate::TlsError> {
        T::verifier(self)
    }

    fn signer(
        &mut self,
        key_der: &[u8],
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), crate::TlsError>
    {
        T::signer(self, key_der)
    }
}

pub struct NoSign;

impl<S> signature::Signer<S> for NoSign {
    fn try_sign(&self, _msg: &[u8]) -> Result<S, signature::Error> {
        unimplemented!()
    }
}

pub struct UnsecureProvider<CipherSuite, RNG> {
    rng: RNG,
    _marker: PhantomData<CipherSuite>,
}

impl<RNG: CryptoRngCore> UnsecureProvider<(), RNG> {
    pub fn new<CipherSuite: TlsCipherSuite>(rng: RNG) -> UnsecureProvider<CipherSuite, RNG> {
        UnsecureProvider {
            rng,
            _marker: PhantomData,
        }
    }
}

impl<CipherSuite: TlsCipherSuite, RNG: CryptoRngCore> CryptoProvider
    for UnsecureProvider<CipherSuite, RNG>
{
    type CipherSuite = CipherSuite;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn signer(
        &mut self,
        key_der: &[u8],
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), crate::TlsError>
    {
        let secret_key =
            SecretKey::from_sec1_der(key_der).map_err(|_| TlsError::InvalidPrivateKey)?;

        Ok((
            SigningKey::from(&secret_key),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ))
    }
}


// Ed25519 Provider 
use ed25519::Signature as Ed25519RawSignature;
use signature::{Signer, SignerMut};

use ed25519_dalek::{
    SigningKey as DalekSigningKey,
    pkcs8::DecodePrivateKey, 
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519Sig([u8; 64]);

impl From<Ed25519RawSignature> for Ed25519Sig {
    fn from(s: Ed25519RawSignature) -> Self {
        Ed25519Sig(s.to_bytes())
    }
}

impl AsRef<[u8]> for Ed25519Sig {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

struct DalekSigner(DalekSigningKey);

impl Signer<Ed25519Sig> for DalekSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Sig, signature::Error> {
        Ok(Ed25519Sig::from(self.0.sign(msg)))
    }
}
pub struct Ed25519Provider<CipherSuite, RNG> {
    rng: RNG,
    verifier: Ed25519Verifier,
    _marker: PhantomData<CipherSuite>,
}

impl<RNG: CryptoRngCore> Ed25519Provider<(), RNG> {
    pub fn new<CipherSuite: TlsCipherSuite>(rng: RNG) -> Ed25519Provider<CipherSuite, RNG> {
        Ed25519Provider {
            rng,
            verifier: Ed25519Verifier::new(),
            _marker: PhantomData,
        }
    }
}

impl<CipherSuite: TlsCipherSuite, RNG: CryptoRngCore> CryptoProvider
    for Ed25519Provider<CipherSuite, RNG>
{
    type CipherSuite = CipherSuite;
    type Signature = Ed25519Sig;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, crate::TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(
        &mut self,
        key_der_or_seed: &[u8],
    ) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        let sk = DalekSigningKey::from_pkcs8_der(key_der_or_seed)
            .map_err(|_| TlsError::InvalidPrivateKey)?;

        Ok((DalekSigner(sk), SignatureScheme::Ed25519))
    }
}
// Ed25519 TlsVerifier
use x509_cert::der::{Decode,Encode};
use x509_cert::Certificate as X509Cert;
use ed25519_dalek::{VerifyingKey, Signature as DalekSignature};
use signature::Verifier;

pub struct Ed25519Verifier{
    ca_vk: Option<VerifyingKey>,
    server_vk: Option<VerifyingKey>,
    transcript_hash: Option<heapless::Vec<u8, 64>>,
}
impl Ed25519Verifier {

    pub fn new() -> Self {
        Self { ca_vk: None, server_vk: None, transcript_hash: None }
    }

    pub fn ed25519_vk_from_cert(cert_der: &[u8]) -> Result<VerifyingKey, ()> {
        let cert = X509Cert::from_der(cert_der)
            .map_err(|_| ())?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let oid_ed25519 = spki::ObjectIdentifier::new_unwrap("1.3.101.112");
        if spki.algorithm.oid != oid_ed25519 {
            return Err(());
        }

        let pk_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(())?;
        if pk_bytes.len() != 32 {
            return Err(());
        }
        VerifyingKey::from_bytes(
            pk_bytes
            .try_into()
            .map_err(|_| ())?)
            .map_err(|_| ()
        )
    }

    pub fn tbs_and_signature_from_cert_der(
        cert_der: &[u8],
    ) -> Result<(Vec<u8, 1024>, [u8; 64]), ()> {
        let cert = X509Cert::from_der(cert_der).map_err(|_| ())?;

        let mut tmp = [0u8; 1024];
        let slice: &[u8] = cert
            .tbs_certificate
            .encode_to_slice(&mut tmp) 
            .map_err(|_| ())?;

        let mut tbs_der: Vec<u8, 1024> = Vec::new();
        tbs_der.extend_from_slice(slice).map_err(|_| ())?;

        let sig_bytes = cert.signature.as_bytes().ok_or(())?;
        if sig_bytes.len() != 64 {
            return Err(());
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(sig_bytes);

        Ok((tbs_der, sig))
        }
}

impl<CipherSuite> TlsVerifier<CipherSuite> for Ed25519Verifier
where
    CipherSuite: TlsCipherSuite,
{
    fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), crate::TlsError> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        ca: &Option<Certificate>,
        cert: CertificateRef,
    ) -> Result<(), TlsError> {

        let ca_vk: VerifyingKey = match ca {
            Some(Certificate::X509(der)) => {
                Ed25519Verifier::ed25519_vk_from_cert(*der).map_err(|_| TlsError::InvalidCertificate)?
            }
            Some(Certificate::RawPublicKey(pk)) => {
                if pk.len() != 32 {
                    return Err(TlsError::InvalidCertificate);
                }
                let arr: [u8; 32] = pk.as_ref()
                    .try_into()
                    .map_err(|_| TlsError::InvalidCertificate)?;
                VerifyingKey::from_bytes(&arr).map_err(|_| TlsError::InvalidCertificate)?
            }
            None => return Err(TlsError::InvalidCertificate),
        };
        
        let leaf_der = match cert.entries.first() {
            Some(CertificateEntryRef::X509(der)) => *der,
            _ => return Err(TlsError::InvalidCertificateEntry)
        };
        let (tbs_der, sig_bytes) = Ed25519Verifier::tbs_and_signature_from_cert_der(leaf_der)
            .map_err(|_| TlsError::InvalidCertificate)?;

        let sig = DalekSignature::from(&sig_bytes);
        ca_vk.verify(tbs_der.as_slice(), &sig)
            .map_err(|_| TlsError::InvalidCertificate)?;

        let digest_out = transcript.clone().finalize_fixed();
        let thash_bytes = digest_out.as_slice();
        let mut thash_vec: Vec<u8, 64> = Vec::new();
        thash_vec.extend_from_slice(thash_bytes)
            .map_err(|_| TlsError::OutOfMemory)?;
        let server_vk = Ed25519Verifier::ed25519_vk_from_cert(leaf_der)
            .map_err(|_| TlsError::InvalidCertificate)?;

        self.transcript_hash = Some(thash_vec);
        self.server_vk = Some(server_vk);
        self.ca_vk = Some(ca_vk);


        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), crate::TlsError> {
        if verify.signature_scheme != SignatureScheme::Ed25519{
            return Err(TlsError::InvalidSignatureScheme);
        }
        let server_vk = self.
            server_vk
            .as_ref()
            .ok_or(TlsError::InvalidCertificate)?;
        let thash = self
            .transcript_hash
            .as_ref()
            .ok_or(TlsError::InvalidCertificate)?;

        let mut msg : heapless::Vec<u8, 160> = heapless::Vec::new();
        msg.extend_from_slice(&[0x20; 64])
            .map_err(|_| TlsError::EncodeError)?;
        msg.extend_from_slice(b"TLS 1.3, server CertificateVerify")
            .map_err(|_| TlsError::EncodeError)?;
        msg.push(0x00).map_err(|_| TlsError::EncodeError)?;
        msg.extend_from_slice(thash.as_slice())
            .map_err(|_| TlsError::EncodeError)?;

        if verify.signature.len() != 64 {
            return Err(TlsError::InvalidRecord);
        }
        let sig = DalekSignature::from_bytes(
            verify.signature.try_into().map_err(|_| TlsError::InvalidRecord)?
        );

        server_vk
            .verify(msg.as_slice(), &sig)
            .map_err(|_| TlsError::EncodeError)?;
        
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    pub(crate) config: &'a TlsConfig<'a>,
    pub(crate) crypto_provider: Provider,
}

impl<'a, Provider> TlsContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    /// Create a new context with a given config and a crypto provider.
    pub fn new(config: &'a TlsConfig<'a>, crypto_provider: Provider) -> Self {
        Self {
            config,
            crypto_provider,
        }
    }
}

impl<'a> TlsConfig<'a> {
    pub fn new() -> Self {
        let mut config = Self {
            signature_schemes: Vec::new(),
            named_groups: Vec::new(),
            max_fragment_length: None,
            psk: None,
            server_name: None,
            ca: None,
            cert: None,
            priv_key: &[],
        };

        if cfg!(feature = "alloc") {
            config = config.enable_rsa_signatures();
        }

        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp256r1Sha256)
                .ok()
        );
        unwrap!(
            config
                .signature_schemes
                .push(SignatureScheme::EcdsaSecp384r1Sha384)
                .ok()
        );
        unwrap!(config.signature_schemes.push(SignatureScheme::Ed25519).ok());

        unwrap!(config.named_groups.push(NamedGroup::Secp256r1));

        config
    }

    /// Enable RSA ciphers even if they might not be supported.
    pub fn enable_rsa_signatures(mut self) -> Self {
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha256)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha384)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha512)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha256)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha384)
                .ok()
        );
        unwrap!(
            self.signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha512)
                .ok()
        );
        self
    }

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Configures the maximum plaintext fragment size.
    ///
    /// This option may help reduce memory size, as smaller fragment lengths require smaller
    /// read/write buffers. Note that embedded-tls does not currently use this option to fragment
    /// writes. Note that the buffers need to include some overhead over the configured fragment
    /// length.
    ///
    /// From [RFC 6066, Section 4.  Maximum Fragment Length Negotiation](https://www.rfc-editor.org/rfc/rfc6066#page-8):
    ///
    /// > Without this extension, TLS specifies a fixed maximum plaintext
    /// > fragment length of 2^14 bytes.  It may be desirable for constrained
    /// > clients to negotiate a smaller maximum fragment length due to memory
    /// > limitations or bandwidth limitations.
    ///
    /// > For example, if the negotiated length is 2^9=512, then, when using currently defined
    /// > cipher suites ([...]) and null compression, the record-layer output can be at most
    /// > 805 bytes: 5 bytes of headers, 512 bytes of application data, 256 bytes of padding,
    /// > and 32 bytes of MAC.
    pub fn with_max_fragment_length(mut self, max_fragment_length: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(max_fragment_length);
        self
    }

    /// Resets the max fragment length to 14 bits (16384).
    pub fn reset_max_fragment_length(mut self) -> Self {
        self.max_fragment_length = None;
        self
    }

    pub fn with_ca(mut self, ca: Certificate<'a>) -> Self {
        self.ca = Some(ca);
        self
    }

    pub fn with_cert(mut self, cert: Certificate<'a>) -> Self {
        self.cert = Some(cert);
        self
    }

    pub fn with_priv_key(mut self, priv_key: &'a [u8]) -> Self {
        self.priv_key = priv_key;
        self
    }

    pub fn with_psk(mut self, psk: &'a [u8], identities: &[&'a [u8]]) -> Self {
        // TODO: Remove potential panic
        self.psk = Some((psk, unwrap!(Vec::from_slice(identities).ok())));
        self
    }
}

impl Default for TlsConfig<'_> {
    fn default() -> Self {
        TlsConfig::new()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Certificate<'a> {
    X509(&'a [u8]),
    RawPublicKey(&'a [u8]),
}
