//! The interfaces a [`CmsEnvironment`](crate::CmsEnvironment) takes implementations of: one per
//! plug point, the implementations of each kind offered a request in the order registered, and the
//! first that does not return [`Error::Unrecognized`](crate::Error::Unrecognized) answering. A
//! provider implements these, and certval's own `PkiEnvironment` traits for hashing and signature
//! verification. A blanket implementation covers every function with a matching signature for the
//! per-algorithm traits, so a bare function can be registered; a type holding state, such as a
//! handle to a hardware module, implements the trait.

use alloc::{sync::Arc, vec::Vec};

use cms::{enveloped_data::RecipientIdentifier, signed_data::SignerIdentifier};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{name::Name, Certificate};
use zeroize::Zeroizing;

use crate::algorithms::{
    ContentEncryptionAlgorithm, KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm,
};
use crate::credential::{contains_email_address, recipient_matches, subject_matches};
use crate::environment::CmsEnvironment;
use crate::error::{Error, Result};
use crate::signed::{signer_matches, DigestAlgorithm};

// ---- Content encryption and decryption

/// The output of content encryption.
pub struct ContentEncryptionOutput {
    /// The ciphertext, without the authentication tag.
    pub ciphertext: Vec<u8>,
    /// The content-encryption key, for the recipients to wrap.
    pub key: Zeroizing<Vec<u8>>,
    /// The algorithm identifier, with the IV (CBC) or `GCMParameters` (GCM) as parameters.
    pub algorithm: AlgorithmIdentifierOwned,
    /// The authentication tag, present for an authenticated algorithm.
    pub tag: Option<Vec<u8>>,
}

/// Content encryption performed by a cryptographic implementation, registered on a
/// [`CmsEnvironment`] with [`CmsEnvironment::add_encrypt_content_callback`].
///
/// An implementation returns [`Error::Unrecognized`] for an algorithm it does not perform, so that
/// the environment passes the request to the next one registered.
///
/// A blanket implementation covers every function with a matching signature, so a bare function
/// (like [`encrypt_content_rust_crypto`](crate::encrypt_content_rust_crypto)) can be registered directly. Implement the trait on a type
/// when the implementation needs to hold state that a function pointer cannot, e.g. a handle to a
/// hardware module.
pub trait EncryptContent {
    /// Generates a key for `alg`, and an IV or nonce, and encrypts `plaintext`. `aad` is the
    /// additional, authenticated data for an authenticated algorithm, and must be `None` otherwise.
    fn encrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput>;
}

impl<F> EncryptContent for F
where
    F: Fn(
        &CmsEnvironment,
        ContentEncryptionAlgorithm,
        &[u8],
        Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput>,
{
    fn encrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        self(env, alg, plaintext, aad)
    }
}

impl<T: EncryptContent + ?Sized> EncryptContent for Arc<T> {
    fn encrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        (**self).encrypt_content(env, alg, plaintext, aad)
    }
}

/// Content decryption performed by a cryptographic implementation, registered on a
/// [`CmsEnvironment`] with [`CmsEnvironment::add_decrypt_content_callback`]. The counterpart of
/// [`EncryptContent`].
///
/// An implementation returns [`Error::Unrecognized`] for an algorithm it does not perform. A
/// blanket implementation covers every function with a matching signature.
pub trait DecryptContent {
    /// Decrypts `ciphertext` with `key` under `alg`, the encryptedContentInfo's
    /// contentEncryptionAlgorithm, whose parameters carry the IV (CBC) or `GCMParameters` (GCM).
    /// For an authenticated algorithm, `aad` is the additional authenticated data and `tag` the
    /// authentication tag; both are `None` otherwise.
    fn decrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

impl<F> DecryptContent for F
where
    F: Fn(
        &CmsEnvironment,
        &AlgorithmIdentifierOwned,
        &[u8],
        &[u8],
        Option<&[u8]>,
        Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>>,
{
    fn decrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self(env, alg, key, ciphertext, aad, tag)
    }
}

impl<T: DecryptContent + ?Sized> DecryptContent for Arc<T> {
    fn decrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        (**self).decrypt_content(env, alg, key, ciphertext, aad, tag)
    }
}

// ---- Recipient key management

/// Key transport performed by a cryptographic implementation, registered with
/// [`CmsEnvironment::add_encrypt_key_transport_callback`].
///
/// An implementation returns [`Error::Unrecognized`] for an algorithm or key it does not handle.
/// A blanket implementation covers every function with a matching signature.
pub trait EncryptKeyTransport {
    /// Encrypts `cek` to the RSA key in `spki` with `alg`, returning the encryptedKey.
    fn encrypt_key_transport(
        &self,
        env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>>;
}

impl<F> EncryptKeyTransport for F
where
    F: Fn(
        &CmsEnvironment,
        KeyTransportAlgorithm,
        &SubjectPublicKeyInfoOwned,
        &[u8],
    ) -> Result<Vec<u8>>,
{
    fn encrypt_key_transport(
        &self,
        env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>> {
        self(env, alg, spki, cek)
    }
}

/// The output of key agreement for one recipient.
pub struct KeyAgreeOutput {
    /// The originator's ephemeral public key, an uncompressed SEC1 point.
    pub ephemeral_public_key: Vec<u8>,
    /// The content-encryption key, wrapped under the derived key-encryption key.
    pub encrypted_key: Vec<u8>,
}

/// Key agreement performed by a cryptographic implementation, registered with
/// [`CmsEnvironment::add_encrypt_key_agreement_callback`]: an ephemeral key pair on the recipient's
/// curve, ECDH, the X9.63 KDF over the `ECC-CMS-SharedInfo` (RFC 5753, section 7.2), and the key
/// wrap.
///
/// An implementation returns [`Error::Unrecognized`] for an algorithm or curve it does not handle.
/// A blanket implementation covers every function with a matching signature.
pub trait EncryptKeyAgreement {
    /// Wraps `cek` for the EC key in `spki`. `ukm` is the user keying material, if any, which is
    /// the entityUInfo of the shared info.
    fn encrypt_key_agreement(
        &self,
        env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput>;
}

impl<F> EncryptKeyAgreement for F
where
    F: Fn(
        &CmsEnvironment,
        KeyAgreementAlgorithm,
        KeyWrapAlgorithm,
        &SubjectPublicKeyInfoOwned,
        Option<&[u8]>,
        &[u8],
    ) -> Result<KeyAgreeOutput>,
{
    fn encrypt_key_agreement(
        &self,
        env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput> {
        self(env, alg, wrap, spki, ukm, cek)
    }
}

/// The output of a KEM for one recipient.
pub struct KemOutput {
    /// The KEM ciphertext.
    pub kem_ct: Vec<u8>,
    /// The content-encryption key, wrapped under the derived key-encryption key.
    pub encrypted_key: Vec<u8>,
}

/// A KEM performed by a cryptographic implementation, registered with
/// [`CmsEnvironment::add_encrypt_kem_callback`]: encapsulation to the recipient's key, the KDF over
/// the `CMSORIforKEMOtherInfo` (RFC 9629, section 5), and the key wrap. The KEM is the one the key in
/// `spki` is for.
///
/// An implementation returns [`Error::Unrecognized`] for a KEM, KDF or wrap it does not handle. A
/// blanket implementation covers every function with a matching signature.
pub trait EncryptKem {
    /// Wraps `cek` for the KEM key in `spki`.
    fn encrypt_kem(
        &self,
        env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput>;
}

impl<F> EncryptKem for F
where
    F: Fn(
        &CmsEnvironment,
        KdfAlgorithm,
        KeyWrapAlgorithm,
        &SubjectPublicKeyInfoOwned,
        Option<&[u8]>,
        &[u8],
    ) -> Result<KemOutput>,
{
    fn encrypt_kem(
        &self,
        env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput> {
        self(env, kdf, wrap, spki, ukm, cek)
    }
}

// ---- Recipient credentials

/// A recipient's private key, which performs a recipient type's whole operation and returns the
/// content-encryption key.
///
/// Each method defaults to [`Error::Unrecognized`], so a credential implements only what its key
/// supports: an RSA key, key transport; an EC key, key agreement; a KEM key, the KEM. A key holder
/// that performs only part of an operation composes with the helpers for the rest:
/// [`unpad_pkcs1v15`](crate::unpad_pkcs1v15) after a raw RSA decryption,
/// [`cek_from_ecdh_secret`](crate::cek_from_ecdh_secret) after an ECDH that returns the shared
/// secret, and [`cek_from_kem_secret`](crate::cek_from_kem_secret) after a decapsulation.
pub trait RecipientCredential {
    /// The certificate for the key, which recipient identifiers are matched against.
    fn certificate(&self) -> &Certificate;

    /// Decrypts a KeyTransRecipientInfo's encryptedKey.
    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        _alg: KeyTransportAlgorithm,
        _encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unrecognized)
    }

    /// Recovers a KeyAgreeRecipientInfo's content-encryption key: ECDH with the originator's
    /// ephemeral key, the X9.63 KDF over the `ECC-CMS-SharedInfo` (with `ukm` as its entityUInfo),
    /// and AES key unwrap of `encrypted_key`.
    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        _alg: KeyAgreementAlgorithm,
        _wrap: KeyWrapAlgorithm,
        _originator: &SubjectPublicKeyInfoOwned,
        _ukm: Option<&[u8]>,
        _encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unrecognized)
    }

    /// Recovers a KEMRecipientInfo's content-encryption key: decapsulation of `kem_ct`, the KDF
    /// over the `CMSORIforKEMOtherInfo`, and AES key unwrap of `encrypted_key`. The KEM is the one
    /// the credential's key is for.
    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        _kdf: KdfAlgorithm,
        _wrap: KeyWrapAlgorithm,
        _kem_ct: &[u8],
        _ukm: Option<&[u8]>,
        _encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unrecognized)
    }
}

impl<T: RecipientCredential + ?Sized> RecipientCredential for Arc<T> {
    fn certificate(&self) -> &Certificate {
        (**self).certificate()
    }
    fn decrypt_key_transport(
        &self,
        env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        (**self).decrypt_key_transport(env, alg, encrypted_key)
    }
    fn decrypt_key_agreement(
        &self,
        env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        (**self).decrypt_key_agreement(env, alg, wrap, originator, ukm, encrypted_key)
    }
    fn decrypt_kem(
        &self,
        env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        (**self).decrypt_kem(env, kdf, wrap, kem_ct, ukm, encrypted_key)
    }
}

/// A shared recipient credential, as a source returns one.
pub type SharedRecipientCredential = Arc<dyn RecipientCredential + Send + Sync>;

/// A store of recipient keys, registered on a [`CmsEnvironment`] with
/// [`CmsEnvironment::add_recipient_credential_source`].
///
/// A key a KeyAgreeRecipientInfo names by `rKeyId` is looked up by that identifier's subject key
/// identifier.
pub trait RecipientCredentialSource {
    /// Returns the credential for the key `rid` names, or `None` if the store holds no such key.
    fn find_recipient_credential(
        &self,
        env: &CmsEnvironment,
        rid: &RecipientIdentifier,
    ) -> Result<Option<SharedRecipientCredential>>;
}

// ---- Signing keys

/// A private key that signs, known by its public key rather than a certificate: e.g. a key signing
/// its own certificate request, or a root's key signing its self-signed certificate. Every
/// [`SigningCredential`] is one, with its certificate's public key, by the implementation below, so
/// [`CredentialSigner`](crate::CredentialSigner) takes either. Each signing method defaults to
/// [`Error::Unrecognized`]; a key implements at least one.
pub trait SigningKey {
    /// The public key, as a certificate or certificate request carries it.
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned;

    /// The signature algorithm the key signs with when the signer does not set one. `None`, the
    /// default, leaves the choice to the key's algorithm.
    fn preferred_signature_algorithm(
        &self,
        _digest: DigestAlgorithm,
    ) -> Option<AlgorithmIdentifierOwned> {
        None
    }

    /// Signs `message` with `alg`, returning the signature value.
    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        _alg: &AlgorithmIdentifierOwned,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unrecognized)
    }

    /// Signs `digest`, computed with the signer's digest algorithm, with `alg`, returning the
    /// signature value.
    fn sign_digest(
        &self,
        _env: &CmsEnvironment,
        _alg: &AlgorithmIdentifierOwned,
        _digest: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unrecognized)
    }
}

impl<T: SigningCredential + ?Sized> SigningKey for T {
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        self.certificate()
            .tbs_certificate()
            .subject_public_key_info()
    }
    fn preferred_signature_algorithm(
        &self,
        digest: DigestAlgorithm,
    ) -> Option<AlgorithmIdentifierOwned> {
        SigningCredential::preferred_signature_algorithm(self, digest)
    }
    fn sign_message(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        SigningCredential::sign_message(self, env, alg, message)
    }
    fn sign_digest(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        SigningCredential::sign_digest(self, env, alg, digest)
    }
}

// ---- Signing credentials

/// A signer's private key, which signs either a message or a digest of it, whichever its key
/// holder does. Each method defaults to [`Error::Unrecognized`]; a credential implements at least
/// one. A pure ML-DSA signature is only ever over the message.
pub trait SigningCredential {
    /// The certificate for the key, which identifies the signer.
    fn certificate(&self) -> &Certificate;

    /// The signature algorithm the credential signs with when the signer does not set one, e.g.
    /// the one fixed by a key holder that signs in only one way. `None`, the default, leaves the
    /// choice to [`default_signature_algorithm`](crate::default_signature_algorithm).
    fn preferred_signature_algorithm(
        &self,
        _digest: DigestAlgorithm,
    ) -> Option<AlgorithmIdentifierOwned> {
        None
    }

    /// Signs `message` with `alg`, returning the signature value.
    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        _alg: &AlgorithmIdentifierOwned,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unrecognized)
    }

    /// Signs `digest`, computed with the signer's digest algorithm, with `alg`, returning the
    /// signature value.
    fn sign_digest(
        &self,
        _env: &CmsEnvironment,
        _alg: &AlgorithmIdentifierOwned,
        _digest: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::Unrecognized)
    }
}

impl<T: SigningCredential + ?Sized> SigningCredential for Arc<T> {
    fn certificate(&self) -> &Certificate {
        (**self).certificate()
    }
    fn preferred_signature_algorithm(
        &self,
        digest: DigestAlgorithm,
    ) -> Option<AlgorithmIdentifierOwned> {
        (**self).preferred_signature_algorithm(digest)
    }
    fn sign_message(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        (**self).sign_message(env, alg, message)
    }
    fn sign_digest(
        &self,
        env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        (**self).sign_digest(env, alg, digest)
    }
}

/// A shared signing credential, as a source returns one.
pub type SharedSigningCredential = Arc<dyn SigningCredential + Send + Sync>;

/// What identifies a signing key to a [`SigningCredentialSource`], by its certificate.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum SigningCredentialLookup<'a> {
    /// The issuer and serial number, or subject key identifier, of the certificate.
    Identifier(&'a SignerIdentifier),
    /// An email address the certificate contains, as a mail client chooses a signing key.
    EmailAddress(&'a str),
    /// The certificate's subject name.
    Subject(&'a Name),
}

impl SigningCredentialLookup<'_> {
    /// Whether this identifies `cert`.
    pub fn matches(&self, cert: &Certificate) -> bool {
        match self {
            SigningCredentialLookup::Identifier(sid) => signer_matches(sid, cert),
            SigningCredentialLookup::EmailAddress(email) => contains_email_address(cert, email),
            SigningCredentialLookup::Subject(subject) => subject_matches(subject, cert),
        }
    }
}

/// A store of signing keys, registered on a [`CmsEnvironment`] with
/// [`CmsEnvironment::add_signing_credential_source`].
pub trait SigningCredentialSource {
    /// The credential for every key `lookup` identifies, empty if the store holds none. An email
    /// address or subject can identify several, e.g. a person's signature and encryption keys, and
    /// [`CmsEnvironment::find_signing_credentials`] narrows them by key usage.
    fn find_signing_credentials(
        &self,
        env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>>;
}

// ---- Recipient certificates

/// What identifies a recipient's certificate to a [`RecipientCertificateSource`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum CertificateLookup<'a> {
    /// The issuer and serial number, or subject key identifier, a recipient identifier carries.
    Identifier(&'a RecipientIdentifier),
    /// An email address, as an S/MIME directory would be searched.
    EmailAddress(&'a str),
    /// A subject name.
    Subject(&'a Name),
}

impl CertificateLookup<'_> {
    /// Whether this identifies `cert`: by recipient identifier, an email address the certificate
    /// contains, or its subject name.
    pub fn matches(&self, cert: &Certificate) -> bool {
        match self {
            CertificateLookup::Identifier(rid) => recipient_matches(rid, cert),
            CertificateLookup::EmailAddress(email) => contains_email_address(cert, email),
            CertificateLookup::Subject(subject) => subject_matches(subject, cert),
        }
    }
}

/// A store of recipients' certificates, e.g. a certificate store, a key chain or a directory,
/// registered on a [`CmsEnvironment`] with [`CmsEnvironment::add_recipient_certificate_source`], so
/// that a message can be encrypted to someone whose certificate the caller does not hold.
pub trait RecipientCertificateSource {
    /// Every certificate `lookup` identifies, empty if the store holds none. An email address or
    /// subject can identify several, e.g. a person's signature and encryption certificates, and
    /// [`CmsEnvironment::find_recipient_certificates`] narrows them by key usage.
    fn find_recipient_certificates(
        &self,
        env: &CmsEnvironment,
        lookup: CertificateLookup<'_>,
    ) -> Result<Vec<Certificate>>;
}

// ---- Signer certificates

/// A store of signers' certificates, consulted after the message's own certificates, registered on
/// a [`CmsEnvironment`] with [`CmsEnvironment::add_signer_certificate_source`].
pub trait SignerCertificateSource {
    /// The certificate `sid` names, or `None` if the store holds none.
    fn find_signer_certificate(
        &self,
        env: &CmsEnvironment,
        sid: &SignerIdentifier,
    ) -> Result<Option<Certificate>>;
}
