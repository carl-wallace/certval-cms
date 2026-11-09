//! [`CmsEnvironment`]: the plug points through which every cryptographic operation of CMS
//! processing goes, the CMS counterpart of certval's `PkiEnvironment`.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use certval::PkiEnvironment;
use cms::enveloped_data::RecipientIdentifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

use crate::algorithms::{
    ContentEncryptionAlgorithm, KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm,
};
use crate::content::{decrypt_content_rust_crypto, encrypt_content_rust_crypto};

use crate::environment_traits::{
    ContentEncryptionOutput, DecryptContent, EncryptContent, EncryptKem, EncryptKeyAgreement,
    EncryptKeyTransport, KemOutput, KeyAgreeOutput, RecipientCertificateSource,
    RecipientCredentialSource, SharedRecipientCredential, SignerCertificateSource,
    SigningCredentialSource,
};
use crate::error::{Error, Result};

/// `data` hashed with `alg` through `pe`. No registered implementation hashing the algorithm is
/// [`Error::Unrecognized`], as it is for a signature no implementation verifies.
pub(crate) fn hash(
    pe: &PkiEnvironment,
    alg: &AlgorithmIdentifierOwned,
    data: &[u8],
) -> Result<Vec<u8>> {
    pe.calculate_hash(pe, alg, data).map_err(|e| match e {
        certval::Error::Unrecognized => Error::Unrecognized,
        e => Error::Certval(e),
    })
}

use crate::software::{
    encrypt_kem_rust_crypto, encrypt_key_agreement_rust_crypto, encrypt_key_transport_rust_crypto,
};

/// Offers a request to each implementation in order and returns the first answer that is not a
/// decline, or a decline if every one declines.
fn first_answer<C: ?Sized, T>(
    callbacks: &[Box<C>],
    mut call: impl FnMut(&C) -> Result<T>,
) -> Result<T> {
    for c in callbacks {
        match call(c) {
            Err(Error::Unrecognized) => continue,
            result => return result,
        }
    }
    Err(Error::Unrecognized)
}

/// The points at which CMS processing takes a pluggable implementation: content encryption and
/// decryption, each kind of recipient key management, the sources of the private keys that decrypt
/// and sign and of recipients' and signers' certificates, and the shared certval `PkiEnvironment`
/// that hashes, verifies signatures and vets certificates.
///
/// As in certval's `PkiEnvironment`, each kind of operation is offered to its registered
/// implementations in order, and the first that does not return [`Error::Unrecognized`] gives the
/// result. A provider registered ahead of [`populate_software`](Self::populate_software) is
/// consulted first, and software answers only what it declined. A caller who requires that every
/// operation reach the provider registers no software.
///
/// A decryption finds the recipient's private key through the registered
/// [`RecipientCredentialSource`]s, by recipient identifier, unless a credential is passed to it
/// directly.
///
/// The environment may also hold a shared certval [`PkiEnvironment`], which vets recipients'
/// certificates when an operation is given settings to vet them with; see
/// [`vet_certificate`](Self::vet_certificate).
#[derive(Default)]
pub struct CmsEnvironment {
    pub(crate) pki_environment: Option<Arc<PkiEnvironment>>,
    encrypt_content_callbacks: Vec<Box<dyn EncryptContent + Send + Sync>>,
    decrypt_content_callbacks: Vec<Box<dyn DecryptContent + Send + Sync>>,
    encrypt_key_transport_callbacks: Vec<Box<dyn EncryptKeyTransport + Send + Sync>>,
    encrypt_key_agreement_callbacks: Vec<Box<dyn EncryptKeyAgreement + Send + Sync>>,
    encrypt_kem_callbacks: Vec<Box<dyn EncryptKem + Send + Sync>>,
    recipient_credential_sources: Vec<Box<dyn RecipientCredentialSource + Send + Sync>>,
    pub(crate) recipient_certificate_sources:
        Vec<Box<dyn RecipientCertificateSource + Send + Sync>>,
    pub(crate) signing_credential_sources: Vec<Box<dyn SigningCredentialSource + Send + Sync>>,
    pub(crate) signer_certificate_sources: Vec<Box<dyn SignerCertificateSource + Send + Sync>>,
}

impl CmsEnvironment {
    /// An environment with nothing registered, which declines every operation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers certval-cms's software implementations after anything already registered.
    pub fn populate_software(&mut self) {
        self.add_encrypt_content_callback(encrypt_content_rust_crypto);
        self.add_decrypt_content_callback(decrypt_content_rust_crypto);
        self.add_encrypt_key_transport_callback(encrypt_key_transport_rust_crypto);
        self.add_encrypt_key_agreement_callback(encrypt_key_agreement_rust_crypto);
        self.add_encrypt_kem_callback(encrypt_kem_rust_crypto);
    }

    /// Registers a content encryption implementation after those already registered.
    pub fn add_encrypt_content_callback<C: EncryptContent + Send + Sync + 'static>(
        &mut self,
        c: C,
    ) {
        self.encrypt_content_callbacks.push(Box::new(c));
    }

    /// Removes every content encryption implementation.
    pub fn clear_encrypt_content_callbacks(&mut self) {
        self.encrypt_content_callbacks.clear();
    }

    /// Encrypts with the first registered implementation that does not decline. See
    /// [`EncryptContent::encrypt_content`].
    pub fn encrypt_content(
        &self,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        first_answer(&self.encrypt_content_callbacks, |c| {
            c.encrypt_content(self, alg, plaintext, aad)
        })
    }

    /// Registers a content decryption implementation after those already registered.
    pub fn add_decrypt_content_callback<C: DecryptContent + Send + Sync + 'static>(
        &mut self,
        c: C,
    ) {
        self.decrypt_content_callbacks.push(Box::new(c));
    }

    /// Removes every content decryption implementation.
    pub fn clear_decrypt_content_callbacks(&mut self) {
        self.decrypt_content_callbacks.clear();
    }

    /// Decrypts with the first registered implementation that does not decline. See
    /// [`DecryptContent::decrypt_content`].
    pub fn decrypt_content(
        &self,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        first_answer(&self.decrypt_content_callbacks, |c| {
            c.decrypt_content(self, alg, key, ciphertext, aad, tag)
        })
    }

    /// Registers a key transport implementation after those already registered.
    pub fn add_encrypt_key_transport_callback<C: EncryptKeyTransport + Send + Sync + 'static>(
        &mut self,
        c: C,
    ) {
        self.encrypt_key_transport_callbacks.push(Box::new(c));
    }

    /// Removes every key transport implementation.
    pub fn clear_encrypt_key_transport_callbacks(&mut self) {
        self.encrypt_key_transport_callbacks.clear();
    }

    /// Key transport with the first registered implementation that does not decline. See
    /// [`EncryptKeyTransport::encrypt_key_transport`].
    pub fn encrypt_key_transport(
        &self,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>> {
        first_answer(&self.encrypt_key_transport_callbacks, |c| {
            c.encrypt_key_transport(self, alg, spki, cek)
        })
    }

    /// Registers a key agreement implementation after those already registered.
    pub fn add_encrypt_key_agreement_callback<C: EncryptKeyAgreement + Send + Sync + 'static>(
        &mut self,
        c: C,
    ) {
        self.encrypt_key_agreement_callbacks.push(Box::new(c));
    }

    /// Removes every key agreement implementation.
    pub fn clear_encrypt_key_agreement_callbacks(&mut self) {
        self.encrypt_key_agreement_callbacks.clear();
    }

    /// Key agreement with the first registered implementation that does not decline. See
    /// [`EncryptKeyAgreement::encrypt_key_agreement`].
    pub fn encrypt_key_agreement(
        &self,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput> {
        first_answer(&self.encrypt_key_agreement_callbacks, |c| {
            c.encrypt_key_agreement(self, alg, wrap, spki, ukm, cek)
        })
    }

    /// Registers a KEM implementation after those already registered.
    pub fn add_encrypt_kem_callback<C: EncryptKem + Send + Sync + 'static>(&mut self, c: C) {
        self.encrypt_kem_callbacks.push(Box::new(c));
    }

    /// Removes every KEM implementation.
    pub fn clear_encrypt_kem_callbacks(&mut self) {
        self.encrypt_kem_callbacks.clear();
    }

    /// A KEM with the first registered implementation that does not decline. See
    /// [`EncryptKem::encrypt_kem`].
    pub fn encrypt_kem(
        &self,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput> {
        first_answer(&self.encrypt_kem_callbacks, |c| {
            c.encrypt_kem(self, kdf, wrap, spki, ukm, cek)
        })
    }

    /// Registers a source of recipient credentials after those already registered.
    pub fn add_recipient_credential_source<S: RecipientCredentialSource + Send + Sync + 'static>(
        &mut self,
        source: S,
    ) {
        self.recipient_credential_sources.push(Box::new(source));
    }

    /// Removes every source of recipient credentials.
    pub fn clear_recipient_credential_sources(&mut self) {
        self.recipient_credential_sources.clear();
    }

    /// The credential the first registered source returns for `rid`, with that source's position.
    pub fn find_recipient_credential(
        &self,
        rid: &RecipientIdentifier,
    ) -> Result<Option<(SharedRecipientCredential, usize)>> {
        for (index, source) in self.recipient_credential_sources.iter().enumerate() {
            if let Some(credential) = source.find_recipient_credential(self, rid)? {
                return Ok(Some((credential, index)));
            }
        }
        Ok(None)
    }
}
