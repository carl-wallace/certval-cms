//! [`CmsEnvironment`], the CMS counterpart of certval's `PkiEnvironment`.

use alloc::{boxed::Box, vec::Vec};

use spki::SubjectPublicKeyInfoOwned;

use crate::algorithms::{
    KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use crate::content::{
    encrypt_content_rust_crypto, ContentEncryptionAlgorithm, EncryptContent, EncryptedContent,
};
use crate::error::{Error, Result};
use crate::recipient::{
    EncryptKem, EncryptKeyAgreement, EncryptKeyTransport, KemOutput, KeyAgreeOutput,
};
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

/// The implementations CMS processing uses, each kind held in the order registered.
///
/// Like certval's `PkiEnvironment`, each kind of operation is offered to the registered
/// implementations in order, and the first that does not return [`Error::Unrecognized`] gives the
/// result. A provider registered ahead of [`populate_software`](Self::populate_software) is
/// consulted first, and software answers only what it declined. A caller who requires that every
/// operation reach the provider registers no software.
///
/// Certificate validation is not held here: an operation that validates a signer or recipient
/// certificate takes a `PkiEnvironment` as well, so one can be shared across uses.
#[derive(Default)]
pub struct CmsEnvironment {
    encrypt_content_callbacks: Vec<Box<dyn EncryptContent + Send + Sync>>,
    encrypt_key_transport_callbacks: Vec<Box<dyn EncryptKeyTransport + Send + Sync>>,
    encrypt_key_agreement_callbacks: Vec<Box<dyn EncryptKeyAgreement + Send + Sync>>,
    encrypt_kem_callbacks: Vec<Box<dyn EncryptKem + Send + Sync>>,
}

impl CmsEnvironment {
    /// An environment with nothing registered, which declines every operation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers certval-cms's software implementations after anything already registered.
    pub fn populate_software(&mut self) {
        self.add_encrypt_content_callback(encrypt_content_rust_crypto);
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
    ) -> Result<EncryptedContent> {
        first_answer(&self.encrypt_content_callbacks, |c| {
            c.encrypt_content(self, alg, plaintext, aad)
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
}
