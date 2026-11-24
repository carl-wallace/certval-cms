//! The bridge to cms's builder traits: [`CmsContentEncryptor`], a cms
//! [`ContentEncryptor`] whose encryption goes through a [`CmsEnvironment`], and the conversions
//! between this crate's errors and cms's builder errors.

use alloc::string::ToString;

use cms::builder::{self, ContentEncryptor};
use const_oid::{DynAssociatedOid, ObjectIdentifier};

use crate::algorithms::ContentEncryptionAlgorithm;
use crate::environment::CmsEnvironment;
use crate::error::Error;

/// A cms [`ContentEncryptor`] for one [`ContentEncryptionAlgorithm`], performed by the first
/// [`EncryptContent`](crate::EncryptContent) implementation registered on a [`CmsEnvironment`]
/// that does not decline. Made by [`CmsEnvironment::content_encryptor`].
///
/// Without a key, the implementation generates one; with one, as for EncryptedData, it is given
/// to [`EncryptContent::encrypt_content_with_key`](crate::EncryptContent::encrypt_content_with_key).
/// The random number generator cms passes is not used: each implementation draws its keys, IVs
/// and nonces from its own source.
#[derive(Clone, Copy, Debug)]
pub struct CmsContentEncryptor<'e> {
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
}

impl<'e> CmsContentEncryptor<'e> {
    /// The encryptor for `alg` through `env`.
    pub fn new(env: &'e CmsEnvironment, alg: ContentEncryptionAlgorithm) -> Self {
        Self { env, alg }
    }

    /// The algorithm it encrypts with.
    pub fn algorithm(&self) -> ContentEncryptionAlgorithm {
        self.alg
    }
}

impl DynAssociatedOid for CmsContentEncryptor<'_> {
    fn oid(&self) -> ObjectIdentifier {
        self.alg.oid()
    }
}

impl<R: ?Sized> ContentEncryptor<R> for CmsContentEncryptor<'_> {
    fn encrypt_content(
        &self,
        key: Option<&[u8]>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        _rng: &mut R,
    ) -> builder::Result<builder::ContentEncryptionOutput> {
        let output = match key {
            Some(key) => self
                .env
                .encrypt_content_with_key(self.alg, key, plaintext, aad),
            None => self.env.encrypt_content(self.alg, plaintext, aad),
        }
        .map_err(to_builder_error)?;
        Ok(builder::ContentEncryptionOutput {
            ciphertext: output.ciphertext,
            key: output.key,
            algorithm: output.algorithm,
            tag: output.tag,
        })
    }
}

/// This crate's error as a cms builder error, for the cms traits this crate implements. cms's
/// builder error has no place for another error, so all but an encoding error become its message.
pub(crate) fn to_builder_error(e: Error) -> builder::Error {
    match e {
        Error::Asn1(e) => builder::Error::Asn1(e),
        e => builder::Error::Builder(e.to_string()),
    }
}

/// A cms builder error, from cms's builders or from an implementation of its traits, as this
/// crate's error: an encoding error stays one; a builder refusing its configuration, e.g. no
/// recipients, is [`Error::InvalidInput`]; anything else is [`Error::Crypto`].
impl From<builder::Error> for Error {
    fn from(e: builder::Error) -> Self {
        match e {
            builder::Error::Asn1(e) => Error::Asn1(e),
            builder::Error::Builder(message) => Error::InvalidInput(message),
            e => Error::Crypto(e.to_string()),
        }
    }
}
