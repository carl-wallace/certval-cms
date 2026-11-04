//! Content encryption: the symmetric half of EnvelopedData and AuthEnvelopedData.
//!
//! [`EncryptContent`] is the interface a provider implements to perform content encryption with its
//! own cryptographic module. An implementation generates the content-encryption key and the IV or
//! nonce itself, encrypts, and returns the key so that each recipient can wrap it. The key is in
//! host memory from then until the message is built, because every recipient wraps the same key.
//!
//! Implementations are registered on a [`CmsEnvironment`], which consults them in order and uses
//! the first that does not decline, as certval's `PkiEnvironment` consults its verification
//! callbacks. [`encrypt_content_rust_crypto`] is the RustCrypto implementation.

use alloc::{format, string::String, sync::Arc, vec, vec::Vec};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, inout::InOutBuf},
    AeadInOut, AesGcm, KeyInit,
};
use cbc::cipher::{block_padding::Pkcs7, BlockCipherEncrypt, BlockModeEncrypt, KeyIvInit};
use const_oid::{db::rfc5911, ObjectIdentifier};
use der::{
    asn1::{Any, OctetString},
    Sequence, Tag,
};
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::environment::CmsEnvironment;
use crate::error::{Error, Result};

/// Length in octets of the GCM nonce generated for a message, the length RFC 5084 recommends.
const GCM_NONCE_LEN: usize = 12;

/// Length in octets of the GCM authentication tag produced for a message.
const GCM_TAG_LEN: usize = 16;

/// Length in octets of an AES-CBC IV.
const CBC_IV_LEN: usize = 16;

/// A content encryption algorithm. CBC serves EnvelopedData (RFC 5652, section 6) and GCM serves
/// AuthEnvelopedData (RFC 5083), with algorithm identifiers as defined by RFC 3565 and RFC 5084.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContentEncryptionAlgorithm {
    /// AES-128 in CBC mode
    Aes128Cbc,
    /// AES-192 in CBC mode
    Aes192Cbc,
    /// AES-256 in CBC mode
    Aes256Cbc,
    /// AES-128 in GCM mode
    Aes128Gcm,
    /// AES-192 in GCM mode
    Aes192Gcm,
    /// AES-256 in GCM mode
    Aes256Gcm,
}

impl ContentEncryptionAlgorithm {
    /// The algorithm's object identifier.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            ContentEncryptionAlgorithm::Aes128Cbc => rfc5911::ID_AES_128_CBC,
            ContentEncryptionAlgorithm::Aes192Cbc => rfc5911::ID_AES_192_CBC,
            ContentEncryptionAlgorithm::Aes256Cbc => rfc5911::ID_AES_256_CBC,
            ContentEncryptionAlgorithm::Aes128Gcm => rfc5911::ID_AES_128_GCM,
            ContentEncryptionAlgorithm::Aes192Gcm => rfc5911::ID_AES_192_GCM,
            ContentEncryptionAlgorithm::Aes256Gcm => rfc5911::ID_AES_256_GCM,
        }
    }

    /// The algorithm an object identifier identifies, if it is one of these.
    pub fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        [
            ContentEncryptionAlgorithm::Aes128Cbc,
            ContentEncryptionAlgorithm::Aes192Cbc,
            ContentEncryptionAlgorithm::Aes256Cbc,
            ContentEncryptionAlgorithm::Aes128Gcm,
            ContentEncryptionAlgorithm::Aes192Gcm,
            ContentEncryptionAlgorithm::Aes256Gcm,
        ]
        .into_iter()
        .find(|a| a.oid() == oid)
    }

    /// Length in octets of the content-encryption key.
    pub fn key_len(self) -> usize {
        match self {
            ContentEncryptionAlgorithm::Aes128Cbc | ContentEncryptionAlgorithm::Aes128Gcm => 16,
            ContentEncryptionAlgorithm::Aes192Cbc | ContentEncryptionAlgorithm::Aes192Gcm => 24,
            ContentEncryptionAlgorithm::Aes256Cbc | ContentEncryptionAlgorithm::Aes256Gcm => 32,
        }
    }

    /// Whether the algorithm authenticates, i.e., is usable for AuthEnvelopedData.
    pub fn is_authenticated(self) -> bool {
        matches!(
            self,
            ContentEncryptionAlgorithm::Aes128Gcm
                | ContentEncryptionAlgorithm::Aes192Gcm
                | ContentEncryptionAlgorithm::Aes256Gcm
        )
    }
}

/// GCM parameters, from RFC 5084, section 3.2.
///
/// ```text
/// GCMParameters ::= SEQUENCE {
///   aes-nonce        OCTET STRING, -- recommended size is 12 octets
///   aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct GcmParameters {
    /// The nonce.
    pub nonce: OctetString,
    /// Length in octets of the authentication tag.
    #[asn1(default = "default_icv_len")]
    pub icv_len: u8,
}

fn default_icv_len() -> u8 {
    12
}

/// The output of content encryption.
pub struct EncryptedContent {
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
/// (like [`encrypt_content_rust_crypto`]) can be registered directly. Implement the trait on a type
/// when the implementation needs to hold state that a function pointer cannot, e.g. a handle to a
/// hardware module.
pub trait EncryptContent {
    /// Generates a key for `alg`, and an IV or nonce, and encrypts `plaintext`. `aad` is the
    /// additional authenticated data for an authenticated algorithm, and must be `None` otherwise.
    fn encrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<EncryptedContent>;
}

impl<F> EncryptContent for F
where
    F: Fn(
        &CmsEnvironment,
        ContentEncryptionAlgorithm,
        &[u8],
        Option<&[u8]>,
    ) -> Result<EncryptedContent>,
{
    fn encrypt_content(
        &self,
        env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<EncryptedContent> {
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
    ) -> Result<EncryptedContent> {
        (**self).encrypt_content(env, alg, plaintext, aad)
    }
}

/// Content encryption with RustCrypto's AES, CBC and GCM implementations, for every
/// [`ContentEncryptionAlgorithm`]. Keys, IVs and nonces come from the operating system's random
/// number generator.
pub fn encrypt_content_rust_crypto(
    _env: &CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<EncryptedContent> {
    if aad.is_some() && !alg.is_authenticated() {
        return Err(Error::InvalidInput(String::from(
            "associated data given for an algorithm that does not authenticate",
        )));
    }
    let key = random(alg.key_len())?;
    match alg {
        ContentEncryptionAlgorithm::Aes128Cbc => cbc_encrypt::<Aes128>(alg, key, plaintext),
        ContentEncryptionAlgorithm::Aes192Cbc => cbc_encrypt::<Aes192>(alg, key, plaintext),
        ContentEncryptionAlgorithm::Aes256Cbc => cbc_encrypt::<Aes256>(alg, key, plaintext),
        ContentEncryptionAlgorithm::Aes128Gcm => {
            gcm_encrypt::<Aes128>(alg, key, plaintext, aad.unwrap_or_default())
        }
        ContentEncryptionAlgorithm::Aes192Gcm => {
            gcm_encrypt::<Aes192>(alg, key, plaintext, aad.unwrap_or_default())
        }
        ContentEncryptionAlgorithm::Aes256Gcm => {
            gcm_encrypt::<Aes256>(alg, key, plaintext, aad.unwrap_or_default())
        }
    }
}

fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut buf)
        .map_err(|e| Error::Crypto(format!("random number generator: {e}")))?;
    Ok(buf)
}

fn cbc_encrypt<C>(
    alg: ContentEncryptionAlgorithm,
    key: Zeroizing<Vec<u8>>,
    plaintext: &[u8],
) -> Result<EncryptedContent>
where
    C: BlockCipherEncrypt,
    cbc::Encryptor<C>: KeyIvInit + BlockModeEncrypt,
{
    let iv = random(CBC_IV_LEN)?;
    let encryptor = cbc::Encryptor::<C>::new_from_slices(&key, &iv)
        .map_err(|e| Error::Crypto(format!("{e}")))?;
    let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);
    Ok(EncryptedContent {
        ciphertext,
        key,
        algorithm: AlgorithmIdentifierOwned {
            oid: alg.oid(),
            parameters: Some(Any::new(Tag::OctetString, iv.as_slice())?),
        },
        tag: None,
    })
}

fn gcm_encrypt<C>(
    alg: ContentEncryptionAlgorithm,
    key: Zeroizing<Vec<u8>>,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedContent>
where
    AesGcm<C, U12>: KeyInit + AeadInOut,
{
    let nonce = random(GCM_NONCE_LEN)?;
    let cipher =
        AesGcm::<C, U12>::new_from_slice(&key).map_err(|e| Error::Crypto(format!("{e}")))?;
    let nonce_array = nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto(String::from("nonce length")))?;
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce_array, aad, InOutBuf::from(ciphertext.as_mut_slice()))
        .map_err(|e| Error::Crypto(format!("{e}")))?;
    let params = GcmParameters {
        nonce: OctetString::new(nonce.as_slice())?,
        icv_len: GCM_TAG_LEN as u8,
    };
    Ok(EncryptedContent {
        ciphertext,
        key,
        algorithm: AlgorithmIdentifierOwned {
            oid: alg.oid(),
            parameters: Some(Any::encode_from(&params)?),
        },
        tag: Some(tag.to_vec()),
    })
}
