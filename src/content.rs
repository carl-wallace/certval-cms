//! Content encryption: the symmetric facet of EnvelopedData and AuthEnvelopedData.
//!
//! [`EncryptContent`] is the interface a provider implements to perform content encryption with its
//! own cryptographic module. An implementation generates the content-encryption key and the IV or
//! nonce itself, encrypts, and returns the key so that each recipient can wrap it. The key is in
//! host memory from then until the message is built, because every recipient wraps the same key.
//!
//! Implementations are registered on a [`CmsEnvironment`], which consults them in order and uses
//! the first that does not decline, as certval's `PkiEnvironment` consults its verification
//! callbacks. [`encrypt_content_rust_crypto`] is the RustCrypto implementation.

use alloc::{format, string::String, vec, vec::Vec};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, inout::InOutBuf},
    AeadInOut, AesGcm, KeyInit,
};
use cbc::cipher::{
    block_padding::Pkcs7, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt,
    BlockModeEncrypt, KeyIvInit,
};
use der::{
    asn1::{Any, OctetString},
    Decode, Encode, Sequence, Tag,
};
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::algorithms::ContentEncryptionAlgorithm;
use crate::environment::CmsEnvironment;
use crate::environment_traits::ContentEncryptionOutput;
use crate::error::{Error, Result};

/// Length in octets of the GCM nonce generated for a message, the length RFC 5084 recommends.
const GCM_NONCE_LEN: usize = 12;

/// Length in octets of the GCM authentication tag produced for a message, and the longest RFC 5084
/// allows a message.
const GCM_TAG_LEN: usize = 16;

/// Shortest GCM authentication tag RFC 5084, section 3.2, allows a message.
const GCM_MIN_TAG_LEN: usize = 12;

/// Length in octets of an AES-CBC IV.
const CBC_IV_LEN: usize = 16;

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

/// Content encryption with RustCrypto's AES, CBC and GCM implementations, for every
/// [`ContentEncryptionAlgorithm`]. Keys, IVs and nonces come from the operating system's random
/// number generator.
pub fn encrypt_content_rust_crypto(
    _env: &CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<ContentEncryptionOutput> {
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
) -> Result<ContentEncryptionOutput>
where
    C: BlockCipherEncrypt,
    cbc::Encryptor<C>: KeyIvInit + BlockModeEncrypt,
{
    let iv = random(CBC_IV_LEN)?;
    let encryptor = cbc::Encryptor::<C>::new_from_slices(&key, &iv)
        .map_err(|e| Error::Crypto(format!("{e}")))?;
    let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);
    Ok(ContentEncryptionOutput {
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
) -> Result<ContentEncryptionOutput>
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
    Ok(ContentEncryptionOutput {
        ciphertext,
        key,
        algorithm: AlgorithmIdentifierOwned {
            oid: alg.oid(),
            parameters: Some(Any::encode_from(&params)?),
        },
        tag: Some(tag.to_vec()),
    })
}

/// The mode-specific parameters of a content encryption algorithm identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContentParameters {
    /// AES-CBC: the 16-octet IV (RFC 3565).
    Cbc {
        /// The IV.
        iv: Vec<u8>,
    },
    /// AES-GCM: the nonce from `GCMParameters` (RFC 5084), of whatever length the message gives.
    Gcm {
        /// The nonce.
        nonce: Vec<u8>,
    },
}

/// Checks and decodes the inputs to content decryption, for a [`DecryptContent`](crate::DecryptContent) implementation:
/// the algorithm `alg` identifies, the key length it takes, associated data and a tag present
/// exactly when it authenticates (the tag always then), and its parameters, with GCM's tag length
/// the one `GCMParameters` gives, within the 12 to 16 octets RFC 5084 allows.
///
/// An algorithm this crate does not know is [`Error::Unrecognized`]; a key of the wrong length is
/// the [`Error::Crypto`] a failed decryption is, so that the two cannot be told apart; malformed
/// inputs otherwise are [`Error::InvalidInput`].
pub fn content_decryption_parameters(
    alg: &AlgorithmIdentifierOwned,
    key: &[u8],
    aad: Option<&[u8]>,
    tag: Option<&[u8]>,
) -> Result<(ContentEncryptionAlgorithm, ContentParameters)> {
    let content_alg = ContentEncryptionAlgorithm::from_oid(alg.oid).ok_or(Error::Unrecognized)?;
    if content_alg.is_authenticated() != tag.is_some()
        || (aad.is_some() && !content_alg.is_authenticated())
    {
        return Err(Error::InvalidInput(String::from(
            "associated data or a tag that does not match the algorithm",
        )));
    }
    if key.len() != content_alg.key_len() {
        return Err(decryption_failed());
    }
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidInput(format!("{} without parameters", alg.oid)))?
        .to_der()?;
    let parameters = match tag {
        None => {
            let iv = OctetString::from_der(&params)?;
            if iv.as_bytes().len() != CBC_IV_LEN {
                return Err(Error::InvalidInput(format!(
                    "CBC IV of {} octets",
                    iv.as_bytes().len()
                )));
            }
            ContentParameters::Cbc {
                iv: iv.as_bytes().to_vec(),
            }
        }
        Some(tag) => {
            let params = GcmParameters::from_der(&params)?;
            // The tag length is an unauthenticated field of the message, so a shorter tag than
            // the RFC allows is refused here, before an implementation that would accept it.
            if !(GCM_MIN_TAG_LEN..=GCM_TAG_LEN).contains(&usize::from(params.icv_len)) {
                return Err(Error::InvalidInput(format!(
                    "GCMParameters gives a tag of {} octets; RFC 5084 allows 12 to 16",
                    params.icv_len
                )));
            }
            if usize::from(params.icv_len) != tag.len() {
                return Err(Error::InvalidInput(format!(
                    "a tag of {} octets where GCMParameters gives {}",
                    tag.len(),
                    params.icv_len
                )));
            }
            ContentParameters::Gcm {
                nonce: params.nonce.as_bytes().to_vec(),
            }
        }
    };
    Ok((content_alg, parameters))
}

/// Content decryption with RustCrypto's AES, CBC and GCM implementations, for every
/// [`ContentEncryptionAlgorithm`], with GCM's 12-octet nonce and 16-octet tag; other nonce and tag
/// lengths are declined. Every failure to decrypt, a wrong key, bad padding or a tag that does not
/// verify, is the same [`Error::Crypto`].
pub fn decrypt_content_rust_crypto(
    _env: &CmsEnvironment,
    alg: &AlgorithmIdentifierOwned,
    key: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    tag: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let (content_alg, parameters) = content_decryption_parameters(alg, key, aad, tag)?;
    let aad = aad.unwrap_or_default();
    match (content_alg, parameters, tag) {
        (ContentEncryptionAlgorithm::Aes128Cbc, ContentParameters::Cbc { iv }, _) => {
            cbc_decrypt::<Aes128>(key, &iv, ciphertext)
        }
        (ContentEncryptionAlgorithm::Aes192Cbc, ContentParameters::Cbc { iv }, _) => {
            cbc_decrypt::<Aes192>(key, &iv, ciphertext)
        }
        (ContentEncryptionAlgorithm::Aes256Cbc, ContentParameters::Cbc { iv }, _) => {
            cbc_decrypt::<Aes256>(key, &iv, ciphertext)
        }
        (ContentEncryptionAlgorithm::Aes128Gcm, ContentParameters::Gcm { nonce }, Some(tag)) => {
            gcm_decrypt::<Aes128>(key, &nonce, ciphertext, aad, tag)
        }
        (ContentEncryptionAlgorithm::Aes192Gcm, ContentParameters::Gcm { nonce }, Some(tag)) => {
            gcm_decrypt::<Aes192>(key, &nonce, ciphertext, aad, tag)
        }
        (ContentEncryptionAlgorithm::Aes256Gcm, ContentParameters::Gcm { nonce }, Some(tag)) => {
            gcm_decrypt::<Aes256>(key, &nonce, ciphertext, aad, tag)
        }
        _ => Err(Error::Unrecognized),
    }
}

fn decryption_failed() -> Error {
    Error::Crypto(String::from("content decryption failed"))
}

fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>
where
    C: BlockCipherDecrypt,
    cbc::Decryptor<C>: KeyIvInit + BlockModeDecrypt,
{
    let decryptor =
        cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| decryption_failed())?;
    decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| decryption_failed())
}

fn gcm_decrypt<C>(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>>
where
    AesGcm<C, U12>: KeyInit + AeadInOut,
{
    // RustCrypto's AesGcm is instantiated for a 12-octet nonce and a 16-octet tag; other lengths
    // are declined.
    if nonce.len() != GCM_NONCE_LEN || tag.len() != GCM_TAG_LEN {
        return Err(Error::Unrecognized);
    }
    let cipher = AesGcm::<C, U12>::new_from_slice(key).map_err(|_| decryption_failed())?;
    let nonce = nonce.try_into().map_err(|_| decryption_failed())?;
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(
            &nonce,
            aad,
            InOutBuf::from(plaintext.as_mut_slice()),
            tag.try_into().map_err(|_| decryption_failed())?,
        )
        .map_err(|_| decryption_failed())?;
    Ok(plaintext)
}
