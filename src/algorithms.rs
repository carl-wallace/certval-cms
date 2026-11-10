//! The algorithms of content encryption, and of the key management recipients use.

use crate::error::{Error, Result};
use alloc::{format, string::String};
use const_oid::{
    db::{
        rfc5753::{
            DH_SINGLE_PASS_COFACTOR_DH_SHA_256_KDF_SCHEME,
            DH_SINGLE_PASS_COFACTOR_DH_SHA_384_KDF_SCHEME,
            DH_SINGLE_PASS_COFACTOR_DH_SHA_512_KDF_SCHEME,
            DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME,
            DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME,
        },
        rfc5911::{
            ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_192_CBC, ID_AES_192_GCM,
            ID_AES_192_WRAP, ID_AES_256_CBC, ID_AES_256_GCM, ID_AES_256_WRAP,
        },
        rfc5912::{
            ID_MGF_1, ID_P_SPECIFIED, ID_RSAES_OAEP, ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512,
            RSA_ENCRYPTION,
        },
    },
    ObjectIdentifier,
};
use der::{
    asn1::{Any, OctetString},
    Decode, Encode,
};
use log::debug;
use rsa::pkcs1::{RsaOaepParamsOwned, RsaOaepParamsRef};
use spki::AlgorithmIdentifierOwned;

/// Decodes an algorithm identifier's parameters as `T`, failing if they are absent.
fn parameters<T: for<'a> Decode<'a, Error = der::Error>>(
    alg: &AlgorithmIdentifierOwned,
) -> Result<T> {
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidInput(alloc::format!("{} without parameters", alg.oid)))?;
    Ok(T::from_der(&params.to_der()?)?)
}

/// id-alg-hkdf-with-sha256, from RFC 8619.
pub const ID_ALG_HKDF_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");

/// id-alg-hkdf-with-sha384, from RFC 8619.
pub const ID_ALG_HKDF_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.29");

/// id-alg-hkdf-with-sha512, from RFC 8619.
pub const ID_ALG_HKDF_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.30");

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
            ContentEncryptionAlgorithm::Aes128Cbc => ID_AES_128_CBC,
            ContentEncryptionAlgorithm::Aes192Cbc => ID_AES_192_CBC,
            ContentEncryptionAlgorithm::Aes256Cbc => ID_AES_256_CBC,
            ContentEncryptionAlgorithm::Aes128Gcm => ID_AES_128_GCM,
            ContentEncryptionAlgorithm::Aes192Gcm => ID_AES_192_GCM,
            ContentEncryptionAlgorithm::Aes256Gcm => ID_AES_256_GCM,
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

/// An RSA key transport algorithm (RFC 8017), for a KeyTransRecipientInfo. OAEP uses MGF1 with the
/// same hash and an empty label (RFC 4055, section 4.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyTransportAlgorithm {
    /// RSAES-PKCS1-v1_5
    RsaPkcs1v15,
    /// RSAES-OAEP with SHA-1, the RSAES-OAEP-params defaults
    RsaOaepSha1,
    /// RSAES-OAEP with SHA-256
    RsaOaepSha256,
    /// RSAES-OAEP with SHA-384
    RsaOaepSha384,
    /// RSAES-OAEP with SHA-512
    RsaOaepSha512,
}

impl KeyTransportAlgorithm {
    /// The keyEncryptionAlgorithm for a KeyTransRecipientInfo.
    pub fn algorithm_identifier(self) -> Result<AlgorithmIdentifierOwned> {
        let oaep_params = match self {
            KeyTransportAlgorithm::RsaPkcs1v15 => {
                return Ok(AlgorithmIdentifierOwned {
                    oid: RSA_ENCRYPTION,
                    parameters: Some(Any::null()),
                })
            }
            KeyTransportAlgorithm::RsaOaepSha1 => RsaOaepParamsRef::new::<sha1::Sha1>().to_der()?,
            KeyTransportAlgorithm::RsaOaepSha256 => {
                RsaOaepParamsRef::new::<sha2::Sha256>().to_der()?
            }
            KeyTransportAlgorithm::RsaOaepSha384 => {
                RsaOaepParamsRef::new::<sha2::Sha384>().to_der()?
            }
            KeyTransportAlgorithm::RsaOaepSha512 => {
                RsaOaepParamsRef::new::<sha2::Sha512>().to_der()?
            }
        };
        Ok(AlgorithmIdentifierOwned {
            oid: ID_RSAES_OAEP,
            parameters: Some(Any::from_der(&oaep_params)?),
        })
    }

    /// The algorithm a KeyTransRecipientInfo's keyEncryptionAlgorithm identifies. OAEP is
    /// recognized only as this crate produces it: MGF1 with the same hash, and an empty label; other
    /// choices are [`Error::Unrecognized`]. A mask generation function other than MGF1, or MGF1
    /// without its hash, is malformed and [`Error::InvalidInput`].
    pub fn from_algorithm_identifier(alg: &AlgorithmIdentifierOwned) -> Result<Self> {
        match alg.oid {
            RSA_ENCRYPTION => Ok(KeyTransportAlgorithm::RsaPkcs1v15),
            ID_RSAES_OAEP => {
                let params: RsaOaepParamsOwned = parameters(alg)?;
                // MGF1 is the one mask generation function (RFC 8017, appendix B.2.1), and its
                // parameters, the hash it uses, are required (RFC 5912: "PARAMS TYPE HashAlgorithm
                // ARE required"). They are an `Option` here only because the type follows
                // AlgorithmIdentifier's generic definition, where parameters are OPTIONAL.
                if params.mask_gen.oid != ID_MGF_1 {
                    debug!(
                        "OAEP mask generation function {} is not MGF1",
                        params.mask_gen.oid
                    );
                    return Err(Error::InvalidInput(format!(
                        "OAEP mask generation function {} is not MGF1",
                        params.mask_gen.oid
                    )));
                }
                let Some(mgf_hash) = params.mask_gen.parameters.as_ref().map(|hash| hash.oid)
                else {
                    debug!("OAEP parameters with MGF1 but no hash for it");
                    return Err(Error::InvalidInput(String::from(
                        "OAEP parameters with MGF1 but no hash for it",
                    )));
                };
                let empty_label = params.p_source.oid == ID_P_SPECIFIED
                    && match &params.p_source.parameters {
                        Some(label) => OctetString::from_der(&label.to_der()?)?.is_empty(),
                        None => false,
                    };
                if mgf_hash != params.hash.oid || !empty_label {
                    return Err(Error::Unrecognized);
                }
                match params.hash.oid {
                    ID_SHA_1 => Ok(KeyTransportAlgorithm::RsaOaepSha1),
                    ID_SHA_256 => Ok(KeyTransportAlgorithm::RsaOaepSha256),
                    ID_SHA_384 => Ok(KeyTransportAlgorithm::RsaOaepSha384),
                    ID_SHA_512 => Ok(KeyTransportAlgorithm::RsaOaepSha512),
                    _ => Err(Error::Unrecognized),
                }
            }
            _ => Err(Error::Unrecognized),
        }
    }
}

/// An ephemeral-static ECDH key agreement scheme with the ANSI X9.63 KDF (RFC 5753, section 7.1.4),
/// for a KeyAgreeRecipientInfo.
///
/// The cofactor schemes differ from the standard ones only by multiplying the shared point by the
/// curve's cofactor, which is 1 for P-256, P-384 and P-521, so on those curves each derives the same
/// key-encryption key as the standard scheme with the same hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyAgreementAlgorithm {
    /// dhSinglePass-stdDH-sha256kdf-scheme
    EcdhSha256,
    /// dhSinglePass-stdDH-sha384kdf-scheme
    EcdhSha384,
    /// dhSinglePass-stdDH-sha512kdf-scheme
    EcdhSha512,
    /// dhSinglePass-cofactorDH-sha256kdf-scheme
    EcdhCofactorSha256,
    /// dhSinglePass-cofactorDH-sha384kdf-scheme
    EcdhCofactorSha384,
    /// dhSinglePass-cofactorDH-sha512kdf-scheme
    EcdhCofactorSha512,
}

impl KeyAgreementAlgorithm {
    /// The scheme's object identifier.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            KeyAgreementAlgorithm::EcdhSha256 => DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME,
            KeyAgreementAlgorithm::EcdhSha384 => DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME,
            KeyAgreementAlgorithm::EcdhSha512 => DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME,
            KeyAgreementAlgorithm::EcdhCofactorSha256 => {
                DH_SINGLE_PASS_COFACTOR_DH_SHA_256_KDF_SCHEME
            }
            KeyAgreementAlgorithm::EcdhCofactorSha384 => {
                DH_SINGLE_PASS_COFACTOR_DH_SHA_384_KDF_SCHEME
            }
            KeyAgreementAlgorithm::EcdhCofactorSha512 => {
                DH_SINGLE_PASS_COFACTOR_DH_SHA_512_KDF_SCHEME
            }
        }
    }

    /// The scheme and key wrap a KeyAgreeRecipientInfo's keyEncryptionAlgorithm identifies: the
    /// scheme's object identifier, with the key wrap algorithm identifier as its parameters (RFC
    /// 5753, section 3.1.1).
    pub fn from_algorithm_identifier(
        alg: &AlgorithmIdentifierOwned,
    ) -> Result<(Self, KeyWrapAlgorithm)> {
        let scheme = [
            KeyAgreementAlgorithm::EcdhSha256,
            KeyAgreementAlgorithm::EcdhSha384,
            KeyAgreementAlgorithm::EcdhSha512,
            KeyAgreementAlgorithm::EcdhCofactorSha256,
            KeyAgreementAlgorithm::EcdhCofactorSha384,
            KeyAgreementAlgorithm::EcdhCofactorSha512,
        ]
        .into_iter()
        .find(|a| a.oid() == alg.oid)
        .ok_or(Error::Unrecognized)?;
        let wrap: AlgorithmIdentifierOwned = parameters(alg)?;
        Ok((scheme, KeyWrapAlgorithm::from_algorithm_identifier(&wrap)?))
    }
}

/// An AES key wrap algorithm (RFC 3394, identifiers from RFC 3565), which wraps the
/// content-encryption key under a key derived for the recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyWrapAlgorithm {
    /// id-aes128-wrap
    Aes128,
    /// id-aes192-wrap
    Aes192,
    /// id-aes256-wrap
    Aes256,
}

impl KeyWrapAlgorithm {
    /// The algorithm's object identifier.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            KeyWrapAlgorithm::Aes128 => ID_AES_128_WRAP,
            KeyWrapAlgorithm::Aes192 => ID_AES_192_WRAP,
            KeyWrapAlgorithm::Aes256 => ID_AES_256_WRAP,
        }
    }

    /// The algorithm identifier, with parameters absent (RFC 3565, section 4.3).
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// Length in octets of the key-encryption key.
    pub fn kek_len(self) -> usize {
        match self {
            KeyWrapAlgorithm::Aes128 => 16,
            KeyWrapAlgorithm::Aes192 => 24,
            KeyWrapAlgorithm::Aes256 => 32,
        }
    }

    /// The key wrap algorithm an algorithm identifier identifies.
    pub fn from_algorithm_identifier(alg: &AlgorithmIdentifierOwned) -> Result<Self> {
        [
            KeyWrapAlgorithm::Aes128,
            KeyWrapAlgorithm::Aes192,
            KeyWrapAlgorithm::Aes256,
        ]
        .into_iter()
        .find(|w| w.oid() == alg.oid)
        .ok_or(Error::Unrecognized)
    }
}

/// A key derivation function for a KEMRecipientInfo (RFC 9629), HKDF from RFC 8619.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KdfAlgorithm {
    /// id-alg-hkdf-with-sha256
    HkdfSha256,
    /// id-alg-hkdf-with-sha384
    HkdfSha384,
    /// id-alg-hkdf-with-sha512
    HkdfSha512,
}

impl KdfAlgorithm {
    /// The algorithm identifier, with parameters absent (RFC 8619, section 3).
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        let oid = match self {
            KdfAlgorithm::HkdfSha256 => ID_ALG_HKDF_WITH_SHA256,
            KdfAlgorithm::HkdfSha384 => ID_ALG_HKDF_WITH_SHA384,
            KdfAlgorithm::HkdfSha512 => ID_ALG_HKDF_WITH_SHA512,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    /// The KDF an algorithm identifier identifies.
    pub fn from_algorithm_identifier(alg: &AlgorithmIdentifierOwned) -> Result<Self> {
        [
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha384,
            KdfAlgorithm::HkdfSha512,
        ]
        .into_iter()
        .find(|k| k.algorithm_identifier().oid == alg.oid)
        .ok_or(Error::Unrecognized)
    }
}
