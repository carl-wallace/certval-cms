//! The key management algorithms recipients use.

use const_oid::{
    db::{
        rfc5753::{
            DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME,
            DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME,
        },
        rfc5911::{ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP},
        rfc5912::{ID_RSAES_OAEP, RSA_ENCRYPTION},
    },
    ObjectIdentifier,
};
use der::{asn1::Any, Decode, Encode};
use rsa::pkcs1::RsaOaepParamsRef;
use spki::AlgorithmIdentifierOwned;

use crate::error::Result;

/// id-alg-hkdf-with-sha256, from RFC 8619.
pub const ID_ALG_HKDF_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");

/// id-alg-hkdf-with-sha384, from RFC 8619.
pub const ID_ALG_HKDF_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.29");

/// id-alg-hkdf-with-sha512, from RFC 8619.
pub const ID_ALG_HKDF_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.30");

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
}

/// An ephemeral-static ECDH key agreement scheme with the ANSI X9.63 KDF (RFC 5753, section 7.1.4),
/// for a KeyAgreeRecipientInfo.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyAgreementAlgorithm {
    /// dhSinglePass-stdDH-sha256kdf-scheme
    EcdhSha256,
    /// dhSinglePass-stdDH-sha384kdf-scheme
    EcdhSha384,
    /// dhSinglePass-stdDH-sha512kdf-scheme
    EcdhSha512,
}

impl KeyAgreementAlgorithm {
    /// The scheme's object identifier.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            KeyAgreementAlgorithm::EcdhSha256 => DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME,
            KeyAgreementAlgorithm::EcdhSha384 => DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME,
            KeyAgreementAlgorithm::EcdhSha512 => DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME,
        }
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
}
