//! Recipients: key management for EnvelopedData and AuthEnvelopedData.
//!
//! Each recipient type here is a `cms` [`RecipientInfoBuilder`] whose cryptography goes through a
//! [`CmsEnvironment`], so the content-encryption key is wrapped by the first registered
//! implementation that performs the operation. The implementations are of three kinds, one per
//! kind of recipient: [`EncryptKeyTransport`] (RSA), [`EncryptKeyAgreement`] (ECDH) and
//! [`EncryptKem`] (ML-KEM). Each takes only the recipient's public key, and performs the whole
//! operation, so that a secret derived along the way, such as an ECDH shared secret or a
//! key-encryption key, stays inside the implementation that derived it.

use alloc::{format, vec, vec::Vec};
use core::marker::PhantomData;

use cms::{
    builder::{RecipientInfoBuilder, RecipientInfoType},
    cert::IssuerAndSerialNumber,
    content_info::CmsVersion,
    enveloped_data::{
        EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, KeyTransRecipientInfo,
        OriginatorIdentifierOrKey, OriginatorPublicKey, OtherRecipientInfo, RecipientEncryptedKey,
        RecipientIdentifier, RecipientInfo, RecipientKeyIdentifier, UserKeyingMaterial,
    },
    kemri::{KemRecipientInfo, ID_ORI_KEM},
};
use const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::{
    asn1::{Any, BitString, OctetString},
    Decode, Encode,
};
use rand_core::CryptoRng;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{ext::pkix::SubjectKeyIdentifier, Certificate};

use crate::algorithms::{
    KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use crate::environment::CmsEnvironment;
use crate::error::{Error, Result};

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

/// The recipient identifier for a certificate: its subject key identifier extension if it has
/// one, otherwise its issuer and serial number.
pub fn recipient_identifier(cert: &Certificate) -> Result<RecipientIdentifier> {
    let skid = cert.tbs_certificate().extensions().and_then(|exts| {
        exts.iter()
            .find(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
    });
    match skid {
        Some(ext) => Ok(RecipientIdentifier::SubjectKeyIdentifier(
            SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())?,
        )),
        None => Ok(RecipientIdentifier::IssuerAndSerialNumber(
            IssuerAndSerialNumber {
                issuer: cert.tbs_certificate().issuer().clone(),
                serial_number: cert.tbs_certificate().serial_number().clone(),
            },
        )),
    }
}

fn subject_public_key_info(cert: &Certificate) -> SubjectPublicKeyInfoOwned {
    cert.tbs_certificate().subject_public_key_info().clone()
}

/// A recipient builder's error, carried through `cms`'s builder error type.
fn builder_error(e: Error) -> cms::builder::Error {
    match e {
        Error::Asn1(e) => cms::builder::Error::Asn1(e),
        Error::Builder(e) => e,
        e => cms::builder::Error::Builder(format!("{e}")),
    }
}

/// A key transport (RSA) recipient, whose key wrapping goes through a [`CmsEnvironment`].
pub struct KeyTransRecipient<'e, R: ?Sized> {
    env: &'e CmsEnvironment,
    rid: RecipientIdentifier,
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyTransportAlgorithm,
    _rng: PhantomData<R>,
}

impl<'e, R: ?Sized> KeyTransRecipient<'e, R> {
    /// A recipient identified by `rid`, holding the RSA key in `spki`.
    pub fn new(
        env: &'e CmsEnvironment,
        rid: RecipientIdentifier,
        spki: SubjectPublicKeyInfoOwned,
        alg: KeyTransportAlgorithm,
    ) -> Self {
        Self {
            env,
            rid,
            spki,
            alg,
            _rng: PhantomData,
        }
    }

    /// The recipient a certificate identifies, by [`recipient_identifier`].
    pub fn from_certificate(
        env: &'e CmsEnvironment,
        cert: &Certificate,
        alg: KeyTransportAlgorithm,
    ) -> Result<Self> {
        Ok(Self::new(
            env,
            recipient_identifier(cert)?,
            subject_public_key_info(cert),
            alg,
        ))
    }
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for KeyTransRecipient<'_, R> {
    type Rng = R;

    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Ktri
    }

    /// RFC 5652, section 6.2.1: 0 for an issuer and serial number, 2 for a subject key identifier.
    fn recipient_info_version(&self) -> CmsVersion {
        match self.rid {
            RecipientIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V0,
            RecipientIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V2,
        }
    }

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        _rng: &mut R,
    ) -> core::result::Result<RecipientInfo, cms::builder::Error> {
        let enc_key = self
            .env
            .encrypt_key_transport(self.alg, &self.spki, content_encryption_key)
            .map_err(builder_error)?;
        Ok(RecipientInfo::Ktri(KeyTransRecipientInfo {
            version: self.recipient_info_version(),
            rid: self.rid.clone(),
            key_enc_alg: self.alg.algorithm_identifier().map_err(builder_error)?,
            enc_key: OctetString::new(enc_key)?,
        }))
    }
}

/// A key agreement (ECDH) recipient, whose key wrapping goes through a [`CmsEnvironment`].
pub struct KeyAgreeRecipient<'e, R: ?Sized> {
    env: &'e CmsEnvironment,
    rid: KeyAgreeRecipientIdentifier,
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    ukm: Option<Vec<u8>>,
    _rng: PhantomData<R>,
}

impl<'e, R: ?Sized> KeyAgreeRecipient<'e, R> {
    /// A recipient identified by `rid`, holding the EC key in `spki`. `ukm` is optional user keying
    /// material, sent in the message and input to the key derivation.
    pub fn new(
        env: &'e CmsEnvironment,
        rid: RecipientIdentifier,
        spki: SubjectPublicKeyInfoOwned,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
    ) -> Self {
        let rid = match rid {
            RecipientIdentifier::IssuerAndSerialNumber(iasn) => {
                KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(iasn)
            }
            RecipientIdentifier::SubjectKeyIdentifier(skid) => {
                KeyAgreeRecipientIdentifier::RKeyId(RecipientKeyIdentifier {
                    subject_key_identifier: skid,
                    date: None,
                    other: None,
                })
            }
        };
        Self {
            env,
            rid,
            spki,
            alg,
            wrap,
            ukm,
            _rng: PhantomData,
        }
    }

    /// The recipient a certificate identifies, by [`recipient_identifier`].
    pub fn from_certificate(
        env: &'e CmsEnvironment,
        cert: &Certificate,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self::new(
            env,
            recipient_identifier(cert)?,
            subject_public_key_info(cert),
            alg,
            wrap,
            ukm,
        ))
    }
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for KeyAgreeRecipient<'_, R> {
    type Rng = R;

    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Kari
    }

    /// RFC 5652, section 6.2.2: always 3.
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V3
    }

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        _rng: &mut R,
    ) -> core::result::Result<RecipientInfo, cms::builder::Error> {
        let output = self
            .env
            .encrypt_key_agreement(
                self.alg,
                self.wrap,
                &self.spki,
                self.ukm.as_deref(),
                content_encryption_key,
            )
            .map_err(builder_error)?;
        let ukm = match &self.ukm {
            Some(ukm) => Some(UserKeyingMaterial::new(ukm.clone())?),
            None => None,
        };
        Ok(RecipientInfo::Kari(KeyAgreeRecipientInfo {
            version: CmsVersion::V3,
            // RFC 5753, section 3.1.1: the ephemeral key, on the recipient's curve, which the
            // algorithm identifier names.
            originator: OriginatorIdentifierOrKey::OriginatorKey(OriginatorPublicKey {
                algorithm: self.spki.algorithm.clone(),
                public_key: BitString::from_bytes(&output.ephemeral_public_key)?,
            }),
            ukm,
            key_enc_alg: AlgorithmIdentifierOwned {
                oid: self.alg.oid(),
                parameters: Some(Any::encode_from(&self.wrap.algorithm_identifier())?),
            },
            recipient_enc_keys: vec![RecipientEncryptedKey {
                rid: self.rid.clone(),
                enc_key: EncryptedKey::new(output.encrypted_key)?,
            }],
        }))
    }
}

/// A KEM (ML-KEM) recipient (RFC 9629), whose key wrapping goes through a [`CmsEnvironment`].
pub struct KemRecipient<'e, R: ?Sized> {
    env: &'e CmsEnvironment,
    rid: RecipientIdentifier,
    spki: SubjectPublicKeyInfoOwned,
    kdf: KdfAlgorithm,
    wrap: KeyWrapAlgorithm,
    ukm: Option<Vec<u8>>,
    _rng: PhantomData<R>,
}

impl<'e, R: ?Sized> KemRecipient<'e, R> {
    /// A recipient identified by `rid`, holding the KEM key in `spki`. `ukm` is optional user keying
    /// material, sent in the message and input to the key derivation.
    pub fn new(
        env: &'e CmsEnvironment,
        rid: RecipientIdentifier,
        spki: SubjectPublicKeyInfoOwned,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
    ) -> Self {
        Self {
            env,
            rid,
            spki,
            kdf,
            wrap,
            ukm,
            _rng: PhantomData,
        }
    }

    /// The recipient a certificate identifies, by [`recipient_identifier`].
    pub fn from_certificate(
        env: &'e CmsEnvironment,
        cert: &Certificate,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self::new(
            env,
            recipient_identifier(cert)?,
            subject_public_key_info(cert),
            kdf,
            wrap,
            ukm,
        ))
    }
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for KemRecipient<'_, R> {
    type Rng = R;

    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Ori
    }

    /// RFC 5652, section 6.1 counts an OtherRecipientInfo as version 3 for the enclosing message.
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V3
    }

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        _rng: &mut R,
    ) -> core::result::Result<RecipientInfo, cms::builder::Error> {
        let output = self
            .env
            .encrypt_kem(
                self.kdf,
                self.wrap,
                &self.spki,
                self.ukm.as_deref(),
                content_encryption_key,
            )
            .map_err(builder_error)?;
        let ukm = match &self.ukm {
            Some(ukm) => Some(UserKeyingMaterial::new(ukm.clone())?),
            None => None,
        };
        let kemri = KemRecipientInfo {
            // RFC 9629, section 3: "version is the syntax version number. The version MUST be 0."
            version: CmsVersion::V0,
            rid: self.rid.clone(),
            // The KEM the recipient's key is for; ML-KEM's parameters are absent (RFC 9936).
            kem: AlgorithmIdentifierOwned {
                oid: self.spki.algorithm.oid,
                parameters: None,
            },
            kem_ct: OctetString::new(output.kem_ct)?,
            kdf: self.kdf.algorithm_identifier(),
            kek_length: self.wrap.kek_len() as u16,
            ukm,
            wrap: self.wrap.algorithm_identifier(),
            encrypted_key: OctetString::new(output.encrypted_key)?,
        };
        Ok(RecipientInfo::Ori(OtherRecipientInfo {
            ori_type: ID_ORI_KEM,
            ori_value: Any::from_der(&kemri.to_der()?)?,
        }))
    }
}
