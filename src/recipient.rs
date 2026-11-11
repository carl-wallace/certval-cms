//! Recipients: key management for EnvelopedData and AuthEnvelopedData.
//!
//! Each recipient type here is a `cms` [`RecipientInfoBuilder`] whose cryptography goes through a
//! [`CmsEnvironment`], so the content-encryption key is wrapped by the first registered
//! implementation that performs the operation. The implementations are of three kinds, one per
//! kind of recipient: [`EncryptKeyTransport`] (RSA), [`EncryptKeyAgreement`] (ECDH) and
//! [`EncryptKem`] (ML-KEM). Each takes only the recipient's public key, and performs the whole
//! operation, so that a secret derived along the way, such as an ECDH shared secret or a
//! key-encryption key, stays inside the implementation that derived it.

use alloc::{boxed::Box, vec, vec::Vec};
use core::marker::PhantomData;

use certval::CertificationPathSettings;
use cms::{
    cert::IssuerAndSerialNumber,
    content_info::CmsVersion,
    enveloped_data::{
        EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, KeyTransRecipientInfo,
        OriginatorIdentifierOrKey, OriginatorPublicKey, OtherRecipientInfo, RecipientEncryptedKey,
        RecipientIdentifier, RecipientInfo, RecipientKeyIdentifier, UserKeyingMaterial,
    },
    kemri::{CmsOriForKemOtherInfo, KemRecipientInfo, ID_ORI_KEM},
};
use const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::{
    asn1::{Any, BitString, OctetString},
    Decode, Encode, Sequence,
};
use rand_core::CryptoRng;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{ext::pkix::SubjectKeyIdentifier, Certificate};

use crate::algorithms::{
    KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use crate::environment::CmsEnvironment;
use crate::error::Result;
use crate::vetting::{KeyUse, Vetting};

/// The `ECC-CMS-SharedInfo` type, from RFC 5753, section 7.2.
///
/// ```text
/// ECC-CMS-SharedInfo ::= SEQUENCE {
///   keyInfo         AlgorithmIdentifier,
///   entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
///   suppPubInfo [2] EXPLICIT OCTET STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EccCmsSharedInfo {
    /// The key wrap algorithm the derived key-encryption key is for.
    pub key_info: AlgorithmIdentifierOwned,
    /// The user keying material, when there is any.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub entity_u_info: Option<OctetString>,
    /// The key-encryption key's length in bits, as four octets.
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    pub supp_pub_info: OctetString,
}

/// The DER encoding of the `ECC-CMS-SharedInfo` (RFC 5753, section 7.2) that an
/// [`EncryptKeyAgreement`](crate::EncryptKeyAgreement) implementation gives the X9.63 KDF as its shared info: `keyInfo` is the
/// key wrap algorithm, `entityUInfo` the ukm when there is one, and `suppPubInfo` the
/// key-encryption key's length in bits, as four octets.
pub fn ecc_cms_shared_info(wrap: KeyWrapAlgorithm, ukm: Option<&[u8]>) -> Result<Vec<u8>> {
    let kek_bits = (wrap.kek_len() as u32 * 8).to_be_bytes();
    Ok(EccCmsSharedInfo {
        key_info: wrap.algorithm_identifier(),
        entity_u_info: match ukm {
            Some(ukm) => Some(OctetString::new(ukm)?),
            None => None,
        },
        supp_pub_info: OctetString::new(kek_bits)?,
    }
    .to_der()?)
}

/// The DER encoding of the `CMSORIforKEMOtherInfo` (RFC 9629, section 5) that an [`EncryptKem`](crate::EncryptKem)
/// implementation gives the KDF as its info.
pub fn kem_other_info(wrap: KeyWrapAlgorithm, ukm: Option<&[u8]>) -> Result<Vec<u8>> {
    Ok(CmsOriForKemOtherInfo {
        wrap: wrap.algorithm_identifier(),
        kek_length: wrap.kek_len() as u16,
        ukm: match ukm {
            Some(ukm) => Some(OctetString::new(ukm)?),
            None => None,
        },
    }
    .to_der()?)
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

/// One recipient's key management: builds the RecipientInfo carrying a content-encryption key to
/// that recipient. This crate's [`KeyTransRecipient`], [`KeyAgreeRecipient`] and [`KemRecipient`]
/// implement it with their cryptography going through a [`CmsEnvironment`]; a recipient whose key
/// management lies elsewhere implements it too, and the builders take either.
pub trait RecipientInfoBuilder {
    /// The random number generator the builder is given.
    type Rng: CryptoRng + ?Sized;

    /// The RecipientInfo carrying `content_encryption_key` to this recipient.
    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut Self::Rng,
    ) -> Result<RecipientInfo>;
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for Box<dyn RecipientInfoBuilder<Rng = R> + '_> {
    type Rng = R;

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut R,
    ) -> Result<RecipientInfo> {
        (**self).build_with_rng(content_encryption_key, rng)
    }
}

/// RFC 5652, section 6.2.1: a KeyTransRecipientInfo is version 0 with an issuer and serial
/// number and 2 with a subject key identifier.
fn key_trans_version(rid: &RecipientIdentifier) -> CmsVersion {
    match rid {
        RecipientIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V0,
        RecipientIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V2,
    }
}

/// A key transport (RSA) recipient, whose key wrapping goes through a [`CmsEnvironment`].
pub struct KeyTransRecipient<'e, R: ?Sized> {
    env: &'e CmsEnvironment,
    vetting: Vetting,
    rid: RecipientIdentifier,
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyTransportAlgorithm,
    _rng: PhantomData<R>,
}

impl<R: ?Sized> core::fmt::Debug for KeyTransRecipient<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyTransRecipient")
            .field("rid", &self.rid)
            .field("alg", &self.alg)
            .field("vetting", &self.vetting)
            .finish()
    }
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
            vetting: Vetting::NotPerformed,
            rid,
            spki,
            alg,
            _rng: PhantomData,
        }
    }

    /// The recipient a certificate identifies, by [`recipient_identifier`]. With `settings`, the
    /// certificate is vetted for key transport first; see [`CmsEnvironment::vet_certificate`].
    pub fn from_certificate(
        env: &'e CmsEnvironment,
        cert: &Certificate,
        settings: Option<&CertificationPathSettings>,
        alg: KeyTransportAlgorithm,
    ) -> Result<Self> {
        let vetting = match settings {
            Some(settings) => env.vet_certificate(cert, KeyUse::KeyTransport, settings)?,
            None => Vetting::NotPerformed,
        };
        let mut recipient = Self::new(
            env,
            recipient_identifier(cert)?,
            subject_public_key_info(cert),
            alg,
        );
        recipient.vetting = vetting;
        Ok(recipient)
    }

    /// Whether the recipient's certificate was vetted.
    pub fn vetting(&self) -> &Vetting {
        &self.vetting
    }
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for KeyTransRecipient<'_, R> {
    type Rng = R;

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        _rng: &mut R,
    ) -> Result<RecipientInfo> {
        let enc_key =
            self.env
                .encrypt_key_transport(self.alg, &self.spki, content_encryption_key)?;
        Ok(RecipientInfo::Ktri(KeyTransRecipientInfo {
            version: key_trans_version(&self.rid),
            rid: self.rid.clone(),
            key_enc_alg: self.alg.algorithm_identifier()?,
            enc_key: OctetString::new(enc_key)?,
        }))
    }
}

/// A key agreement (ECDH) recipient, whose key wrapping goes through a [`CmsEnvironment`].
pub struct KeyAgreeRecipient<'e, R: ?Sized> {
    env: &'e CmsEnvironment,
    vetting: Vetting,
    rid: KeyAgreeRecipientIdentifier,
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    ukm: Option<Vec<u8>>,
    _rng: PhantomData<R>,
}

impl<R: ?Sized> core::fmt::Debug for KeyAgreeRecipient<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyAgreeRecipient")
            .field("rid", &self.rid)
            .field("alg", &self.alg)
            .field("wrap", &self.wrap)
            .field("ukm", &self.ukm.as_ref().map(Vec::len))
            .field("vetting", &self.vetting)
            .finish()
    }
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
            vetting: Vetting::NotPerformed,
            rid,
            spki,
            alg,
            wrap,
            ukm,
            _rng: PhantomData,
        }
    }

    /// The recipient a certificate identifies, by [`recipient_identifier`]. With `settings`, the
    /// certificate is vetted for key agreement first; see [`CmsEnvironment::vet_certificate`].
    pub fn from_certificate(
        env: &'e CmsEnvironment,
        cert: &Certificate,
        settings: Option<&CertificationPathSettings>,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
    ) -> Result<Self> {
        let vetting = match settings {
            Some(settings) => env.vet_certificate(cert, KeyUse::KeyAgreement, settings)?,
            None => Vetting::NotPerformed,
        };
        let mut recipient = Self::new(
            env,
            recipient_identifier(cert)?,
            subject_public_key_info(cert),
            alg,
            wrap,
            ukm,
        );
        recipient.vetting = vetting;
        Ok(recipient)
    }

    /// Whether the recipient's certificate was vetted.
    pub fn vetting(&self) -> &Vetting {
        &self.vetting
    }
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for KeyAgreeRecipient<'_, R> {
    type Rng = R;

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        _rng: &mut R,
    ) -> Result<RecipientInfo> {
        let output = self.env.encrypt_key_agreement(
            self.alg,
            self.wrap,
            &self.spki,
            self.ukm.as_deref(),
            content_encryption_key,
        )?;
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
    vetting: Vetting,
    rid: RecipientIdentifier,
    spki: SubjectPublicKeyInfoOwned,
    kdf: KdfAlgorithm,
    wrap: KeyWrapAlgorithm,
    ukm: Option<Vec<u8>>,
    _rng: PhantomData<R>,
}

impl<R: ?Sized> core::fmt::Debug for KemRecipient<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KemRecipient")
            .field("rid", &self.rid)
            .field("kem", &self.spki.algorithm.oid)
            .field("kdf", &self.kdf)
            .field("wrap", &self.wrap)
            .field("ukm", &self.ukm.as_ref().map(Vec::len))
            .field("vetting", &self.vetting)
            .finish()
    }
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
            vetting: Vetting::NotPerformed,
            rid,
            spki,
            kdf,
            wrap,
            ukm,
            _rng: PhantomData,
        }
    }

    /// The recipient a certificate identifies, by [`recipient_identifier`]. With `settings`, the
    /// certificate is vetted for a KEM first; see [`CmsEnvironment::vet_certificate`].
    pub fn from_certificate(
        env: &'e CmsEnvironment,
        cert: &Certificate,
        settings: Option<&CertificationPathSettings>,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        ukm: Option<Vec<u8>>,
    ) -> Result<Self> {
        let vetting = match settings {
            Some(settings) => env.vet_certificate(cert, KeyUse::Kem, settings)?,
            None => Vetting::NotPerformed,
        };
        let mut recipient = Self::new(
            env,
            recipient_identifier(cert)?,
            subject_public_key_info(cert),
            kdf,
            wrap,
            ukm,
        );
        recipient.vetting = vetting;
        Ok(recipient)
    }

    /// Whether the recipient's certificate was vetted.
    pub fn vetting(&self) -> &Vetting {
        &self.vetting
    }
}

impl<R: CryptoRng + ?Sized> RecipientInfoBuilder for KemRecipient<'_, R> {
    type Rng = R;

    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        _rng: &mut R,
    ) -> Result<RecipientInfo> {
        let output = self.env.encrypt_kem(
            self.kdf,
            self.wrap,
            &self.spki,
            self.ukm.as_deref(),
            content_encryption_key,
        )?;
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
