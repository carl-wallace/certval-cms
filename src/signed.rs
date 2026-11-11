//! Building SignedData (RFC 5652, section 5).
//!
//! Each signer's private key is a [`SigningCredential`], passed to the builder or found by a
//! registered [`SigningCredentialSource`] by signer identifier, email address or subject. The message digest, and the digest
//! a credential signs when it signs digests, are computed by the environment's `PkiEnvironment`, so
//! that hashing goes through its providers too.

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier,
        SignerInfo, SignerInfos,
    },
};
use const_oid::{
    db::{
        fips202::{ID_SHAKE_128, ID_SHAKE_256},
        fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87},
        fips205::{
            ID_SLH_DSA_SHAKE_128_F, ID_SLH_DSA_SHAKE_128_S, ID_SLH_DSA_SHAKE_192_F,
            ID_SLH_DSA_SHAKE_192_S, ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHAKE_256_S,
            ID_SLH_DSA_SHA_2_128_F, ID_SLH_DSA_SHA_2_128_S, ID_SLH_DSA_SHA_2_192_F,
            ID_SLH_DSA_SHA_2_192_S, ID_SLH_DSA_SHA_2_256_F, ID_SLH_DSA_SHA_2_256_S,
        },
        rfc5911::{
            ID_AA_SIGNING_CERTIFICATE_V_2, ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST,
            ID_SIGNED_DATA, ID_SIGNING_TIME,
        },
        rfc5912::{
            ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
            ID_EC_PUBLIC_KEY, ID_RSASSA_PSS, ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512,
            RSA_ENCRYPTION, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
            SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
        },
    },
    ObjectIdentifier,
};
use core::marker::PhantomData;
use der::{
    asn1::{Any, BitString, OctetString, SetOfVec},
    Decode, Encode, Tag,
};
use log::debug;
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use x509_cert::{attr::Attribute, name::Name, time::Time, Certificate};

use crate::credential::CredentialOrigin;
use crate::environment::{hash, CmsEnvironment};
use crate::environment_traits::{
    SharedSigningCredential, SigningCredential, SigningCredentialLookup, SigningCredentialSource,
    SigningKey,
};
use crate::error::{Error, Result};
use crate::ess::{EssCertIdV2, IssuerSerial, SigningCertificateV2};
use crate::recipient::recipient_identifier;
use crate::vetting::{key_usage_permits, KeyUse};
use certval::PathValidationStatus;

/// A digest algorithm for a signer (RFC 5754).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHAKE128 with a 256-bit output (RFC 8702), the digest RFC 9814 pairs with SLH-DSA's
    /// SHAKE-128 parameter sets. Computing it needs certval's `pqc` feature.
    Shake128,
    /// SHAKE256 with a 512-bit output (RFC 8702), the digest RFC 9814 pairs with SLH-DSA's
    /// SHAKE-192 and SHAKE-256 parameter sets. Computing it needs certval's `pqc` feature.
    Shake256,
}

impl DigestAlgorithm {
    /// The size of the algorithm's output in bits.
    pub fn bits(self) -> usize {
        match self {
            DigestAlgorithm::Sha256 => 256,
            DigestAlgorithm::Sha384 => 384,
            DigestAlgorithm::Sha512 => 512,
            DigestAlgorithm::Shake128 => 256,
            DigestAlgorithm::Shake256 => 512,
        }
    }

    /// The algorithm's object identifier.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            DigestAlgorithm::Sha256 => ID_SHA_256,
            DigestAlgorithm::Sha384 => ID_SHA_384,
            DigestAlgorithm::Sha512 => ID_SHA_512,
            DigestAlgorithm::Shake128 => ID_SHAKE_128,
            DigestAlgorithm::Shake256 => ID_SHAKE_256,
        }
    }

    /// The algorithm identifier, with parameters absent (RFC 5754, section 2).
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// The digest algorithm an algorithm identifier identifies.
    pub fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Shake128,
            DigestAlgorithm::Shake256,
        ]
        .into_iter()
        .find(|d| d.oid() == oid)
    }
}

/// The signature algorithm a signer uses by default with `cert`'s key and `digest`: PKCS #1 v1.5
/// for an RSA key, ECDSA for an EC key, and pure ML-DSA or SLH-DSA for an ML-DSA or SLH-DSA key,
/// which hash nothing themselves. RSASSA-PSS is chosen by passing [`rsa_pss`] to the signer instead.
pub fn default_signature_algorithm(
    cert: &Certificate,
    digest: DigestAlgorithm,
) -> Result<AlgorithmIdentifierOwned> {
    default_signature_algorithm_for_key(cert.tbs_certificate().subject_public_key_info(), digest)
}

/// [`default_signature_algorithm`] for the key `spki`, which no certificate need contain yet.
pub(crate) fn default_signature_algorithm_for_key(
    spki: &SubjectPublicKeyInfoOwned,
    digest: DigestAlgorithm,
) -> Result<AlgorithmIdentifierOwned> {
    let key_alg = spki.algorithm.oid;
    if slh_dsa_digest(key_alg).is_some() {
        return Ok(AlgorithmIdentifierOwned {
            oid: key_alg,
            parameters: None,
        });
    }
    let (oid, parameters) = match (key_alg, digest) {
        (RSA_ENCRYPTION, DigestAlgorithm::Sha256) => {
            (SHA_256_WITH_RSA_ENCRYPTION, Some(Any::null()))
        }
        (RSA_ENCRYPTION, DigestAlgorithm::Sha384) => {
            (SHA_384_WITH_RSA_ENCRYPTION, Some(Any::null()))
        }
        (RSA_ENCRYPTION, DigestAlgorithm::Sha512) => {
            (SHA_512_WITH_RSA_ENCRYPTION, Some(Any::null()))
        }
        (ID_EC_PUBLIC_KEY, DigestAlgorithm::Sha256) => (ECDSA_WITH_SHA_256, None),
        (ID_EC_PUBLIC_KEY, DigestAlgorithm::Sha384) => (ECDSA_WITH_SHA_384, None),
        (ID_EC_PUBLIC_KEY, DigestAlgorithm::Sha512) => (ECDSA_WITH_SHA_512, None),
        (ID_ML_DSA_44, _) | (ID_ML_DSA_65, _) | (ID_ML_DSA_87, _) => (key_alg, None),
        _ => return Err(Error::Unrecognized),
    };
    Ok(AlgorithmIdentifierOwned { oid, parameters })
}

/// RSASSA-PSS with `digest`, MGF1 with the same hash, and a salt the length of the hash (RFC 4055).
pub fn rsa_pss(digest: DigestAlgorithm) -> Result<AlgorithmIdentifierOwned> {
    use rsa::pkcs1::RsaPssParams;
    let params = match digest {
        DigestAlgorithm::Sha256 => RsaPssParams::new::<sha2::Sha256>(32).to_der()?,
        DigestAlgorithm::Sha384 => RsaPssParams::new::<sha2::Sha384>(48).to_der()?,
        DigestAlgorithm::Sha512 => RsaPssParams::new::<sha2::Sha512>(64).to_der()?,
        // RFC 8702's RSASSA-PSS with SHAKE uses identifiers of its own, which are not offered.
        DigestAlgorithm::Shake128 | DigestAlgorithm::Shake256 => return Err(Error::Unrecognized),
    };
    Ok(AlgorithmIdentifierOwned {
        oid: ID_RSASSA_PSS,
        parameters: Some(Any::from_der(&params)?),
    })
}

/// The digest algorithm `signature_algorithm` uses: the hash a sha*WithRSAEncryption or
/// ecdsa-with-SHA* identifier names, or RSASSA-PSS's hashAlgorithm parameter. `None` for an
/// algorithm using none: ML-DSA, which hashes nothing itself, and rsaEncryption, which leaves the
/// hash to the SignerInfo's digestAlgorithm (RFC 3370, section 3.2).
pub(crate) fn signature_algorithm_digest(
    signature_algorithm: &AlgorithmIdentifierOwned,
) -> Result<Option<ObjectIdentifier>> {
    let oid = match signature_algorithm.oid {
        SHA_224_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_224 => ID_SHA_224,
        SHA_256_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_256 => ID_SHA_256,
        SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => ID_SHA_384,
        SHA_512_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_512 => ID_SHA_512,
        ID_RSASSA_PSS => {
            let params = signature_algorithm.parameters.as_ref().ok_or_else(|| {
                Error::InvalidInput(String::from("RSASSA-PSS without parameters"))
            })?;
            rsa::pkcs1::RsaPssParamsOwned::from_der(&params.to_der()?)?
                .hash
                .oid
        }
        _ => return Ok(None),
    };
    Ok(Some(oid))
}

/// The digest a signer uses with `signature_algorithm` (RFC 5754, section 3): the one the
/// algorithm uses, which `chosen` must then be; otherwise `chosen`, or when neither says, SHA-512
/// for ML-DSA (RFC 9881) and SHA-256 for the rest.
pub(crate) fn signer_digest(
    signature_algorithm: &AlgorithmIdentifierOwned,
    chosen: Option<DigestAlgorithm>,
) -> Result<DigestAlgorithm> {
    let Some(used) = signature_algorithm_digest(signature_algorithm)? else {
        if let Some((bits, paired)) = slh_dsa_digest(signature_algorithm.oid) {
            // RFC 9814, section 4: with signed attributes, a digest at least twice the size of the
            // hash in the SLH-DSA tree, by default the one its table pairs with the parameter set.
            let digest = chosen.unwrap_or(paired);
            if digest.bits() < bits {
                return Err(Error::InvalidInput(format!(
                    "a {digest:?} digest with an SLH-DSA parameter set needing {bits} bits"
                )));
            }
            return Ok(digest);
        }
        let default = match signature_algorithm.oid {
            ID_ML_DSA_44 | ID_ML_DSA_65 | ID_ML_DSA_87 => DigestAlgorithm::Sha512,
            _ => DigestAlgorithm::Sha256,
        };
        return Ok(chosen.unwrap_or(default));
    };
    if let Some(chosen) = chosen {
        if chosen.oid() != used {
            return Err(Error::InvalidInput(format!(
                "a {chosen:?} digest with a signature algorithm using {used}"
            )));
        }
    }
    DigestAlgorithm::from_oid(used).ok_or(Error::Unrecognized)
}

/// For the SLH-DSA parameter set `oid`, the smallest digest in bits RFC 9814 (section 4) allows with
/// signed attributes, twice the size of the hash in its tree, and the digest its table pairs with
/// the set; `None` for any other algorithm.
pub(crate) fn slh_dsa_digest(oid: ObjectIdentifier) -> Option<(usize, DigestAlgorithm)> {
    match oid {
        ID_SLH_DSA_SHA_2_128_S | ID_SLH_DSA_SHA_2_128_F => Some((256, DigestAlgorithm::Sha256)),
        ID_SLH_DSA_SHA_2_192_S | ID_SLH_DSA_SHA_2_192_F => Some((384, DigestAlgorithm::Sha512)),
        ID_SLH_DSA_SHA_2_256_S | ID_SLH_DSA_SHA_2_256_F => Some((512, DigestAlgorithm::Sha512)),
        ID_SLH_DSA_SHAKE_128_S | ID_SLH_DSA_SHAKE_128_F => Some((256, DigestAlgorithm::Shake128)),
        ID_SLH_DSA_SHAKE_192_S | ID_SLH_DSA_SHAKE_192_F => Some((384, DigestAlgorithm::Shake256)),
        ID_SLH_DSA_SHAKE_256_S | ID_SLH_DSA_SHAKE_256_F => Some((512, DigestAlgorithm::Shake256)),
        _ => None,
    }
}

/// A [`SigningCredential`] around any [`signature::Signer`] that knows its signature algorithm, e.g.
/// one a hardware token or platform key store implements, so that it can sign SignedData unchanged.
///
/// The signer hashes and signs the message itself, with the algorithm it reports, which is the
/// signature algorithm it prefers; asked to sign with another, it declines. The certificate is not
/// checked against the signer's key: a mismatch is a signature the certificate does not verify.
pub struct SignerCredential<S, Sig> {
    certificate: Certificate,
    signer: S,
    _signature: PhantomData<fn() -> Sig>,
}

impl<S, Sig> core::fmt::Debug for SignerCredential<S, Sig> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignerCredential")
            .field(
                "subject",
                &format_args!("{}", self.certificate.tbs_certificate().subject()),
            )
            .finish()
    }
}

impl<S, Sig> SignerCredential<S, Sig> {
    /// A credential signing with `signer`, identified by `certificate`.
    pub fn new(certificate: Certificate, signer: S) -> Self {
        Self {
            certificate,
            signer,
            _signature: PhantomData,
        }
    }
}

impl<S, Sig> SigningCredential for SignerCredential<S, Sig>
where
    S: signature::Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn preferred_signature_algorithm(
        &self,
        _digest: DigestAlgorithm,
    ) -> Option<AlgorithmIdentifierOwned> {
        self.signer.signature_algorithm_identifier().ok()
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let own = self
            .signer
            .signature_algorithm_identifier()
            .map_err(|e| Error::Crypto(format!("{e}")))?;
        if own != *alg {
            return Err(Error::Unrecognized);
        }
        let signature = self
            .signer
            .try_sign(message)
            .map_err(|e| Error::Crypto(format!("{e}")))?;
        Ok(signature.to_bitstring()?.raw_bytes().to_vec())
    }
}

/// A [`signature::Signer`] over a [`SigningKey`], for the builders that take one, such as
/// x509-cert's certificate, request and CRL builders and x509-ocsp's request and response builders,
/// so that a key any provider holds can sign certificates, requests, CRLs and OCSP responses. Every
/// [`SigningCredential`] is a [`SigningKey`], so a credential is taken as it is; a key with no
/// certificate yet, e.g. a [`SoftwareKey`](crate::SoftwareKey), signs its own request or a
/// self-signed certificate.
///
/// The key signs with one signature algorithm, which the signer reports, and its public key is the
/// signer's verifying key, so an issuer's authority key identifier, or a request's subject key, can
/// be taken from it. A key that signs only digests is given the digest, computed by the
/// environment's `PkiEnvironment`, as SignedData signing does.
pub struct CredentialSigner<'a, K: SigningKey + ?Sized = dyn SigningCredential + 'a> {
    env: &'a CmsEnvironment,
    key: &'a K,
    signature_algorithm: AlgorithmIdentifierOwned,
    digest: DigestAlgorithm,
}

impl<K: SigningKey + ?Sized> core::fmt::Debug for CredentialSigner<'_, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredentialSigner")
            .field("key", &self.key.public_key().algorithm.oid)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("digest", &self.digest)
            .finish()
    }
}

impl<'a, K: SigningKey + ?Sized> CredentialSigner<'a, K> {
    /// A signer for `key` with `digest` and the signature algorithm the key prefers for it, or
    /// else the one [`default_signature_algorithm`] chooses for it. A key preferring an algorithm
    /// that uses another digest, as a [`SignerCredential`] with a fixed algorithm may, is
    /// [`Error::InvalidInput`].
    pub fn new(env: &'a CmsEnvironment, key: &'a K, digest: DigestAlgorithm) -> Result<Self> {
        let signature_algorithm = match key.preferred_signature_algorithm(digest) {
            Some(alg) => alg,
            None => default_signature_algorithm_for_key(key.public_key(), digest)?,
        };
        Self::with_algorithm(env, key, digest, signature_algorithm)
    }

    /// A signer for `key` with `signature_algorithm`, e.g. RSASSA-PSS from [`rsa_pss`]. `digest`
    /// is the digest a key that signs only digests is given; one other than the digest
    /// `signature_algorithm` uses is [`Error::InvalidInput`].
    pub fn with_algorithm(
        env: &'a CmsEnvironment,
        key: &'a K,
        digest: DigestAlgorithm,
        signature_algorithm: AlgorithmIdentifierOwned,
    ) -> Result<Self> {
        signer_digest(&signature_algorithm, Some(digest))?;
        Ok(Self {
            env,
            key,
            signature_algorithm,
            digest,
        })
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let alg = &self.signature_algorithm;
        match self.key.sign_message(self.env, alg, message) {
            Err(Error::Unrecognized) => {
                let pe = self.env.pki_environment().ok_or(Error::NoPkiEnvironment)?;
                let digest = hash(pe, &self.digest.algorithm_identifier(), message)?;
                self.key.sign_digest(self.env, alg, &digest)
            }
            result => result,
        }
    }
}

/// A signature a [`CredentialSigner`] made, as the signature value's octets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSignature(Vec<u8>);

impl CredentialSignature {
    /// The signature value's octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SignatureBitStringEncoding for CredentialSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

impl<K: SigningKey + ?Sized> signature::Signer<CredentialSignature> for CredentialSigner<'_, K> {
    fn try_sign(
        &self,
        message: &[u8],
    ) -> core::result::Result<CredentialSignature, signature::Error> {
        self.sign(message)
            .map(CredentialSignature)
            .map_err(signature::Error::from_source)
    }
}

impl<K: SigningKey + ?Sized> DynSignatureAlgorithmIdentifier for CredentialSigner<'_, K> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(self.signature_algorithm.clone())
    }
}

impl<K: SigningKey + ?Sized> signature::Keypair for CredentialSigner<'_, K> {
    type VerifyingKey = SignerPublicKey;

    fn verifying_key(&self) -> SignerPublicKey {
        SignerPublicKey(self.key.public_key().clone())
    }
}

/// The public key of a [`CredentialSigner`]'s key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerPublicKey(pub SubjectPublicKeyInfoOwned);

impl EncodePublicKey for SignerPublicKey {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        Ok(der::Document::encode_msg(&self.0)?)
    }
}

/// A source holding one signing credential, which it returns for a lookup that identifies its
/// certificate.
pub struct SingleSigningCredential(SharedSigningCredential);

impl core::fmt::Debug for SingleSigningCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SingleSigningCredential")
            .field(
                "subject",
                &format_args!("{}", self.0.certificate().tbs_certificate().subject()),
            )
            .finish()
    }
}

impl SingleSigningCredential {
    /// A source for `credential` alone.
    pub fn new(credential: SharedSigningCredential) -> Self {
        Self(credential)
    }
}

impl SigningCredentialSource for SingleSigningCredential {
    fn find_signing_credentials(
        &self,
        _env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>> {
        if lookup.matches(self.0.certificate()) {
            Ok(vec![self.0.clone()])
        } else {
            Ok(vec![])
        }
    }
}

/// The signer identifier for a certificate: its subject key identifier extension if it has one,
/// otherwise its issuer and serial number.
pub fn signer_identifier(cert: &Certificate) -> Result<SignerIdentifier> {
    Ok(match recipient_identifier(cert)? {
        cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(iasn) => {
            SignerIdentifier::IssuerAndSerialNumber(iasn)
        }
        cms::enveloped_data::RecipientIdentifier::SubjectKeyIdentifier(skid) => {
            SignerIdentifier::SubjectKeyIdentifier(skid)
        }
    })
}

/// Whether `sid` names `cert`: its issuer and serial number, or its subject key identifier.
pub fn signer_matches(sid: &SignerIdentifier, cert: &Certificate) -> bool {
    let rid = match sid {
        SignerIdentifier::IssuerAndSerialNumber(iasn) => {
            cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(iasn.clone())
        }
        SignerIdentifier::SubjectKeyIdentifier(skid) => {
            cms::enveloped_data::RecipientIdentifier::SubjectKeyIdentifier(skid.clone())
        }
    };
    crate::credential::recipient_matches(&rid, cert)
}

/// How a signer's key is found.
enum SignerKey<'c> {
    Explicit(&'c dyn SigningCredential),
    Identifier(SignerIdentifier),
    EmailAddress(String),
    Subject(Name),
}

impl core::fmt::Debug for SignerKey<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignerKey::Explicit(credential) => f
                .debug_tuple("Explicit")
                .field(&format_args!(
                    "{}",
                    credential.certificate().tbs_certificate().subject()
                ))
                .finish(),
            SignerKey::Identifier(sid) => f.debug_tuple("Identifier").field(sid).finish(),
            SignerKey::EmailAddress(email) => f.debug_tuple("EmailAddress").field(email).finish(),
            SignerKey::Subject(subject) => f
                .debug_tuple("Subject")
                .field(&format_args!("{subject}"))
                .finish(),
        }
    }
}

/// One signer of a SignedData: its key, digest algorithm, signature algorithm and any signed
/// attributes beyond the ones the builder adds.
#[derive(Debug)]
pub struct Signer<'c> {
    key: SignerKey<'c>,
    digest: Option<DigestAlgorithm>,
    signature_algorithm: Option<AlgorithmIdentifierOwned>,
    signed_attributes: Vec<Attribute>,
    signing_time: Option<Time>,
    ess_cert_id: bool,
    issuer_and_serial: bool,
}

impl<'c> Signer<'c> {
    fn with(key: SignerKey<'c>) -> Self {
        Self {
            key,
            digest: None,
            signature_algorithm: None,
            signed_attributes: vec![],
            signing_time: None,
            ess_cert_id: true,
            issuer_and_serial: false,
        }
    }

    /// A signer whose key is `credential`.
    pub fn explicit(credential: &'c dyn SigningCredential) -> Self {
        Self::with(SignerKey::Explicit(credential))
    }

    /// A signer whose key a registered [`SigningCredentialSource`] finds by `sid`.
    pub fn by_identifier(sid: SignerIdentifier) -> Self {
        Self::with(SignerKey::Identifier(sid))
    }

    /// A signer whose key is the first a registered [`SigningCredentialSource`] finds for a
    /// certificate containing `email` and permitting signing (see
    /// [`CmsEnvironment::find_signing_credentials`]). To choose among several, find them and pass
    /// the one chosen to [`explicit`](Self::explicit).
    pub fn by_email_address(email: impl Into<String>) -> Self {
        Self::with(SignerKey::EmailAddress(email.into()))
    }

    /// A signer whose key is the first a registered [`SigningCredentialSource`] finds for a
    /// certificate with subject `subject` permitting signing, as
    /// [`by_email_address`](Self::by_email_address) finds one by email address.
    pub fn by_subject(subject: Name) -> Self {
        Self::with(SignerKey::Subject(subject))
    }

    /// The digest algorithm, which must be the one the signature algorithm uses, when it uses
    /// one (RFC 5754, section 3); unless set, that one, or for an algorithm hashing nothing itself,
    /// SHA-512 for ML-DSA (RFC 9881), the digest RFC 9814 pairs with an SLH-DSA parameter set
    /// (SHA-256 or SHA-512 for the SHA2 sets, SHAKE128 or SHAKE256 for the SHAKE sets), and SHA-256
    /// otherwise. For SLH-DSA, a
    /// digest shorter than RFC 9814 allows is refused.
    pub fn digest(mut self, digest: DigestAlgorithm) -> Self {
        self.digest = Some(digest);
        self
    }

    /// The signature algorithm, [`default_signature_algorithm`] for the key and the digest, or
    /// the one the credential prefers, unless set.
    pub fn signature_algorithm(mut self, alg: AlgorithmIdentifierOwned) -> Self {
        self.signature_algorithm = Some(alg);
        self
    }

    /// Adds a signed attribute beyond content-type and message-digest, which the builder adds;
    /// one of those two is refused when the message is built.
    pub fn signed_attribute(mut self, attribute: Attribute) -> Self {
        self.signed_attributes.push(attribute);
        self
    }

    /// Leaves out the ESSCertIDv2 of the signer's certificate, in a signing-certificate-v2
    /// attribute (RFC 5035), which is otherwise added to bind the certificate into the signature.
    pub fn without_ess_cert_id(mut self) -> Self {
        self.ess_cert_id = false;
        self
    }

    /// Identifies the signer by its certificate's issuer and serial number even when the
    /// certificate has a subject key identifier, for a verifier that matches signers that way
    /// only. Otherwise the subject key identifier is used when the certificate has one (see
    /// [`signer_identifier`]).
    pub fn identified_by_issuer_and_serial(mut self) -> Self {
        self.issuer_and_serial = true;
        self
    }

    /// Adds a signing-time attribute with `time`, which the caller supplies so that the builder
    /// needs no clock. It is encoded as RFC 5652, section 11.3 requires: UTCTime through 2049,
    /// GeneralizedTime after, whichever form `time` is in.
    pub fn signing_time(mut self, time: Time) -> Self {
        self.signing_time = Some(Time::from(time.to_date_time()));
        self
    }
}

/// Which certificates a SignedData carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IncludeCertificates {
    /// None.
    None,
    /// Each signer's certificate.
    Signers,
}

/// What a signer signed with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SignerReport {
    /// The signer identifier written to its SignerInfo.
    pub sid: SignerIdentifier,
    /// Where the signer's credential came from.
    pub credential: CredentialOrigin,
}

/// A built SignedData, with what each signer signed with.
#[derive(Debug)]
#[non_exhaustive]
pub struct BuiltSignedData {
    /// The SignedData, in a ContentInfo.
    pub content_info: ContentInfo,
    /// One report per signer, in the order the signers were added.
    pub signers: Vec<SignerReport>,
}

/// What a SignedData signs.
enum Content<'c> {
    /// Content carried in the message.
    Encapsulated(&'c [u8]),
    /// Content carried elsewhere (detached), hashed here.
    Detached(&'c [u8]),
    /// Content carried elsewhere and hashed elsewhere, with this algorithm.
    Digest(DigestAlgorithm, &'c [u8]),
}

impl core::fmt::Debug for Content<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Content::Encapsulated(content) => {
                write!(f, "Encapsulated(<{} octets>)", content.len())
            }
            Content::Detached(content) => write!(f, "Detached(<{} octets>)", content.len()),
            Content::Digest(alg, digest) => {
                write!(f, "Digest({alg:?}, <{} octets>)", digest.len())
            }
        }
    }
}

/// Builds SignedData, signed by one or more signers through a [`CmsEnvironment`], with the content
/// encapsulated or, with [`detached`](Self::detached) or [`from_digest`](Self::from_digest), carried
/// elsewhere.
#[derive(Debug)]
pub struct SignedDataBuilder<'c> {
    content_type: ObjectIdentifier,
    content: Content<'c>,
    signers: Vec<Signer<'c>>,
    include_certificates: IncludeCertificates,
    certificates: Vec<Certificate>,
}

impl<'c> SignedDataBuilder<'c> {
    /// A builder for SignedData encapsulating `content`, whose type is id-data unless set.
    pub fn new(content: &'c [u8]) -> Self {
        Self {
            content_type: ID_DATA,
            content: Content::Encapsulated(content),
            signers: vec![],
            include_certificates: IncludeCertificates::Signers,
            certificates: vec![],
        }
    }

    /// A builder for SignedData over content carried elsewhere and already hashed, as `digest` with
    /// `digest_alg`, e.g. content too large to hold. Every signer must use `digest_alg`.
    pub fn from_digest(digest_alg: DigestAlgorithm, digest: &'c [u8]) -> Self {
        let mut builder = Self::new(&[]);
        builder.content = Content::Digest(digest_alg, digest);
        builder
    }

    /// Leaves the content out of the message (RFC 5652, section 5.2: eContent absent), to be
    /// carried elsewhere. It is still hashed here for each signer's message digest.
    pub fn detached(&mut self) -> &mut Self {
        if let Content::Encapsulated(content) = self.content {
            self.content = Content::Detached(content);
        }
        self
    }

    /// Sets the content's type.
    pub fn content_type(&mut self, content_type: ObjectIdentifier) -> &mut Self {
        self.content_type = content_type;
        self
    }

    /// Adds a signer.
    pub fn add_signer(&mut self, signer: Signer<'c>) -> &mut Self {
        self.signers.push(signer);
        self
    }

    /// Which certificates to carry; each signer's, unless set.
    pub fn include_certificates(&mut self, include: IncludeCertificates) -> &mut Self {
        self.include_certificates = include;
        self
    }

    /// Adds a certificate to carry, e.g. an intermediate CA a recipient may lack.
    pub fn add_certificate(&mut self, cert: Certificate) -> &mut Self {
        self.certificates.push(cert);
        self
    }

    /// Signs and builds the SignedData, in a ContentInfo.
    pub fn build(&mut self, env: &CmsEnvironment) -> Result<BuiltSignedData> {
        if self.signers.is_empty() {
            return Err(Error::InvalidInput(String::from("no signers")));
        }
        let pe = env.pki_environment().ok_or(Error::NoPkiEnvironment)?;

        let mut digest_algorithms: Vec<AlgorithmIdentifierOwned> = vec![];
        let mut signer_infos = vec![];
        let mut reports = vec![];
        let mut certificates = self.certificates.clone();
        let mut skid_signer = false;
        for signer in &self.signers {
            let (held, origin) = match &signer.key {
                SignerKey::Explicit(credential) => {
                    (Held::Explicit(*credential), CredentialOrigin::Explicit)
                }
                SignerKey::Identifier(sid) => found(env, SigningCredentialLookup::Identifier(sid))?,
                SignerKey::EmailAddress(email) => {
                    found(env, SigningCredentialLookup::EmailAddress(email))?
                }
                SignerKey::Subject(subject) => {
                    found(env, SigningCredentialLookup::Subject(subject))?
                }
            };
            let credential = held.credential();
            let cert = credential.certificate();
            let sid = if signer.issuer_and_serial {
                SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: cert.tbs_certificate().issuer().clone(),
                    serial_number: cert.tbs_certificate().serial_number().clone(),
                })
            } else {
                signer_identifier(cert)?
            };
            skid_signer |= matches!(sid, SignerIdentifier::SubjectKeyIdentifier(_));
            let requested = signer.digest.unwrap_or(DigestAlgorithm::Sha256);
            let signature_algorithm = match &signer.signature_algorithm {
                Some(alg) => alg.clone(),
                None => match credential.preferred_signature_algorithm(requested) {
                    Some(alg) => alg,
                    None => default_signature_algorithm(cert, requested)?,
                },
            };
            let digest_algorithm = signer_digest(&signature_algorithm, signer.digest)?;
            let digest_alg = digest_algorithm.algorithm_identifier();
            if !digest_algorithms.contains(&digest_alg) {
                digest_algorithms.push(digest_alg.clone());
            }

            // RFC 5652, section 5.3: content-type and message-digest are required whenever signed
            // attributes are present, and they always are here.
            let message_digest = match self.content {
                Content::Encapsulated(content) | Content::Detached(content) => {
                    hash(pe, &digest_alg, content)?
                }
                Content::Digest(alg, digest) => {
                    if alg != digest_algorithm {
                        return Err(Error::InvalidInput(format!(
                            "a {digest_algorithm:?} signer of content hashed with {alg:?}"
                        )));
                    }
                    digest.to_vec()
                }
            };
            let mut attrs = vec![
                attribute(ID_CONTENT_TYPE, &self.content_type)?,
                attribute(ID_MESSAGE_DIGEST, &OctetString::new(message_digest)?)?,
            ];
            if let Some(time) = &signer.signing_time {
                attrs.push(attribute(ID_SIGNING_TIME, time)?);
            }
            if signer.ess_cert_id {
                // RFC 5035, section 3: an ESSCertIDv2 of the signer's certificate, its hash SHA-256,
                // the default, which is therefore not encoded.
                let sha256 = DigestAlgorithm::Sha256.algorithm_identifier();
                let cert_hash = hash(pe, &sha256, &cert.to_der()?)?;
                let signing_certificate = SigningCertificateV2 {
                    certs: vec![EssCertIdV2 {
                        hash_algorithm: None,
                        cert_hash: OctetString::new(cert_hash)?,
                        issuer_serial: Some(IssuerSerial::of(cert)),
                    }],
                    policies: None,
                };
                attrs.push(attribute(
                    ID_AA_SIGNING_CERTIFICATE_V_2,
                    &signing_certificate,
                )?);
            }
            // RFC 5652, section 11: one content-type and one message-digest attribute, which the
            // builder has added; a second of either is a message the verifier refuses.
            if let Some(attr) = signer
                .signed_attributes
                .iter()
                .find(|a| a.oid == ID_CONTENT_TYPE || a.oid == ID_MESSAGE_DIGEST)
            {
                return Err(Error::InvalidInput(format!(
                    "a {} signed attribute, which the builder adds",
                    attr.oid
                )));
            }
            attrs.extend(signer.signed_attributes.iter().cloned());
            let signed_attrs = SignedAttributes::try_from(attrs)?;

            // RFC 5652, section 5.4: the signature covers the DER encoding of the signed attributes
            // with an EXPLICIT SET OF tag.
            let to_be_signed = signed_attrs.to_der()?;
            let signature = match credential.sign_message(env, &signature_algorithm, &to_be_signed)
            {
                Err(Error::Unrecognized) => {
                    let digest = hash(pe, &digest_alg, &to_be_signed)?;
                    credential.sign_digest(env, &signature_algorithm, &digest)?
                }
                result => result?,
            };

            if self.include_certificates == IncludeCertificates::Signers
                && !certificates.contains(cert)
            {
                certificates.push(cert.clone());
            }
            signer_infos.push(SignerInfo {
                // RFC 5652, section 5.3: 1 for an issuer and serial number, 3 for a subject key
                // identifier.
                version: match sid {
                    SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
                    SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
                },
                sid: sid.clone(),
                digest_alg,
                signed_attrs: Some(signed_attrs),
                signature_algorithm,
                signature: OctetString::new(signature)?,
                unsigned_attrs: None,
            });
            reports.push(SignerReport {
                sid,
                credential: origin,
            });
        }

        let certificates = if certificates.is_empty() {
            None
        } else {
            Some(CertificateSet::try_from(
                certificates
                    .into_iter()
                    .map(CertificateChoices::Certificate)
                    .collect::<Vec<_>>(),
            )?)
        };
        let signed_data = SignedData {
            // RFC 5652, section 5.1: 3 if any signer is identified by subject key identifier or the
            // content is not id-data, otherwise 1. This builder carries no attribute or other
            // certificates and no other revocation information.
            version: if skid_signer || self.content_type != ID_DATA {
                CmsVersion::V3
            } else {
                CmsVersion::V1
            },
            digest_algorithms: SetOfVec::try_from(digest_algorithms)?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: self.content_type,
                econtent: match self.content {
                    Content::Encapsulated(content) => Some(Any::new(Tag::OctetString, content)?),
                    Content::Detached(_) | Content::Digest(..) => None,
                },
            },
            certificates,
            crls: None,
            signer_infos: SignerInfos::try_from(signer_infos)?,
        };
        Ok(BuiltSignedData {
            content_info: ContentInfo {
                content_type: ID_SIGNED_DATA,
                content: Any::from_der(&signed_data.to_der()?)?,
            },
            signers: reports,
        })
    }
}

/// A signer's credential, borrowed when passed in and shared when a source found it.
enum Held<'a> {
    Explicit(&'a dyn SigningCredential),
    Shared(SharedSigningCredential),
}

impl Held<'_> {
    fn credential(&self) -> &dyn SigningCredential {
        match self {
            Held::Explicit(c) => *c,
            Held::Shared(c) => c.as_ref(),
        }
    }
}

/// An attribute with one value.
pub(crate) fn attribute(oid: ObjectIdentifier, value: &impl Encode) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(Any::from_der(&value.to_der()?)?)?;
    Ok(Attribute { oid, values })
}

/// The first credential the environment's sources find for `lookup`, held for the builder. A
/// lookup by identifier names one certificate; when a source holds it but its key usage does not
/// permit signing, that is reported, as vetting reports it, rather than as no credential.
fn found<'c>(
    env: &CmsEnvironment,
    lookup: SigningCredentialLookup<'_>,
) -> Result<(Held<'c>, CredentialOrigin)> {
    let by_identifier = matches!(lookup, SigningCredentialLookup::Identifier(_));
    let (permitted, refused) = env.signing_credentials(lookup)?;
    match permitted.into_iter().next() {
        Some((credential, index)) => {
            Ok((Held::Shared(credential), CredentialOrigin::Source(index)))
        }
        None => {
            if by_identifier && refused {
                return Err(Error::Certval(certval::Error::PathValidation(
                    PathValidationStatus::InvalidKeyUsage,
                )));
            }
            Err(Error::NoMatchingSigner)
        }
    }
}

impl CmsEnvironment {
    /// Every credential the registered sources return for `lookup`, in the order registered, each
    /// with its source's position, whose certificate's key usage permits signing: digitalSignature
    /// or nonRepudiation. A certificate whose key usage extension does not decode is passed over.
    /// Any narrower choice, e.g. by extended key usage, is the caller's.
    pub fn find_signing_credentials(
        &self,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<(SharedSigningCredential, usize)>> {
        Ok(self.signing_credentials(lookup)?.0)
    }

    /// [`find_signing_credentials`](Self::find_signing_credentials), and whether any credential
    /// the sources returned was left out for its key usage.
    pub(crate) fn signing_credentials(
        &self,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<(Vec<(SharedSigningCredential, usize)>, bool)> {
        let mut found = vec![];
        let mut refused = false;
        for (index, source) in self.signing_credential_sources.iter().enumerate() {
            for credential in source.find_signing_credentials(self, lookup)? {
                match key_usage_permits(credential.certificate(), KeyUse::Signing) {
                    Ok(true) => found.push((credential, index)),
                    Ok(false) => refused = true,
                    Err(e) => debug!("passing over a signing credential: {e}"),
                }
            }
        }
        Ok((found, refused))
    }

    /// Registers a source of signing credentials after those already registered.
    pub fn add_signing_credential_source<S: SigningCredentialSource + Send + Sync + 'static>(
        &mut self,
        source: S,
    ) {
        self.signing_credential_sources.push(Box::new(source));
    }

    /// Removes every source of signing credentials.
    pub fn clear_signing_credential_sources(&mut self) {
        self.signing_credential_sources.clear();
    }
}
