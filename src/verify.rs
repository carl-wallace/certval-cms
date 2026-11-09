//! Verifying SignedData (RFC 5652, section 5.6), and reading the certificates of a SignedData that
//! has no signers.
//!
//! Each signer's certificate is found among the message's certificates or through the registered
//! [`SignerCertificateSource`]s; its signature, and the message digest it covers, are checked with
//! the environment's `PkiEnvironment`, so that signature verification and hashing go through its
//! providers; and its certificate is vetted when settings are given.

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

use certval::{CertificationPathSettings, PkiEnvironment};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedAttributes, SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::{
    db::{
        rfc5911::{
            ID_AA_SIGNING_CERTIFICATE_V_2, ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST,
            ID_SIGNED_DATA,
        },
        rfc5912::{
            ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
            SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
        },
    },
    ObjectIdentifier,
};
use der::{
    asn1::{Any, BitString, OctetString},
    Decode, Encode,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::environment::CmsEnvironment;
use crate::environment_traits::SignerCertificateSource;
use crate::error::{Error, Result};
use crate::ess::SigningCertificateV2;
use crate::signed::{signature_algorithm_digest, signer_matches};
use crate::vetting::{KeyUse, Vetting};

/// Where a signer's certificate came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertificateOrigin {
    /// The message's certificates.
    Message,
    /// The source registered at this position on the environment.
    Source(usize),
}

/// Which signers must verify for a SignedData to verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignerPolicy {
    /// Every signer.
    All,
    /// At least one signer; the others' failures are reported.
    Any,
}

/// A signer whose signature verified.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VerifiedSigner {
    /// The signer identifier.
    pub sid: SignerIdentifier,
    /// The signer's certificate.
    pub certificate: Certificate,
    /// Where the certificate came from.
    pub certificate_origin: CertificateOrigin,
    /// Whether the certificate was vetted.
    pub vetting: Vetting,
    /// The signed attributes, which the signature covered, if the signer had any.
    pub signed_attributes: Option<SignedAttributes>,
    /// CA certificates from the message that the validated path needed and the `PkiEnvironment`
    /// did not have; a caller may add them to it. Empty when the `PkiEnvironment` had a path.
    pub message_ca_certificates: Vec<Certificate>,
}

/// A verified SignedData.
#[non_exhaustive]
pub struct VerifiedSignedData {
    /// The encapsulated content's type, so that nested content can be processed in turn.
    pub content_type: ObjectIdentifier,
    /// The content: the encapsulated content, or the detached content that was supplied.
    pub content: Vec<u8>,
    /// The signers that verified, in the order of their SignerInfos.
    pub signers: Vec<VerifiedSigner>,
    /// Under [`SignerPolicy::Any`], the signers that did not verify, with why.
    pub failed: Vec<(SignerIdentifier, Error)>,
}

/// The certificates carried by a SignedData with no signers, e.g. the certificates-only message a
/// SCEP response carries. Nothing is verified: each certificate is to be vetted on its own before
/// its key is relied on. A SignedData that has signers is verified with
/// [`CmsEnvironment::verify_signed_data`] instead, and is refused here.
pub fn certificates_only(content_info: &ContentInfo) -> Result<Vec<Certificate>> {
    let signed_data = signed_data(content_info)?;
    if !signed_data.signer_infos.0.is_empty() {
        return Err(Error::InvalidInput(String::from(
            "a SignedData with signers, which is to be verified",
        )));
    }
    Ok(certificates(&signed_data))
}

fn signed_data(content_info: &ContentInfo) -> Result<SignedData> {
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(Error::InvalidInput(format!(
            "{} is not SignedData",
            content_info.content_type
        )));
    }
    Ok(SignedData::from_der(&content_info.content.to_der()?)?)
}

fn certificates(signed_data: &SignedData) -> Vec<Certificate> {
    signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert.clone()),
            _ => None,
        })
        .collect()
}

/// The one value of the one attribute of type `oid`, which RFC 5652, section 11 requires of
/// content-type and message-digest.
fn single_value(attrs: &SignedAttributes, oid: ObjectIdentifier) -> Result<&Any> {
    let mut found = attrs.iter().filter(|a| a.oid == oid);
    let (Some(attr), None) = (found.next(), found.next()) else {
        return Err(Error::InvalidInput(format!(
            "not exactly one {oid} signed attribute"
        )));
    };
    let mut values = attr.values.iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(Error::InvalidInput(format!(
            "a {oid} signed attribute without exactly one value"
        )));
    };
    Ok(value)
}

/// The one value of the attribute of type `oid`, if there is one.
fn optional_single_value(attrs: &SignedAttributes, oid: ObjectIdentifier) -> Result<Option<&Any>> {
    if attrs.iter().any(|a| a.oid == oid) {
        single_value(attrs, oid).map(Some)
    } else {
        Ok(None)
    }
}

/// Checks that a signing-certificate-v2 attribute (RFC 5035), if present, identifies `cert`: its
/// first ESSCertIDv2's hash is the certificate's, computed with the `PkiEnvironment`, and its issuer
/// and serial number, if present, are the certificate's. The attribute is not required. Its policies
/// field is not applied, and a signing-certificate attribute (RFC 2634, a SHA-1 hash) is not
/// checked.
fn check_ess_cert_id(
    pe: &PkiEnvironment,
    attrs: &SignedAttributes,
    cert: &Certificate,
) -> Result<()> {
    let Some(value) = optional_single_value(attrs, ID_AA_SIGNING_CERTIFICATE_V_2)? else {
        return Ok(());
    };
    let mismatch = || {
        Error::InvalidInput(String::from(
            "the signing-certificate-v2 attribute does not identify the signer's certificate",
        ))
    };
    let signing_certificate = SigningCertificateV2::from_der(&value.to_der()?)?;
    let id = signing_certificate.certs.first().ok_or_else(mismatch)?;
    let hash = pe.calculate_hash(pe, &id.hash_algorithm(), &cert.to_der()?)?;
    if hash != id.cert_hash.as_bytes()
        || id.issuer_serial.as_ref().is_some_and(|is| !is.names(cert))
    {
        return Err(mismatch());
    }
    Ok(())
}

/// The signature algorithm to verify with. A SignerInfo may name rsaEncryption, the key's algorithm,
/// for PKCS #1 v1.5 (RFC 3370, section 3.2), as OpenSSL does; that is the signature algorithm for
/// the signer's digest algorithm.
fn signature_algorithm(signer: &SignerInfo) -> AlgorithmIdentifierOwned {
    if signer.signature_algorithm.oid != RSA_ENCRYPTION {
        return signer.signature_algorithm.clone();
    }
    let oid = match signer.digest_alg.oid {
        ID_SHA_256 => SHA_256_WITH_RSA_ENCRYPTION,
        ID_SHA_384 => SHA_384_WITH_RSA_ENCRYPTION,
        ID_SHA_512 => SHA_512_WITH_RSA_ENCRYPTION,
        _ => return signer.signature_algorithm.clone(),
    };
    AlgorithmIdentifierOwned {
        oid,
        parameters: Some(Any::null()),
    }
}

impl CmsEnvironment {
    /// Registers a source of signer certificates after those already registered.
    pub fn add_signer_certificate_source<S: SignerCertificateSource + Send + Sync + 'static>(
        &mut self,
        source: S,
    ) {
        self.signer_certificate_sources.push(Box::new(source));
    }

    /// Removes every source of signer certificates.
    pub fn clear_signer_certificate_sources(&mut self) {
        self.signer_certificate_sources.clear();
    }

    /// The certificate `sid` names: from `message_certs` if one matches, otherwise the first the
    /// registered sources return.
    fn find_signer_certificate(
        &self,
        sid: &SignerIdentifier,
        message_certs: &[Certificate],
    ) -> Result<(Certificate, CertificateOrigin)> {
        if let Some(cert) = message_certs.iter().find(|c| signer_matches(sid, c)) {
            return Ok((cert.clone(), CertificateOrigin::Message));
        }
        for (index, source) in self.signer_certificate_sources.iter().enumerate() {
            if let Some(cert) = source.find_signer_certificate(self, sid)? {
                return Ok((cert, CertificateOrigin::Source(index)));
            }
        }
        Err(Error::NoMatchingSigner)
    }

    /// Verifies one SignerInfo over `content`, of type `content_type`.
    fn verify_signer(
        &self,
        signer: &SignerInfo,
        content_type: ObjectIdentifier,
        content: &[u8],
        message_certs: &[Certificate],
        settings: Option<&CertificationPathSettings>,
    ) -> Result<VerifiedSigner> {
        let pe = self.pki_environment().ok_or(Error::NoPkiEnvironment)?;
        let (certificate, certificate_origin) =
            self.find_signer_certificate(&signer.sid, message_certs)?;

        // RFC 5754, section 3: the digest algorithm is the one the signature algorithm uses, when
        // it uses one. The verifiers this crate interoperates with hash the signed attributes with
        // digestAlgorithm, so a pair that disagrees is refused rather than verified either way.
        let signature_alg = signature_algorithm(signer);
        if let Some(used) = signature_algorithm_digest(&signature_alg)? {
            if used != signer.digest_alg.oid {
                return Err(Error::InvalidInput(format!(
                    "a {} digestAlgorithm with a {} signatureAlgorithm",
                    signer.digest_alg.oid, signer.signature_algorithm.oid
                )));
            }
        }

        // RFC 5652, section 5.4: with signed attributes, the signature covers their DER encoding
        // with an EXPLICIT SET OF tag, and they carry the content's type and digest; without them,
        // it covers the content itself, which must then be id-data.
        let to_be_verified = match &signer.signed_attrs {
            Some(attrs) => {
                let attr_type =
                    ObjectIdentifier::from_der(&single_value(attrs, ID_CONTENT_TYPE)?.to_der()?)?;
                if attr_type != content_type {
                    return Err(Error::InvalidInput(format!(
                        "a content-type attribute of {attr_type} for {content_type} content"
                    )));
                }
                let digest =
                    OctetString::from_der(&single_value(attrs, ID_MESSAGE_DIGEST)?.to_der()?)?;
                if pe.calculate_hash(pe, &signer.digest_alg, content)? != digest.as_bytes() {
                    return Err(Error::Crypto(String::from(
                        "the message digest does not match the content",
                    )));
                }
                check_ess_cert_id(pe, attrs, &certificate)?;
                attrs.to_der()?
            }
            None => {
                if content_type != ID_DATA {
                    return Err(Error::InvalidInput(format!(
                        "{content_type} content without signed attributes"
                    )));
                }
                content.to_vec()
            }
        };
        // No registered implementation verifying the algorithm is a decline, not a bad signature.
        pe.verify_signature_message(
            pe,
            &to_be_verified,
            &BitString::from_bytes(signer.signature.as_bytes())?,
            &signature_alg,
            certificate.tbs_certificate().subject_public_key_info(),
        )
        .map_err(|e| match e {
            certval::Error::Unrecognized => Error::Unrecognized,
            e => Error::Certval(e),
        })?;

        let (vetting, message_ca_certificates) =
            self.vet_with_candidates(&certificate, KeyUse::Signing, settings, message_certs)?;
        Ok(VerifiedSigner {
            sid: signer.sid.clone(),
            certificate,
            certificate_origin,
            vetting,
            signed_attributes: signer.signed_attrs.clone(),
            message_ca_certificates,
        })
    }

    /// Verifies a SignedData in a ContentInfo.
    ///
    /// For each SignerInfo: the signer's certificate is found among the message's certificates or
    /// through the registered [`SignerCertificateSource`]s; the content-type and message-digest
    /// attributes are checked against the content; the signature is verified with the
    /// `PkiEnvironment`'s providers, as is a signing-certificate-v2 attribute (RFC 5035) if the
    /// signer has one; and, with `settings`, the certificate is vetted for signing
    /// (see [`vet_certificate`](Self::vet_certificate)). When the `PkiEnvironment` has no path for
    /// it, paths are prepared through the CA certificates the message carries, and those a validated
    /// path needed are reported in [`VerifiedSigner::message_ca_certificates`]; the
    /// `PkiEnvironment` is not changed.
    ///
    /// The signing-certificate-v2 attribute's policies field is not applied: the policies a signer's
    /// certificate must satisfy are set in `settings`, and certval enforces them in path validation.
    /// The original signing-certificate attribute (RFC 2634), which identifies the certificate by its
    /// SHA-1 hash, is not checked.
    ///
    /// Content carried outside the message (detached, eContent absent) is passed as
    /// `detached_content`, and only then: a detached message without it, or content passed for a
    /// message that carries its own, is refused.
    ///
    /// A SignedData with no signers is refused; its certificates are read with
    /// [`certificates_only`].
    ///
    /// Requires a `PkiEnvironment`, which performs the hashing and signature verification, whether
    /// or not `settings` are given. A signature whose algorithm no implementation registered there
    /// verifies is [`Error::Unrecognized`]; RSA in software is certval's `rsa` feature, which this
    /// crate's `rsa` feature turns on.
    pub fn verify_signed_data(
        &self,
        content_info: &ContentInfo,
        detached_content: Option<&[u8]>,
        settings: Option<&CertificationPathSettings>,
        policy: SignerPolicy,
    ) -> Result<VerifiedSignedData> {
        let signed_data = signed_data(content_info)?;
        if signed_data.signer_infos.0.is_empty() {
            return Err(Error::InvalidInput(String::from(
                "a SignedData with no signers; its certificates are read with certificates_only",
            )));
        }
        let content_type = signed_data.encap_content_info.econtent_type;
        let content = match (&signed_data.encap_content_info.econtent, detached_content) {
            (Some(econtent), None) => OctetString::from_der(&econtent.to_der()?)?
                .as_bytes()
                .to_vec(),
            (None, Some(content)) => content.to_vec(),
            (None, None) => {
                return Err(Error::InvalidInput(String::from(
                    "the content is detached, and was not supplied",
                )))
            }
            (Some(_), Some(_)) => {
                return Err(Error::InvalidInput(String::from(
                    "content supplied for a message that carries its own",
                )))
            }
        };
        let message_certs = certificates(&signed_data);

        let mut signers = vec![];
        let mut failed = vec![];
        for signer in signed_data.signer_infos.0.iter() {
            match self.verify_signer(signer, content_type, &content, &message_certs, settings) {
                Ok(verified) => signers.push(verified),
                Err(e) => {
                    if policy == SignerPolicy::All {
                        return Err(e);
                    }
                    failed.push((signer.sid.clone(), e));
                }
            }
        }
        if signers.is_empty() {
            let (_, first) = failed.remove(0);
            return Err(first);
        }
        Ok(VerifiedSignedData {
            content_type,
            content,
            signers,
            failed,
        })
    }
}
