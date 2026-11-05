//! The ESS signing-certificate-v2 attribute (RFC 5035, section 3), which binds a signer's
//! certificate into its signed attributes, so that another certificate for the same key cannot be
//! substituted for it. The original signing-certificate attribute (RFC 2634), which identifies the
//! certificate by its SHA-1 hash, is not processed.

use alloc::{vec, vec::Vec};

use const_oid::db::rfc5912::ID_SHA_256;
use der::{asn1::OctetString, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::pkix::{certpolicy::PolicyInformation, name::GeneralName},
    serial_number::SerialNumber,
    Certificate,
};

/// ```text
/// IssuerSerial ::= SEQUENCE {
///   issuer       GeneralNames,
///   serialNumber CertificateSerialNumber }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IssuerSerial {
    /// The issuer's names.
    pub issuer: Vec<GeneralName>,
    /// The certificate's serial number.
    pub serial_number: SerialNumber,
}

impl IssuerSerial {
    /// The issuer and serial number of `cert`, the issuer as a directory name.
    pub fn of(cert: &Certificate) -> Self {
        Self {
            issuer: vec![GeneralName::DirectoryName(
                cert.tbs_certificate().issuer().clone(),
            )],
            serial_number: cert.tbs_certificate().serial_number().clone(),
        }
    }

    /// Whether this names `cert`.
    pub fn names(&self, cert: &Certificate) -> bool {
        self.serial_number == *cert.tbs_certificate().serial_number()
            && self.issuer.iter().any(|name| match name {
                GeneralName::DirectoryName(issuer) => issuer == cert.tbs_certificate().issuer(),
                _ => false,
            })
    }
}

/// ```text
/// ESSCertIDv2 ::= SEQUENCE {
///   hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///   certHash      Hash,
///   issuerSerial  IssuerSerial OPTIONAL }
/// ```
///
/// The default hash algorithm is absent from the encoding (DER, X.690 section 11.5), so an absent
/// `hash_algorithm` is SHA-256; see [`hash_algorithm`](Self::hash_algorithm).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertIdV2 {
    /// The algorithm `cert_hash` was computed with; absent for SHA-256.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// The hash of the certificate's DER encoding.
    pub cert_hash: OctetString,
    /// The certificate's issuer and serial number.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

impl EssCertIdV2 {
    /// The hash algorithm, SHA-256 when absent.
    pub fn hash_algorithm(&self) -> AlgorithmIdentifierOwned {
        self.hash_algorithm
            .clone()
            .unwrap_or(AlgorithmIdentifierOwned {
                oid: ID_SHA_256,
                parameters: None,
            })
    }
}

/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///   certs    SEQUENCE OF ESSCertIDv2,
///   policies SEQUENCE OF PolicyInformation OPTIONAL }
/// ```
///
/// The policies, which constrain the certificate's use, are decoded but not applied when a
/// SignedData is verified; applying them is the caller's.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificateV2 {
    /// The signer's certificate first, then any others relevant to the signature.
    pub certs: Vec<EssCertIdV2>,
    /// The policies under which the signer's certificate is to be used.
    #[asn1(optional = "true")]
    pub policies: Option<Vec<PolicyInformation>>,
}
