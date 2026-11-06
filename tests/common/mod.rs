//! A test PKI for the vetting and SignedData tests: CAs that issue certificates with chosen
//! extensions, and a PkiEnvironment that trusts one of them.

#![allow(dead_code)]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use certval::{
    CertFile, CertSource, CertVector, CertificationPathSettings, PkiEnvironment, TaSource,
};
use certval_cms::CmsEnvironment;
use const_oid::db::rfc5912::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE, ID_CE_SUBJECT_KEY_IDENTIFIER,
};
use der::{asn1::OctetString, Decode, Encode};
use elliptic_curve::Generate as _;
use getrandom::SysRng;
use p256::pkcs8::EncodePublicKey;
use rand_core::UnwrapErr;
use sha1::{Digest, Sha1};
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier},
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate, TbsCertificate,
};

pub type Rng = UnwrapErr<SysRng>;

pub fn rng() -> Rng {
    UnwrapErr(SysRng)
}

/// Issues a certificate with exactly the given extensions, plus a subject key identifier when
/// `skid` is set.
struct Profile {
    issuer: Name,
    subject: Name,
    extensions: Vec<Extension>,
    skid: bool,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = self.extensions.clone();
        if self.skid {
            let skid = SubjectKeyIdentifier(
                OctetString::new(Sha1::digest(spk.subject_public_key.raw_bytes()).to_vec())
                    .unwrap(),
            );
            extensions.push(extension(ID_CE_SUBJECT_KEY_IDENTIFIER, false, &skid));
        }
        Ok(extensions)
    }
}

pub fn extension(
    oid: const_oid::ObjectIdentifier,
    critical: bool,
    value: &impl Encode,
) -> Extension {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

pub fn key_usage(usages: impl Into<der::flagset::FlagSet<KeyUsages>>) -> Extension {
    extension(ID_CE_KEY_USAGE, true, &KeyUsage(usages.into()))
}

/// A subject alternative name extension containing `email` as an rfc822Name.
pub fn email_address(email: &str) -> Extension {
    extension(
        const_oid::db::rfc5912::ID_CE_SUBJECT_ALT_NAME,
        false,
        &x509_cert::ext::pkix::SubjectAltName(vec![
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(
                der::asn1::Ia5String::new(email).unwrap(),
            ),
        ]),
    )
}

pub fn ca_extensions() -> Vec<Extension> {
    vec![
        extension(
            ID_CE_BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
        ),
        key_usage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
    ]
}

pub fn day() -> Validity {
    Validity::from_now(Duration::from_secs(86400)).unwrap()
}

/// A CA: its key and its certificate.
pub struct Ca {
    key: p256::ecdsa::SigningKey,
    name: Name,
    pub cert: Certificate,
}

impl Ca {
    /// A root CA, with a self-signed certificate.
    pub fn new(name: &str) -> Self {
        let key = p256::ecdsa::SigningKey::from(p256::SecretKey::generate_from_rng(&mut rng()));
        let name = Name::from_str(name).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let cert = issue(
            &key,
            &name,
            &name,
            spki.as_bytes(),
            1,
            ca_extensions(),
            true,
            day(),
        );
        Self { key, name, cert }
    }

    /// A CA whose certificate this CA issues.
    pub fn intermediate(&self, name: &str) -> Ca {
        let key = p256::ecdsa::SigningKey::from(p256::SecretKey::generate_from_rng(&mut rng()));
        let name = Name::from_str(name).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let cert = issue(
            &self.key,
            &self.name,
            &name,
            spki.as_bytes(),
            2,
            ca_extensions(),
            true,
            day(),
        );
        Ca { key, name, cert }
    }

    /// An end-entity certificate for `spki_der`, with the given extensions and a subject key
    /// identifier.
    pub fn issue(
        &self,
        spki_der: &[u8],
        serial: u8,
        extensions: Vec<Extension>,
        validity: Validity,
    ) -> Certificate {
        let subject = Name::from_str(&format!("CN=entity {serial}")).unwrap();
        issue(
            &self.key, &self.name, &subject, spki_der, serial, extensions, true, validity,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn issue(
    key: &p256::ecdsa::SigningKey,
    issuer: &Name,
    subject: &Name,
    spki_der: &[u8],
    serial: u8,
    extensions: Vec<Extension>,
    skid: bool,
    validity: Validity,
) -> Certificate {
    let profile = Profile {
        issuer: issuer.clone(),
        subject: subject.clone(),
        extensions,
        skid,
    };
    CertificateBuilder::new(
        profile,
        SerialNumber::new(&[serial]).unwrap(),
        validity,
        SubjectPublicKeyInfoOwned::from_der(spki_der).unwrap(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(key)
    .unwrap()
}

/// A certificate for `spki_der` named `subject`, issued under `issuer` by any signer the builder
/// takes, with the given extensions and a subject key identifier.
pub fn issue_by<S, Sig>(
    signer: &S,
    issuer: &Name,
    subject: &str,
    spki_der: &[u8],
    serial: u8,
    extensions: Vec<Extension>,
) -> Certificate
where
    S: signature::Signer<Sig> + signature::Keypair + spki::DynSignatureAlgorithmIdentifier,
    S::VerifyingKey: spki::EncodePublicKey,
    Sig: spki::SignatureBitStringEncoding,
{
    let profile = Profile {
        issuer: issuer.clone(),
        subject: Name::from_str(subject).unwrap(),
        extensions,
        skid: true,
    };
    CertificateBuilder::new(
        profile,
        SerialNumber::new(&[serial]).unwrap(),
        day(),
        SubjectPublicKeyInfoOwned::from_der(spki_der).unwrap(),
    )
    .unwrap()
    .build::<_, Sig>(signer)
    .unwrap()
}

/// Settings for a test: revocation is not checked, there being no CRLs.
pub fn settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::default();
    cps.set_check_revocation_status(false);
    cps
}

/// A PkiEnvironment trusting `anchor`, with `intermediates` in a certificate source.
pub fn pki_environment(anchor: &Ca, intermediates: &[&Certificate]) -> Arc<PkiEnvironment> {
    let cps = settings();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut anchors = TaSource::new();
    anchors.push(CertFile {
        filename: "anchor".into(),
        bytes: anchor.cert.to_der().unwrap(),
    });
    anchors.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(anchors));
    // Path building runs through certificate sources, so one is registered even with nothing in it.
    let mut certs = CertSource::new();
    for (i, cert) in intermediates.iter().enumerate() {
        certs.push(CertFile {
            filename: format!("intermediate {i}"),
            bytes: cert.to_der().unwrap(),
        });
    }
    certs.initialize(&cps).unwrap();
    certs.find_all_partial_paths(&pe, &cps);
    pe.add_certificate_source(Box::new(certs));
    Arc::new(pe)
}

/// A software environment whose PkiEnvironment trusts `anchor`.
pub fn environment(anchor: &Ca, intermediates: &[&Certificate]) -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env.set_pki_environment(pki_environment(anchor, intermediates));
    env
}
