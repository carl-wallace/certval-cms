//! Certificate vetting: recipients made with and without settings, against a PkiEnvironment that
//! trusts a test CA, and the ways vetting fails: no PkiEnvironment, an untrusted issuer, a key usage
//! that does not permit the use, an expired certificate, and revocation that cannot be determined.

mod common;

use certval::{CertificationPathSettings, PathValidationStatus, TimeOfInterest};
use certval_cms::{
    CertificateLookup, CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder, Error,
    KeyAgreeRecipient, KeyAgreementAlgorithm, KeyTransRecipient, KeyTransportAlgorithm,
    KeyWrapAlgorithm, RecipientCertificateSource, SoftwareRecipientKey, Vetting,
};
use common::{day, email_address, key_usage, rng, settings, Ca, Rng};
use elliptic_curve::Generate as _;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use x509_cert::{
    ext::{pkix::KeyUsages, Extension},
    time::Validity,
    Certificate,
};

const MESSAGE: &[u8] = b"certval-cms vetting";

fn environment(ca: &Ca) -> CmsEnvironment {
    common::environment(ca, &[])
}

struct RsaRecipient {
    cert: Certificate,
    pkcs8: Vec<u8>,
}

fn rsa_recipient(
    ca: &Ca,
    serial: u8,
    extensions: Vec<Extension>,
    validity: Validity,
) -> RsaRecipient {
    let key = rsa::RsaPrivateKey::new(&mut rng(), 2048).unwrap();
    let spki = key.to_public_key().to_public_key_der().unwrap();
    RsaRecipient {
        cert: ca.issue(spki.as_bytes(), serial, extensions, validity),
        pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
    }
}

fn is_status(result: Result<impl Sized, Error>, status: PathValidationStatus) -> bool {
    match result {
        Err(Error::Certval(certval::Error::PathValidation(s))) => s == status,
        _ => false,
    }
}

// ---- vetting performed or not

#[test]
fn without_settings_vetting_is_not_performed() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(&ca, 2, vec![key_usage(KeyUsages::KeyEncipherment)], day());
    let mut env = CmsEnvironment::new();
    env.populate_software();
    let r = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        None,
        KeyTransportAlgorithm::RsaOaepSha256,
    )
    .unwrap();
    assert!(matches!(r.vetting(), Vetting::NotPerformed));

    let env = environment(&ca);
    let r = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        None,
        KeyTransportAlgorithm::RsaOaepSha256,
    )
    .unwrap();
    assert!(matches!(r.vetting(), Vetting::NotPerformed));
}

#[test]
fn settings_without_a_pki_environment_are_an_error() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(&ca, 3, vec![], day());
    let mut env = CmsEnvironment::new();
    env.populate_software();
    let result = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        Some(&settings()),
        KeyTransportAlgorithm::RsaOaepSha256,
    );
    assert!(matches!(result, Err(Error::NoPkiEnvironment)));
}

#[test]
fn a_certificate_from_a_trusted_ca_is_validated_and_its_message_decrypts() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(&ca, 4, vec![key_usage(KeyUsages::KeyEncipherment)], day());
    let env = environment(&ca);
    let r = KeyTransRecipient::from_certificate(
        &env,
        &recipient.cert,
        Some(&settings()),
        KeyTransportAlgorithm::RsaOaepSha256,
    )
    .unwrap();
    assert!(matches!(r.vetting(), Vetting::Validated(_)));
    let ci = EnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes128Cbc)
        .unwrap()
        .add_recipient(r)
        .build_content_info(&env, &mut rng())
        .unwrap();
    let credential =
        SoftwareRecipientKey::from_pkcs8_der(recipient.cert.clone(), &recipient.pkcs8).unwrap();
    let decrypted = env.decrypt_enveloped_data(&ci, Some(&credential)).unwrap();
    assert_eq!(decrypted.content.as_slice(), MESSAGE);
}

#[test]
fn a_certificate_without_key_usage_is_unrestricted() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(&ca, 5, vec![], day());
    let env = environment(&ca);
    let r = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        Some(&settings()),
        KeyTransportAlgorithm::RsaPkcs1v15,
    )
    .unwrap();
    assert!(matches!(r.vetting(), Vetting::Validated(_)));
}

// ---- vetting fails

#[test]
fn a_certificate_from_an_untrusted_ca_is_refused() {
    let trusted = Ca::new("CN=trusted CA");
    let other = Ca::new("CN=other CA");
    let recipient = rsa_recipient(
        &other,
        6,
        vec![key_usage(KeyUsages::KeyEncipherment)],
        day(),
    );
    let env = environment(&trusted);
    let result = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        Some(&settings()),
        KeyTransportAlgorithm::RsaOaepSha256,
    );
    assert!(matches!(result, Err(Error::Certval(_))));
}

#[test]
fn a_key_usage_that_does_not_permit_the_use_is_refused() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca);
    let signing_only = rsa_recipient(&ca, 7, vec![key_usage(KeyUsages::DigitalSignature)], day());
    assert!(is_status(
        KeyTransRecipient::<Rng>::from_certificate(
            &env,
            &signing_only.cert,
            Some(&settings()),
            KeyTransportAlgorithm::RsaOaepSha256,
        ),
        PathValidationStatus::InvalidKeyUsage
    ));

    // An EC key certified for key agreement is accepted for it, and refused for key transport.
    let ec = p256::SecretKey::generate_from_rng(&mut rng());
    let ec_cert = ca.issue(
        ec.public_key().to_public_key_der().unwrap().as_bytes(),
        8,
        vec![key_usage(KeyUsages::KeyAgreement)],
        day(),
    );
    let r = KeyAgreeRecipient::<Rng>::from_certificate(
        &env,
        &ec_cert,
        Some(&settings()),
        KeyAgreementAlgorithm::EcdhSha256,
        KeyWrapAlgorithm::Aes128,
        None,
    )
    .unwrap();
    assert!(matches!(r.vetting(), Vetting::Validated(_)));
    assert!(is_status(
        KeyTransRecipient::<Rng>::from_certificate(
            &env,
            &ec_cert,
            Some(&settings()),
            KeyTransportAlgorithm::RsaOaepSha256,
        ),
        PathValidationStatus::InvalidKeyUsage
    ));
}

#[test]
fn a_certificate_not_valid_at_the_time_of_interest_is_refused() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(&ca, 9, vec![key_usage(KeyUsages::KeyEncipherment)], day());
    let env = environment(&ca);
    let mut later = settings();
    let in_a_week = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 7 * 86400;
    later.set_time_of_interest(TimeOfInterest::from_unix_secs(in_a_week).unwrap());
    let result = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        Some(&later),
        KeyTransportAlgorithm::RsaOaepSha256,
    );
    assert!(matches!(result, Err(Error::Certval(_))));
}

#[test]
fn revocation_checked_without_revocation_information_is_not_determined() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(&ca, 10, vec![key_usage(KeyUsages::KeyEncipherment)], day());
    let env = environment(&ca);
    // certval checks revocation by default; nothing here can say whether the certificate is revoked.
    let result = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &recipient.cert,
        Some(&CertificationPathSettings::default()),
        KeyTransportAlgorithm::RsaOaepSha256,
    );
    assert!(is_status(
        result,
        PathValidationStatus::RevocationStatusNotDetermined
    ));
}

// ---- recipient certificate sources

/// Finds the certificates a lookup identifies, in the order held.
struct Directory(Vec<Certificate>);

impl RecipientCertificateSource for Directory {
    fn find_recipient_certificates(
        &self,
        _env: &CmsEnvironment,
        lookup: CertificateLookup<'_>,
    ) -> certval_cms::Result<Vec<Certificate>> {
        Ok(self
            .0
            .iter()
            .filter(|c| lookup.matches(c))
            .cloned()
            .collect())
    }
}

const EMAIL: &str = "recipient@example.com";

#[test]
fn a_recipient_certificate_is_found_and_then_vetted() {
    let ca = Ca::new("CN=test CA");
    let recipient = rsa_recipient(
        &ca,
        11,
        vec![key_usage(KeyUsages::KeyEncipherment), email_address(EMAIL)],
        day(),
    );
    let mut env = environment(&ca);
    env.add_recipient_certificate_source(Directory(vec![recipient.cert.clone()]));
    assert!(env
        .find_recipient_certificate(CertificateLookup::EmailAddress("someone@example.com"))
        .unwrap()
        .is_none());
    let cert = env
        .find_recipient_certificate(CertificateLookup::EmailAddress(EMAIL))
        .unwrap()
        .unwrap();
    let r = KeyTransRecipient::<Rng>::from_certificate(
        &env,
        &cert,
        Some(&settings()),
        KeyTransportAlgorithm::RsaOaepSha256,
    )
    .unwrap();
    assert!(matches!(r.vetting(), Vetting::Validated(_)));
}

#[test]
fn the_recipient_certificate_found_is_one_whose_key_usage_permits_encryption() {
    let ca = Ca::new("CN=test CA");
    let signature = rsa_recipient(
        &ca,
        12,
        vec![key_usage(KeyUsages::DigitalSignature), email_address(EMAIL)],
        day(),
    );
    let encryption = rsa_recipient(
        &ca,
        13,
        vec![key_usage(KeyUsages::KeyEncipherment), email_address(EMAIL)],
        day(),
    );
    let mut env = environment(&ca);
    env.add_recipient_certificate_source(Directory(vec![
        signature.cert.clone(),
        encryption.cert.clone(),
    ]));
    let cert = env
        .find_recipient_certificate(CertificateLookup::EmailAddress(EMAIL))
        .unwrap()
        .unwrap();
    assert_eq!(cert, encryption.cert);
    assert_eq!(
        env.find_recipient_certificates(CertificateLookup::EmailAddress(EMAIL))
            .unwrap(),
        [encryption.cert]
    );
}

#[test]
fn a_recipient_certificate_without_key_usage_is_found() {
    let ca = Ca::new("CN=test CA");
    let signature = rsa_recipient(
        &ca,
        14,
        vec![key_usage(KeyUsages::DigitalSignature), email_address(EMAIL)],
        day(),
    );
    let unrestricted = rsa_recipient(&ca, 15, vec![email_address(EMAIL)], day());
    let mut env = environment(&ca);
    env.add_recipient_certificate_source(Directory(vec![
        signature.cert.clone(),
        unrestricted.cert.clone(),
    ]));
    let cert = env
        .find_recipient_certificate(CertificateLookup::EmailAddress(EMAIL))
        .unwrap()
        .unwrap();
    assert_eq!(cert, unrestricted.cert);
}

#[test]
fn no_recipient_certificate_is_found_when_none_permits_encryption() {
    let ca = Ca::new("CN=test CA");
    let signature = rsa_recipient(
        &ca,
        16,
        vec![key_usage(KeyUsages::DigitalSignature), email_address(EMAIL)],
        day(),
    );
    let agreement = rsa_recipient(
        &ca,
        17,
        vec![key_usage(KeyUsages::KeyAgreement), email_address(EMAIL)],
        day(),
    );
    let mut env = environment(&ca);
    env.add_recipient_certificate_source(Directory(vec![signature.cert, agreement.cert]));
    assert!(env
        .find_recipient_certificate(CertificateLookup::EmailAddress(EMAIL))
        .unwrap()
        .is_none());
}
