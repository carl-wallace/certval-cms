//! `CredentialSigner`: a CA's key, held as a `SigningCredential`, signs a certificate and a CRL
//! through x509-cert's builders, and each signature verifies with the CA certificate's key. ECDSA on
//! P-256, and with `pqc`, ML-DSA-65.

mod common;

use certval_cms::{
    CmsEnvironment, CredentialSignature, CredentialSigner, DigestAlgorithm, SoftwareSigningKey,
};
use common::{ca_extensions, environment, issue_by, key_usage, rng, Ca};
use der::Encode;
use elliptic_curve::Generate as _;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use signature::Keypair;
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::{
    builder::{Builder, CrlBuilder},
    crl::CertificateList,
    ext::pkix::{CrlNumber, KeyUsages},
    Certificate,
};

/// A CA certificate `root` issues for a key given as PKCS #8 and SPKI, and the CA's credential.
fn subordinate_ca(root: &Ca, spki_der: &[u8], pkcs8: &[u8]) -> SoftwareSigningKey {
    let cert = root.issue(spki_der, 2, ca_extensions(), common::day());
    SoftwareSigningKey::from_pkcs8_der(cert, pkcs8).unwrap()
}

/// Verifies a signature over `message` with `issuer`'s key, as certval does for a certificate.
fn assert_signed_by(
    env: &CmsEnvironment,
    issuer: &Certificate,
    message: &[u8],
    signature: &der::asn1::BitString,
    alg: &spki::AlgorithmIdentifierOwned,
    name: &str,
) {
    let pe = env.pki_environment().unwrap();
    pe.verify_signature_message(
        pe,
        message,
        signature,
        alg,
        issuer.tbs_certificate().subject_public_key_info(),
    )
    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
}

/// The CA's credential issues a certificate and a CRL, and both verify with the CA's key.
fn issues_and_revokes(
    env: &CmsEnvironment,
    ca: &SoftwareSigningKey,
    digest: DigestAlgorithm,
    name: &str,
) {
    let signer = CredentialSigner::new(env, ca, digest).unwrap();
    let ca_cert = certval_cms::SigningCredential::certificate(ca);
    assert_eq!(
        signer
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
        ca_cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap(),
        "{name}: the verifying key is the certificate's"
    );

    let ee_key = p256::ecdsa::SigningKey::from(p256::SecretKey::generate_from_rng(&mut rng()));
    let ee = issue_by::<_, CredentialSignature>(
        &signer,
        ca_cert.tbs_certificate().subject(),
        "CN=issued through CredentialSigner",
        ee_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
        3,
        vec![key_usage(KeyUsages::DigitalSignature)],
    );
    assert_eq!(
        *ee.signature_algorithm(),
        signer.signature_algorithm_identifier().unwrap(),
        "{name}"
    );
    assert_signed_by(
        env,
        ca_cert,
        &ee.tbs_certificate().to_der().unwrap(),
        ee.signature(),
        ee.signature_algorithm(),
        &format!("{name}: certificate"),
    );

    let crl: CertificateList = CrlBuilder::new(ca_cert, CrlNumber::try_from(1u32).unwrap())
        .unwrap()
        .build::<_, CredentialSignature>(&signer)
        .unwrap();
    assert_eq!(
        crl.tbs_cert_list.issuer,
        *ca_cert.tbs_certificate().subject(),
        "{name}"
    );
    assert_signed_by(
        env,
        ca_cert,
        &crl.tbs_cert_list.to_der().unwrap(),
        &crl.signature,
        &crl.signature_algorithm,
        &format!("{name}: CRL"),
    );
}

#[test]
fn ecdsa_p256_issues_a_certificate_and_a_crl() {
    let root = Ca::new("CN=test root");
    let env = environment(&root, &[]);
    let key = p256::SecretKey::generate_from_rng(&mut rng());
    let ca = subordinate_ca(
        &root,
        key.public_key().to_public_key_der().unwrap().as_bytes(),
        key.to_pkcs8_der().unwrap().as_bytes(),
    );
    for digest in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        issues_and_revokes(&env, &ca, digest, &format!("P-256 {digest:?}"));
    }
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_65_issues_a_certificate_and_a_crl() {
    use ml_dsa::common::Generate as _;
    let root = Ca::new("CN=test root");
    let env = environment(&root, &[]);
    let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate_from_rng(&mut rng());
    let ca = subordinate_ca(
        &root,
        key.verifying_key().to_public_key_der().unwrap().as_bytes(),
        key.to_pkcs8_der().unwrap().as_bytes(),
    );
    issues_and_revokes(&env, &ca, DigestAlgorithm::Sha512, "ML-DSA-65");
}
