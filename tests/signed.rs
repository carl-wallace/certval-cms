//! SignedData: messages signed here with every signature algorithm and verified again, with and
//! without vetting; several signers and the signer policy; signers found through sources; the
//! failures (a changed content, signature or content type, no signers); a signer whose intermediate
//! CA only the message carries; and certificates-only messages.
//!
//! With `CERTVAL_CMS_OPENSSL` set to an `openssl` command, messages `openssl cms -sign` builds are
//! verified here, and messages built here are verified by `openssl cms -verify`.

mod common;

use std::process::Command;
use std::sync::Arc;

use certval::PathValidationStatus;
use certval_cms::{
    certificates_only, rsa_pss, signer_identifier, CertificateOrigin, CmsEnvironment,
    CredentialOrigin, DigestAlgorithm, Error, IncludeCertificates, SignedDataBuilder, Signer,
    SignerCertificateSource, SignerPolicy, SigningCredentialLookup, SingleSigningCredential,
    SoftwareSigningKey, Vetting,
};
use cms::{content_info::ContentInfo, signed_data::SignedData, signed_data::SignerIdentifier};
use common::{
    ca_extensions, day, email_address, environment, issue_by, key_usage, rng, settings, Ca,
};
use const_oid::db::rfc5911::{ID_CONTENT_TYPE, ID_DATA, ID_ENVELOPED_DATA};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, Decode, Encode,
};
use elliptic_curve::Generate as _;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use x509_cert::{
    ext::{pkix::KeyUsages, Extension},
    name::Name,
    Certificate,
};

const MESSAGE: &[u8] = b"certval-cms signed content";

const DIGESTS: [DigestAlgorithm; 3] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

/// A signer's certificate and private key as PKCS #8.
struct Signatory {
    cert: Certificate,
    pkcs8: Vec<u8>,
}

impl Signatory {
    fn credential(&self) -> SoftwareSigningKey {
        SoftwareSigningKey::from_pkcs8_der(self.cert.clone(), &self.pkcs8).unwrap()
    }
}

fn rsa_signatory(ca: &Ca, serial: u8) -> Signatory {
    rsa_signatory_with(ca, serial, vec![key_usage(KeyUsages::DigitalSignature)])
}

fn rsa_signatory_with(ca: &Ca, serial: u8, extensions: Vec<Extension>) -> Signatory {
    let key = rsa::RsaPrivateKey::new(&mut rng(), 2048).unwrap();
    let spki = key.to_public_key().to_public_key_der().unwrap();
    Signatory {
        cert: ca.issue(spki.as_bytes(), serial, extensions, day()),
        pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
    }
}

macro_rules! ec_signatory {
    ($curve:ident, $ca:expr, $serial:expr) => {{
        let key = $curve::SecretKey::generate_from_rng(&mut rng());
        let spki = key.public_key().to_public_key_der().unwrap();
        Signatory {
            cert: $ca.issue(
                spki.as_bytes(),
                $serial,
                vec![key_usage(KeyUsages::NonRepudiation)],
                day(),
            ),
            pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        }
    }};
}

fn sign(env: &CmsEnvironment, signer: Signer<'_>) -> ContentInfo {
    SignedDataBuilder::new(MESSAGE)
        .add_signer(signer)
        .build(env)
        .unwrap()
        .content_info
}

fn assert_verifies_vetted(env: &CmsEnvironment, ci: &ContentInfo, name: &str) {
    let verified = env
        .verify_signed_data(ci, None, Some(&settings()), SignerPolicy::All)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(verified.content, MESSAGE, "{name}");
    assert_eq!(verified.content_type, ID_DATA, "{name}");
    assert_eq!(verified.signers.len(), 1, "{name}");
    let signer = &verified.signers[0];
    assert!(matches!(signer.vetting, Vetting::Validated(_)), "{name}");
    assert_eq!(
        signer.certificate_origin,
        CertificateOrigin::Message,
        "{name}"
    );
    assert!(signer.message_ca_certificates.is_empty(), "{name}");
}

// ---- round trips

#[test]
fn rsa_pkcs1v15_and_pss_with_each_digest() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 2);
    let credential = signatory.credential();
    for digest in DIGESTS {
        let ci = sign(&env, Signer::explicit(&credential).digest(digest));
        assert_verifies_vetted(&env, &ci, &format!("PKCS #1 v1.5 {digest:?}"));
        let ci = sign(
            &env,
            Signer::explicit(&credential)
                .digest(digest)
                .signature_algorithm(rsa_pss(digest).unwrap()),
        );
        assert_verifies_vetted(&env, &ci, &format!("PSS {digest:?}"));

        // The signature algorithm alone chooses the digest.
        let ci = sign(
            &env,
            Signer::explicit(&credential).signature_algorithm(rsa_pss(digest).unwrap()),
        );
        assert_verifies_vetted(&env, &ci, &format!("PSS {digest:?} by signature algorithm"));
        assert_eq!(signer_digest_algorithms(&ci), vec![digest.oid()]);
    }

    // A digest other than the one the signature algorithm uses is refused.
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(
                Signer::explicit(&credential)
                    .digest(DigestAlgorithm::Sha256)
                    .signature_algorithm(rsa_pss(DigestAlgorithm::Sha384).unwrap())
            )
            .build(&env),
        Err(Error::InvalidInput(_))
    ));
}

/// Each signer's digestAlgorithm, in SignerInfo order.
fn signer_digest_algorithms(ci: &ContentInfo) -> Vec<const_oid::ObjectIdentifier> {
    signed_data(ci)
        .signer_infos
        .0
        .iter()
        .map(|si| si.digest_alg.oid)
        .collect()
}

macro_rules! ecdsa_round_trips {
    ($curve:ident) => {{
        let ca = Ca::new("CN=test CA");
        let env = environment(&ca, &[]);
        let signatory = ec_signatory!($curve, ca, 3);
        let credential = signatory.credential();
        for digest in DIGESTS {
            let ci = sign(&env, Signer::explicit(&credential).digest(digest));
            assert_verifies_vetted(&env, &ci, &format!("{} {digest:?}", stringify!($curve)));
        }
    }};
}

#[test]
fn ecdsa_on_p256() {
    ecdsa_round_trips!(p256);
}

#[test]
fn ecdsa_on_p384() {
    ecdsa_round_trips!(p384);
}

#[test]
fn ecdsa_on_p521() {
    ecdsa_round_trips!(p521);
}

#[test]
fn without_settings_the_signer_is_not_vetted() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 4);
    let ci = sign(&env, Signer::explicit(&signatory.credential()));
    let verified = env
        .verify_signed_data(&ci, None, None, SignerPolicy::All)
        .unwrap();
    assert!(matches!(verified.signers[0].vetting, Vetting::NotPerformed));
}

#[test]
fn several_signers_each_verify_and_report() {
    let ca = Ca::new("CN=test CA");
    let mut env = environment(&ca, &[]);
    let rsa = rsa_signatory(&ca, 5);
    let ec = ec_signatory!(p256, ca, 6);
    env.add_signing_credential_source(SingleSigningCredential::new(Arc::new(ec.credential())));
    let rsa_key = rsa.credential();
    let built = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&rsa_key))
        .add_signer(
            Signer::by_identifier(signer_identifier(&ec.cert).unwrap())
                .digest(DigestAlgorithm::Sha384),
        )
        .build(&env)
        .unwrap();
    assert_eq!(built.signers[0].credential, CredentialOrigin::Explicit);
    assert_eq!(built.signers[1].credential, CredentialOrigin::Source(0));
    let verified = env
        .verify_signed_data(
            &built.content_info,
            None,
            Some(&settings()),
            SignerPolicy::All,
        )
        .unwrap();
    assert_eq!(verified.signers.len(), 2);
    assert!(verified.failed.is_empty());
}

/// Finds one certificate by signer identifier, as a store the message does not carry would.
struct Directory(Certificate);

impl SignerCertificateSource for Directory {
    fn find_signer_certificate(
        &self,
        _env: &CmsEnvironment,
        sid: &SignerIdentifier,
    ) -> certval_cms::Result<Option<Certificate>> {
        Ok(certval_cms::signer_matches(sid, &self.0).then(|| self.0.clone()))
    }
}

#[test]
fn a_signer_certificate_the_message_omits_is_found_through_a_source() {
    let ca = Ca::new("CN=test CA");
    let mut env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 7);
    let credential = signatory.credential();
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&credential))
        .include_certificates(IncludeCertificates::None)
        .build(&env)
        .unwrap()
        .content_info;
    assert!(matches!(
        env.verify_signed_data(&ci, None, None, SignerPolicy::All),
        Err(Error::NoMatchingSigner)
    ));
    env.add_signer_certificate_source(Directory(signatory.cert.clone()));
    let verified = env
        .verify_signed_data(&ci, None, Some(&settings()), SignerPolicy::All)
        .unwrap();
    assert_eq!(
        verified.signers[0].certificate_origin,
        CertificateOrigin::Source(0)
    );
}

#[test]
fn a_signer_identified_by_issuer_and_serial_is_so_despite_a_subject_key_identifier() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 35);
    let credential = signatory.credential();
    let by_default = signed_data(&sign(&env, Signer::explicit(&credential)));
    assert!(matches!(
        by_default.signer_infos.0.iter().next().unwrap().sid,
        SignerIdentifier::SubjectKeyIdentifier(_)
    ));
    let ci = sign(
        &env,
        Signer::explicit(&credential).identified_by_issuer_and_serial(),
    );
    match &signed_data(&ci).signer_infos.0.iter().next().unwrap().sid {
        SignerIdentifier::IssuerAndSerialNumber(iasn) => {
            assert_eq!(&iasn.issuer, signatory.cert.tbs_certificate().issuer());
            assert_eq!(
                &iasn.serial_number,
                signatory.cert.tbs_certificate().serial_number()
            );
        }
        other => panic!("{other:?}"),
    }
    assert_verifies_vetted(&env, &ci, "issuer and serial");
}

// ---- failures

fn signed_data(ci: &ContentInfo) -> SignedData {
    SignedData::from_der(&ci.content.to_der().unwrap()).unwrap()
}

fn content_info(sd: &SignedData) -> ContentInfo {
    ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(sd).unwrap(),
    }
}

#[test]
fn a_changed_content_fails_the_message_digest() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 8);
    let mut sd = signed_data(&sign(&env, Signer::explicit(&signatory.credential())));
    sd.encap_content_info.econtent =
        Some(Any::encode_from(&OctetString::new(b"other content".to_vec()).unwrap()).unwrap());
    match env.verify_signed_data(&content_info(&sd), None, None, SignerPolicy::All) {
        Err(Error::Crypto(e)) => assert_eq!(e, "the message digest does not match the content"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[test]
fn a_changed_signature_fails_verification() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = ec_signatory!(p256, ca, 9);
    let mut sd = signed_data(&sign(&env, Signer::explicit(&signatory.credential())));
    let mut infos: Vec<_> = sd.signer_infos.0.iter().cloned().collect();
    let mut signature = infos[0].signature.as_bytes().to_vec();
    let last = signature.len() - 1;
    signature[last] ^= 1;
    infos[0].signature = OctetString::new(signature).unwrap();
    sd.signer_infos = cms::signed_data::SignerInfos::try_from(infos).unwrap();
    assert!(matches!(
        env.verify_signed_data(&content_info(&sd), None, None, SignerPolicy::All),
        Err(Error::Certval(_))
    ));
}

/// RFC 5754, section 3: a SignerInfo whose digestAlgorithm is not the hash its signatureAlgorithm
/// uses is malformed, whichever hash the signature would verify under.
#[test]
fn a_digest_algorithm_the_signature_algorithm_does_not_use_is_refused() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = ec_signatory!(p256, ca, 29);
    let mut sd = signed_data(&sign(&env, Signer::explicit(&signatory.credential())));
    let mut infos: Vec<_> = sd.signer_infos.0.iter().cloned().collect();
    infos[0].digest_alg = DigestAlgorithm::Sha384.algorithm_identifier();
    sd.signer_infos = cms::signed_data::SignerInfos::try_from(infos).unwrap();
    assert!(matches!(
        env.verify_signed_data(&content_info(&sd), None, None, SignerPolicy::All),
        Err(Error::InvalidInput(_))
    ));
}

/// A digest algorithm no registered implementation hashes is declined, as a signature algorithm
/// none verifies is, and not reported as a certval failure.
#[test]
fn a_digest_algorithm_no_implementation_hashes_is_unrecognized() {
    use const_oid::db::rfc5912::RSA_ENCRYPTION;
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 31);
    let mut sd = signed_data(&sign(&env, Signer::explicit(&signatory.credential())));
    let mut infos: Vec<_> = sd.signer_infos.0.iter().cloned().collect();
    // MD5, which nothing registered hashes, with rsaEncryption, which names no hash itself.
    infos[0].digest_alg = spki::AlgorithmIdentifierOwned {
        oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
        parameters: None,
    };
    infos[0].signature_algorithm = spki::AlgorithmIdentifierOwned {
        oid: RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    };
    sd.signer_infos = cms::signed_data::SignerInfos::try_from(infos).unwrap();
    assert!(matches!(
        env.verify_signed_data(&content_info(&sd), None, None, SignerPolicy::All),
        Err(Error::Unrecognized)
    ));
}

/// A signer named by identifier whose certificate a source holds, with a key usage that does not
/// permit signing, is reported for the key usage, as vetting would report it.
#[test]
fn a_named_signing_credential_refused_for_key_usage_says_so() {
    let ca = Ca::new("CN=test CA");
    let mut env = environment(&ca, &[]);
    let encipherment_only =
        rsa_signatory_with(&ca, 32, vec![key_usage(KeyUsages::KeyEncipherment)]);
    env.add_signing_credential_source(SingleSigningCredential::new(Arc::new(
        encipherment_only.credential(),
    )));
    let sid = signer_identifier(&encipherment_only.cert).unwrap();
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::by_identifier(sid))
            .build(&env),
        Err(Error::Certval(certval::Error::PathValidation(
            PathValidationStatus::InvalidKeyUsage
        )))
    ));
    // Found by email address, where several may answer, it is simply not among them.
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::by_subject(
                encipherment_only.cert.tbs_certificate().subject().clone()
            ))
            .build(&env),
        Err(Error::NoMatchingSigner)
    ));
}

/// The builder adds content-type and message-digest; a second one from the caller would make a
/// message the verifier refuses, so the build refuses it first.
#[test]
fn a_signed_attribute_the_builder_adds_is_refused() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 33);
    let credential = signatory.credential();
    let mut values = SetOfVec::new();
    values.insert(Any::encode_from(&ID_DATA).unwrap()).unwrap();
    let content_type = x509_cert::attr::Attribute {
        oid: ID_CONTENT_TYPE,
        values,
    };
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::explicit(&credential).signed_attribute(content_type))
            .build(&env),
        Err(Error::InvalidInput(_))
    ));
}

/// Debug on a key names its certificate and the kind of key, never the key; on an environment,
/// what is registered where.
#[test]
fn debug_output_names_keys_without_showing_them() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 34);
    let shown = format!("{:?}", signatory.credential());
    assert!(shown.contains("CN=entity 34"), "{shown}");
    assert!(shown.contains("Rsa"), "{shown}");
    assert!(shown.len() < 200, "{shown}");
    let shown = format!("{env:?}");
    assert!(shown.contains("pki_environment: true"), "{shown}");
    assert!(shown.contains("encrypt_content: 1"), "{shown}");
}

#[test]
fn a_content_type_attribute_that_does_not_match_is_refused() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 10);
    let mut sd = signed_data(&sign(&env, Signer::explicit(&signatory.credential())));
    sd.encap_content_info.econtent_type = ID_ENVELOPED_DATA;
    assert!(matches!(
        env.verify_signed_data(&content_info(&sd), None, None, SignerPolicy::All),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn the_signer_policy_decides_whether_one_failure_fails_the_message() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let good = rsa_signatory(&ca, 11);
    let other = Ca::new("CN=other CA");
    let untrusted = rsa_signatory(&other, 12);
    let (good_key, untrusted_key) = (good.credential(), untrusted.credential());
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&good_key))
        .add_signer(Signer::explicit(&untrusted_key))
        .build(&env)
        .unwrap()
        .content_info;
    assert!(env
        .verify_signed_data(&ci, None, Some(&settings()), SignerPolicy::All)
        .is_err());
    let verified = env
        .verify_signed_data(&ci, None, Some(&settings()), SignerPolicy::Any)
        .unwrap();
    assert_eq!(verified.signers.len(), 1);
    assert_eq!(verified.failed.len(), 1);
}

#[test]
fn a_signed_data_with_no_signers_is_not_verified_but_its_certificates_are_read() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 13);
    let mut sd = signed_data(&sign(&env, Signer::explicit(&signatory.credential())));
    assert!(matches!(
        certificates_only(&content_info(&sd)),
        Err(Error::InvalidInput(_))
    ));
    sd.signer_infos = cms::signed_data::SignerInfos::try_from(vec![]).unwrap();
    let ci = content_info(&sd);
    assert!(matches!(
        env.verify_signed_data(&ci, None, None, SignerPolicy::Any),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(
        certificates_only(&ci).unwrap(),
        vec![signatory.cert.clone()]
    );
}

// ---- an intermediate only the message carries

#[test]
fn an_intermediate_only_the_message_carries_is_used_and_reported() {
    let root = Ca::new("CN=root CA");
    let intermediate = root.intermediate("CN=intermediate CA");
    let signatory = rsa_signatory(&intermediate, 14);
    let credential = signatory.credential();

    // The environment trusts the root but lacks the intermediate, which the message carries.
    let env = environment(&root, &[]);
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&credential))
        .add_certificate(intermediate.cert.clone())
        .build(&env)
        .unwrap()
        .content_info;
    let verified = env
        .verify_signed_data(&ci, None, Some(&settings()), SignerPolicy::All)
        .unwrap();
    assert!(matches!(verified.signers[0].vetting, Vetting::Validated(_)));
    assert_eq!(
        verified.signers[0].message_ca_certificates,
        vec![intermediate.cert.clone()]
    );

    // An environment that already has the intermediate needs nothing from the message.
    let env = environment(&root, &[&intermediate.cert]);
    let verified = env
        .verify_signed_data(&ci, None, Some(&settings()), SignerPolicy::All)
        .unwrap();
    assert!(verified.signers[0].message_ca_certificates.is_empty());

    // Without the intermediate anywhere, there is no path.
    let bare = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&credential))
        .build(&environment(&root, &[]))
        .unwrap()
        .content_info;
    assert!(environment(&root, &[])
        .verify_signed_data(&bare, None, Some(&settings()), SignerPolicy::All)
        .is_err());
}

/// The message's CA certificates are followed by issuer name. Many bearing the signer's issuer's
/// name but not its key are each examined once and passed over, and the intermediate among them
/// is found; without it, the message fails as it would with no CA certificates at all.
#[test]
fn ca_certificates_bearing_the_issuers_name_without_its_key_are_passed_over() {
    use std::str::FromStr;
    let root = Ca::new("CN=root CA");
    let intermediate = root.intermediate("CN=intermediate CA");
    let signatory = rsa_signatory(&intermediate, 30);
    let credential = signatory.credential();
    let env = environment(&root, &[]);
    let name = Name::from_str("CN=intermediate CA").unwrap();
    let lookalikes: Vec<Certificate> = (0..12u8)
        .map(|serial| {
            let key = p256::ecdsa::SigningKey::from(p256::SecretKey::generate_from_rng(&mut rng()));
            let spki = key.verifying_key().to_public_key_der().unwrap();
            issue_by::<_, p256::ecdsa::DerSignature>(
                &key,
                &name,
                "CN=intermediate CA",
                spki.as_bytes(),
                100 + serial,
                ca_extensions(),
            )
        })
        .collect();

    let mut builder = SignedDataBuilder::new(MESSAGE);
    builder.add_signer(Signer::explicit(&credential));
    for cert in &lookalikes {
        builder.add_certificate(cert.clone());
    }
    let without = builder.build(&env).unwrap().content_info;
    builder.add_certificate(intermediate.cert.clone());
    let with = builder.build(&env).unwrap().content_info;

    let started = std::time::Instant::now();
    let verified = env
        .verify_signed_data(&with, None, Some(&settings()), SignerPolicy::All)
        .unwrap();
    assert!(matches!(verified.signers[0].vetting, Vetting::Validated(_)));
    assert_eq!(
        verified.signers[0].message_ca_certificates,
        vec![intermediate.cert.clone()]
    );
    assert!(matches!(
        env.verify_signed_data(&without, None, Some(&settings()), SignerPolicy::All),
        Err(Error::Certval(_))
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

// ---- OpenSSL

fn openssl() -> Option<String> {
    match std::env::var("CERTVAL_CMS_OPENSSL") {
        Ok(openssl) => Some(openssl),
        Err(_) => {
            eprintln!("skipped: CERTVAL_CMS_OPENSSL is not set");
            None
        }
    }
}

fn pem(cert: &Certificate) -> String {
    use x509_cert::der::EncodePem;
    cert.to_pem(der::pem::LineEnding::LF).unwrap()
}

#[test]
fn openssl_and_this_crate_verify_each_others_messages() {
    let Some(openssl) = openssl() else { return };
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, pem(&ca.cert)).unwrap();
    let content_path = dir.path().join("content");
    std::fs::write(&content_path, MESSAGE).unwrap();

    let rsa = rsa_signatory(&ca, 15);
    let ec = ec_signatory!(p384, ca, 16);
    for (name, signatory) in [("RSA", &rsa), ("ECDSA", &ec)] {
        let cert_path = dir.path().join("signer.pem");
        let key_path = dir.path().join("signer.key");
        std::fs::write(&cert_path, pem(&signatory.cert)).unwrap();
        std::fs::write(
            &key_path,
            der::pem::encode_string("PRIVATE KEY", der::pem::LineEnding::LF, &signatory.pkcs8)
                .unwrap(),
        )
        .unwrap();

        // OpenSSL signs; this crate verifies.
        let output = Command::new(&openssl)
            .args([
                "cms",
                "-sign",
                "-binary",
                "-nodetach",
                "-outform",
                "DER",
                "-in",
            ])
            .arg(&content_path)
            .arg("-signer")
            .arg(&cert_path)
            .arg("-inkey")
            .arg(&key_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ci = ContentInfo::from_der(&output.stdout).unwrap();
        let verified = env
            .verify_signed_data(&ci, None, Some(&settings()), SignerPolicy::All)
            .unwrap_or_else(|e| panic!("{name}, OpenSSL's message: {e}"));
        assert_eq!(verified.content, MESSAGE);

        // This crate signs; OpenSSL verifies.
        let signed = sign(&env, Signer::explicit(&signatory.credential()));
        let signed_path = dir.path().join("signed.der");
        std::fs::write(&signed_path, signed.to_der().unwrap()).unwrap();
        let output = Command::new(&openssl)
            .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
            .arg(&signed_path)
            .arg("-CAfile")
            .arg(&ca_path)
            .args(["-purpose", "any"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}, this crate's message: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, MESSAGE);
    }

    // A signature::Signer fixed at ecdsa-with-SHA384, with the signer's digest left to follow it;
    // OpenSSL hashes the signed attributes with digestAlgorithm, so the two must agree.
    {
        use certval_cms::SignerCredential;
        use p384::pkcs8::DecodePrivateKey;
        let signer = p384::ecdsa::SigningKey::from_pkcs8_der(&ec.pkcs8).unwrap();
        let credential =
            SignerCredential::<_, p384::ecdsa::DerSignature>::new(ec.cert.clone(), signer);
        let signed = sign(&env, Signer::explicit(&credential));
        let signed_path = dir.path().join("signed.der");
        std::fs::write(&signed_path, signed.to_der().unwrap()).unwrap();
        let output = Command::new(&openssl)
            .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
            .arg(&signed_path)
            .arg("-CAfile")
            .arg(&ca_path)
            .args(["-purpose", "any"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "SignerCredential, this crate's message: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, MESSAGE);
    }
}

// ---- ESS signing-certificate

fn signed_attribute_types(ci: &ContentInfo) -> Vec<const_oid::ObjectIdentifier> {
    let sd = signed_data(ci);
    let info = sd.signer_infos.0.iter().next().unwrap();
    info.signed_attrs
        .as_ref()
        .unwrap()
        .iter()
        .map(|a| a.oid)
        .collect()
}

#[test]
fn an_ess_cert_id_is_added_unless_left_out() {
    use const_oid::db::rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2;
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 17);
    let credential = signatory.credential();

    let ci = sign(&env, Signer::explicit(&credential));
    assert!(signed_attribute_types(&ci).contains(&ID_AA_SIGNING_CERTIFICATE_V_2));
    assert_verifies_vetted(&env, &ci, "with an ESSCertIDv2");

    let ci = sign(&env, Signer::explicit(&credential).without_ess_cert_id());
    assert!(!signed_attribute_types(&ci).contains(&ID_AA_SIGNING_CERTIFICATE_V_2));
    assert_verifies_vetted(&env, &ci, "without an ESSCertIDv2");
}

#[test]
fn another_certificate_for_the_same_key_is_refused() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 18);
    // A second certificate for the same key: the same subject key identifier, so the SignerInfo's
    // identifier matches it too.
    let substitute = ca.issue(
        signatory
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap()
            .as_slice(),
        19,
        vec![key_usage(KeyUsages::DigitalSignature)],
        day(),
    );
    let credential = signatory.credential();
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&credential))
        .include_certificates(IncludeCertificates::None)
        .add_certificate(substitute)
        .build(&env)
        .unwrap()
        .content_info;
    match env.verify_signed_data(&ci, None, None, SignerPolicy::All) {
        Err(Error::InvalidInput(e)) => {
            assert_eq!(
                e,
                "the signing-certificate-v2 attribute does not identify the signer's certificate"
            )
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
}

// ---- detached content

#[test]
fn detached_content_is_signed_and_verified_when_supplied() {
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 20);
    let credential = signatory.credential();
    let ci = SignedDataBuilder::new(MESSAGE)
        .detached()
        .add_signer(Signer::explicit(&credential))
        .build(&env)
        .unwrap()
        .content_info;
    assert!(signed_data(&ci).encap_content_info.econtent.is_none());
    let verified = env
        .verify_signed_data(&ci, Some(MESSAGE), Some(&settings()), SignerPolicy::All)
        .unwrap();
    assert_eq!(verified.content, MESSAGE);
    assert!(matches!(
        env.verify_signed_data(&ci, None, None, SignerPolicy::All),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        env.verify_signed_data(&ci, Some(b"other content"), None, SignerPolicy::All),
        Err(Error::Crypto(_))
    ));
    // Content passed for a message that carries its own is refused.
    let attached = sign(&env, Signer::explicit(&credential));
    assert!(matches!(
        env.verify_signed_data(&attached, Some(MESSAGE), None, SignerPolicy::All),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn content_hashed_elsewhere_is_signed_by_signers_using_that_digest() {
    use sha2::Digest;
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = ec_signatory!(p384, ca, 21);
    let credential = signatory.credential();
    let digest = sha2::Sha384::digest(MESSAGE);
    let ci = SignedDataBuilder::from_digest(DigestAlgorithm::Sha384, &digest)
        .add_signer(Signer::explicit(&credential).digest(DigestAlgorithm::Sha384))
        .build(&env)
        .unwrap()
        .content_info;
    let verified = env
        .verify_signed_data(&ci, Some(MESSAGE), Some(&settings()), SignerPolicy::All)
        .unwrap();
    assert_eq!(verified.signers.len(), 1);
    assert!(matches!(
        SignedDataBuilder::from_digest(DigestAlgorithm::Sha384, &digest)
            .add_signer(Signer::explicit(&credential))
            .build(&env),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn openssl_verifies_a_detached_message() {
    let Some(openssl) = openssl() else { return };
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 22);
    let ci = SignedDataBuilder::new(MESSAGE)
        .detached()
        .add_signer(Signer::explicit(&signatory.credential()))
        .build(&env)
        .unwrap()
        .content_info;
    let dir = tempfile::tempdir().unwrap();
    let (ca_path, content_path, signed_path) = (
        dir.path().join("ca.pem"),
        dir.path().join("content"),
        dir.path().join("signed.der"),
    );
    std::fs::write(&ca_path, pem(&ca.cert)).unwrap();
    std::fs::write(&content_path, MESSAGE).unwrap();
    std::fs::write(&signed_path, ci.to_der().unwrap()).unwrap();
    let output = Command::new(&openssl)
        .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
        .arg(&signed_path)
        .arg("-content")
        .arg(&content_path)
        .arg("-CAfile")
        .arg(&ca_path)
        .args(["-purpose", "any"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---- signature::Signer through SignerCredential

#[test]
fn a_signature_signer_signs_with_its_own_algorithm() {
    use certval_cms::SignerCredential;
    use rsa::pkcs8::DecodePrivateKey;
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);

    let rsa = rsa_signatory(&ca, 23);
    let rsa_signer = rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(
        rsa::RsaPrivateKey::from_pkcs8_der(&rsa.pkcs8).unwrap(),
    );
    let rsa_credential =
        SignerCredential::<_, rsa::pkcs1v15::Signature>::new(rsa.cert.clone(), rsa_signer);

    // The ECDSA signer's algorithm is fixed at ecdsa-with-SHA384; the signer's digest follows it
    // without being set.
    let ec = ec_signatory!(p384, ca, 24);
    let ec_signer = p384::ecdsa::SigningKey::from_pkcs8_der(&ec.pkcs8).unwrap();
    let ec_credential =
        SignerCredential::<_, p384::ecdsa::DerSignature>::new(ec.cert.clone(), ec_signer);

    let built = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&rsa_credential).digest(DigestAlgorithm::Sha384))
        .add_signer(Signer::explicit(&ec_credential))
        .build(&env)
        .unwrap();
    let sd = signed_data(&built.content_info);
    let algs: Vec<_> = sd
        .signer_infos
        .0
        .iter()
        .map(|si| si.signature_algorithm.oid)
        .collect();
    assert!(algs.contains(&const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION));
    assert!(algs.contains(&const_oid::db::rfc5912::ECDSA_WITH_SHA_384));
    assert_eq!(
        signer_digest_algorithms(&built.content_info),
        vec![DigestAlgorithm::Sha384.oid(); 2]
    );
    let verified = env
        .verify_signed_data(
            &built.content_info,
            None,
            Some(&settings()),
            SignerPolicy::All,
        )
        .unwrap();
    assert_eq!(verified.signers.len(), 2);

    // Asked for another algorithm, the signer declines.
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(
                Signer::explicit(&rsa_credential)
                    .signature_algorithm(rsa_pss(DigestAlgorithm::Sha256).unwrap())
            )
            .build(&env),
        Err(Error::Unrecognized)
    ));

    // A digest set to one the fixed algorithm does not use is refused, in SignedData and in a
    // CredentialSigner.
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::explicit(&ec_credential).digest(DigestAlgorithm::Sha256))
            .build(&env),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        certval_cms::CredentialSigner::new(&env, &ec_credential, DigestAlgorithm::Sha256),
        Err(Error::InvalidInput(_))
    ));
    assert!(
        certval_cms::CredentialSigner::new(&env, &ec_credential, DigestAlgorithm::Sha384).is_ok()
    );
}

// ---- nested content

#[test]
fn signed_and_enveloped_layers_are_unwrapped_in_either_order() {
    use certval_cms::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyTransRecipient, KeyTransportAlgorithm,
        Layer, SoftwareRecipientKey,
    };
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let signatory = rsa_signatory(&ca, 25);
    let signing_key = signatory.credential();
    let key = rsa::RsaPrivateKey::new(&mut rng(), 2048).unwrap();
    let recipient_cert = ca.issue(
        key.to_public_key().to_public_key_der().unwrap().as_bytes(),
        26,
        vec![key_usage(KeyUsages::KeyEncipherment)],
        day(),
    );
    let recipient_key = SoftwareRecipientKey::from_pkcs8_der(
        recipient_cert.clone(),
        key.to_pkcs8_der().unwrap().as_bytes(),
    )
    .unwrap();
    let envelop = |content: &[u8], content_type| {
        let recipient = KeyTransRecipient::from_certificate(
            &env,
            &recipient_cert,
            Some(&settings()),
            KeyTransportAlgorithm::RsaOaepSha256,
        )
        .unwrap();
        let mut builder =
            EnvelopedDataBuilder::new(content, ContentEncryptionAlgorithm::Aes256Cbc).unwrap();
        builder.content_type(content_type);
        builder
            .add_recipient(recipient)
            .build_content_info(&env, &mut rng())
            .unwrap()
    };
    let sign_as = |content: &[u8], content_type| {
        SignedDataBuilder::new(content)
            .content_type(content_type)
            .add_signer(Signer::explicit(&signing_key))
            .build(&env)
            .unwrap()
            .content_info
    };

    // Signed, then enveloped: SignedData inside EnvelopedData.
    let signed = sign_as(MESSAGE, ID_DATA);
    let outer = envelop(
        &signed.content.to_der().unwrap(),
        const_oid::db::rfc5911::ID_SIGNED_DATA,
    );
    let unwrapped = env
        .unwrap_content_info(
            &outer,
            Some(&recipient_key),
            Some(&settings()),
            SignerPolicy::All,
        )
        .unwrap();
    assert!(matches!(
        unwrapped.layers.as_slice(),
        [Layer::Enveloped(_), Layer::Signed(_)]
    ));
    assert_eq!(unwrapped.content_type, ID_DATA);
    assert_eq!(unwrapped.content, MESSAGE);

    // Enveloped, then signed: EnvelopedData inside SignedData.
    let enveloped = envelop(MESSAGE, ID_DATA);
    let outer = sign_as(&enveloped.content.to_der().unwrap(), ID_ENVELOPED_DATA);
    let unwrapped = env
        .unwrap_content_info(
            &outer,
            Some(&recipient_key),
            Some(&settings()),
            SignerPolicy::All,
        )
        .unwrap();
    assert!(matches!(
        unwrapped.layers.as_slice(),
        [Layer::Signed(_), Layer::Enveloped(_)]
    ));
    assert_eq!(unwrapped.content, MESSAGE);
}

// ---- ML-DSA

/// RFC 9881: an ML-DSA signer's message digest is SHA-512 unless set.
#[cfg(feature = "pqc")]
#[test]
fn an_ml_dsa_signer_digests_with_sha512_by_default() {
    use ml_dsa::common::Generate as _;
    use ml_dsa::signature::Keypair;
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate_from_rng(&mut rng());
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let cert = ca.issue(
        spki.as_bytes(),
        35,
        vec![key_usage(KeyUsages::DigitalSignature)],
        day(),
    );
    let signatory = Signatory {
        cert,
        pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
    };
    let ci = sign(&env, Signer::explicit(&signatory.credential()));
    assert_eq!(
        signer_digest_algorithms(&ci),
        vec![DigestAlgorithm::Sha512.oid()]
    );
    assert_verifies_vetted(&env, &ci, "ML-DSA-65 with its default digest");
}

#[cfg(feature = "pqc")]
macro_rules! ml_dsa_round_trip {
    ($params:ty, $serial:expr) => {{
        use ml_dsa::common::Generate as _;
        use ml_dsa::signature::Keypair;
        let ca = Ca::new("CN=test CA");
        let env = environment(&ca, &[]);
        let key = ml_dsa::SigningKey::<$params>::generate_from_rng(&mut rng());
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let cert = ca.issue(
            spki.as_bytes(),
            $serial,
            vec![key_usage(KeyUsages::DigitalSignature)],
            day(),
        );
        let signatory = Signatory {
            cert,
            pkcs8: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        };
        let ci = sign(&env, Signer::explicit(&signatory.credential()));
        assert_verifies_vetted(&env, &ci, stringify!($params));
    }};
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_with_each_parameter_set() {
    ml_dsa_round_trip!(ml_dsa::MlDsa44, 27);
    ml_dsa_round_trip!(ml_dsa::MlDsa65, 28);
    ml_dsa_round_trip!(ml_dsa::MlDsa87, 29);
}

/// An ML-DSA key OpenSSL generated, in the `both` form OpenSSL writes, signs here, and OpenSSL
/// verifies the message.
#[cfg(feature = "pqc")]
#[test]
fn an_openssl_ml_dsa_key_signs_and_openssl_verifies() {
    let Some(openssl) = openssl() else { return };
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.der");
    let status = Command::new(&openssl)
        .args([
            "genpkey",
            "-algorithm",
            "ML-DSA-65",
            "-outform",
            "DER",
            "-out",
        ])
        .arg(&key_path)
        .status()
        .unwrap();
    if !status.success() {
        eprintln!("skipped: {openssl} has no ML-DSA");
        return;
    }
    let output = Command::new(&openssl)
        .args([
            "pkey", "-inform", "DER", "-pubout", "-outform", "DER", "-in",
        ])
        .arg(&key_path)
        .output()
        .unwrap();
    let ca = Ca::new("CN=test CA");
    let env = environment(&ca, &[]);
    let cert = ca.issue(
        &output.stdout,
        30,
        vec![key_usage(KeyUsages::DigitalSignature)],
        day(),
    );
    let credential =
        SoftwareSigningKey::from_pkcs8_der(cert, &std::fs::read(&key_path).unwrap()).unwrap();
    let ci = sign(&env, Signer::explicit(&credential));

    let (ca_path, signed_path) = (dir.path().join("ca.pem"), dir.path().join("signed.der"));
    std::fs::write(&ca_path, pem(&ca.cert)).unwrap();
    std::fs::write(&signed_path, ci.to_der().unwrap()).unwrap();
    let output = Command::new(&openssl)
        .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
        .arg(&signed_path)
        .arg("-CAfile")
        .arg(&ca_path)
        .args(["-purpose", "any"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, MESSAGE);
}

// ---- signing credentials found by email address and subject

/// A person's encryption and signature credentials and a credential with no key usage extension,
/// all containing the same email address, registered in that order.
fn environment_with_one_persons_credentials(ca: &Ca) -> (CmsEnvironment, [Signatory; 3]) {
    const EMAIL: &str = "signer@example.com";
    let mut env = environment(ca, &[]);
    let signatories = [
        rsa_signatory_with(
            ca,
            20,
            vec![key_usage(KeyUsages::KeyEncipherment), email_address(EMAIL)],
        ),
        rsa_signatory_with(
            ca,
            21,
            vec![
                key_usage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
                email_address(EMAIL),
            ],
        ),
        rsa_signatory_with(ca, 22, vec![email_address(EMAIL)]),
    ];
    for signatory in &signatories {
        env.add_signing_credential_source(SingleSigningCredential::new(Arc::new(
            signatory.credential(),
        )));
    }
    (env, signatories)
}

#[test]
fn the_signing_credentials_found_by_email_address_are_those_permitting_signing() {
    let ca = Ca::new("CN=test CA");
    let (env, signatories) = environment_with_one_persons_credentials(&ca);
    let found = env
        .find_signing_credentials(SigningCredentialLookup::EmailAddress("signer@EXAMPLE.com"))
        .unwrap();
    let found: Vec<(&Certificate, usize)> =
        found.iter().map(|(c, i)| (c.certificate(), *i)).collect();
    assert_eq!(
        found,
        [(&signatories[1].cert, 1), (&signatories[2].cert, 2)]
    );
    assert!(env
        .find_signing_credentials(SigningCredentialLookup::EmailAddress("Signer@example.com"))
        .unwrap()
        .is_empty());
}

#[test]
fn a_signer_found_by_email_address_signs_with_the_first_credential_permitting_signing() {
    let ca = Ca::new("CN=test CA");
    let (env, signatories) = environment_with_one_persons_credentials(&ca);
    let built = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::by_email_address("signer@example.com"))
        .build(&env)
        .unwrap();
    assert_eq!(built.signers[0].credential, CredentialOrigin::Source(1));
    let verified = env
        .verify_signed_data(
            &built.content_info,
            None,
            Some(&settings()),
            SignerPolicy::All,
        )
        .unwrap();
    assert_eq!(verified.signers[0].certificate, signatories[1].cert);
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::by_email_address("someone@example.com"))
            .build(&env),
        Err(Error::NoMatchingSigner)
    ));
}

#[test]
fn a_signer_found_by_subject_signs() {
    let ca = Ca::new("CN=test CA");
    let (env, signatories) = environment_with_one_persons_credentials(&ca);
    let subject = signatories[2].cert.tbs_certificate().subject().clone();
    let built = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::by_subject(subject))
        .build(&env)
        .unwrap();
    assert_eq!(built.signers[0].credential, CredentialOrigin::Source(2));
    assert!(matches!(
        SignedDataBuilder::new(MESSAGE)
            .add_signer(Signer::by_subject("CN=entity 20".parse::<Name>().unwrap()))
            .build(&env),
        Err(Error::NoMatchingSigner)
    ));
}
