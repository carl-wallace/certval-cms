//! Decryption: messages built here, for every recipient type and algorithm, decrypted again through
//! the environment with software credentials, found both explicitly and through sources; recipient
//! matching by subject key identifier and by issuer and serial number; and the failure behavior.
//!
//! With `CERTVAL_CMS_OPENSSL` set to an `openssl` command, messages that `openssl cms -encrypt`
//! builds, which shares no code with this crate, are decrypted here too. ML-KEM recipients need
//! OpenSSL 3.6 or later there.

use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use certval_cms::{
    unpad_pkcs1v15, AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm,
    CredentialOrigin, EnvelopedDataBuilder, Error, GcmParameters, KdfAlgorithm, KemRecipient,
    KeyAgreeRecipient, KeyAgreementAlgorithm, KeyTransRecipient, KeyTransportAlgorithm,
    KeyWrapAlgorithm, RecipientCredential, RecipientInfoBuilder, SingleRecipientCredential,
    SoftwareRecipientKey,
};
use cms::{
    cert::x509::attr::Attribute, content_info::ContentInfo, enveloped_data::RecipientIdentifier,
};
use const_oid::db::rfc5911::{ID_CONTENT_TYPE, ID_DATA, ID_ENVELOPED_DATA};
use const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::{
    asn1::{OctetString, SetOfVec},
    Any, Decode, Encode,
};
use elliptic_curve::Generate as _;
use getrandom::SysRng;
use ml_kem::{Kem, MlKem1024, MlKem512, MlKem768};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand_core::UnwrapErr;
use sha1::{Digest, Sha1};
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    ext::{pkix::SubjectKeyIdentifier, Extension},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate, TbsCertificate,
};
use zeroize::Zeroizing;

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] =
    b"certval-cms decryption, longer than one AES block so that padding is exercised";

const CONTENT: [ContentEncryptionAlgorithm; 6] = [
    ContentEncryptionAlgorithm::Aes128Cbc,
    ContentEncryptionAlgorithm::Aes192Cbc,
    ContentEncryptionAlgorithm::Aes256Cbc,
    ContentEncryptionAlgorithm::Aes128Gcm,
    ContentEncryptionAlgorithm::Aes192Gcm,
    ContentEncryptionAlgorithm::Aes256Gcm,
];

const WRAPS: [KeyWrapAlgorithm; 3] = [
    KeyWrapAlgorithm::Aes128,
    KeyWrapAlgorithm::Aes192,
    KeyWrapAlgorithm::Aes256,
];

const UKMS: [Option<&[u8]>; 2] = [None, Some(b"user keying material")];

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

fn software() -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env
}

// ---- certificates

/// Issues leaf certificates for any key from a fixed test CA, with or without a subject key
/// identifier.
struct TestProfile {
    subject: Name,
    skid: bool,
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        Name::from_str("CN=certval-cms test CA").unwrap()
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
        if !self.skid {
            return Ok(vec![]);
        }
        let skid = SubjectKeyIdentifier(
            OctetString::new(Sha1::digest(spk.subject_public_key.raw_bytes()).to_vec()).unwrap(),
        );
        Ok(vec![Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(skid.to_der().unwrap()).unwrap(),
        }])
    }
}

fn certificate(spki_der: &[u8], subject: &str, serial: u8, skid: bool) -> Certificate {
    let ca = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let profile = TestProfile {
        subject: Name::from_str(subject).unwrap(),
        skid,
    };
    CertificateBuilder::new(
        profile,
        SerialNumber::new(&[serial]).unwrap(),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        SubjectPublicKeyInfoOwned::from_der(spki_der).unwrap(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&ca)
    .unwrap()
}

/// A recipient's certificate and its private key as PKCS #8.
struct Recipient {
    cert: Certificate,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl Recipient {
    fn credential(&self) -> SoftwareRecipientKey {
        SoftwareRecipientKey::from_pkcs8_der(self.cert.clone(), &self.pkcs8).unwrap()
    }
}

fn rsa_recipient(serial: u8, skid: bool) -> Recipient {
    let key = rsa::PrivateKey::new(&mut rng(), 2048).unwrap();
    let spki = key.to_public_key().to_public_key_der().unwrap();
    Recipient {
        cert: certificate(spki.as_bytes(), "CN=rsa recipient", serial, skid),
        pkcs8: Zeroizing::new(key.to_pkcs8_der().unwrap().as_bytes().to_vec()),
    }
}

macro_rules! ec_recipient {
    ($curve:ident, $serial:expr) => {{
        let key = $curve::SecretKey::generate_from_rng(&mut rng());
        let spki = key.public_key().to_public_key_der().unwrap();
        Recipient {
            cert: certificate(spki.as_bytes(), "CN=ec recipient", $serial, true),
            pkcs8: Zeroizing::new(key.to_pkcs8_der().unwrap().as_bytes().to_vec()),
        }
    }};
}

macro_rules! kem_recipient {
    ($kem:ty, $serial:expr) => {{
        let (dk, ek) = <$kem as Kem>::generate_keypair_from_rng(&mut rng());
        let spki = ek.to_public_key_der().unwrap();
        Recipient {
            cert: certificate(spki.as_bytes(), "CN=kem recipient", $serial, true),
            pkcs8: Zeroizing::new(dk.to_pkcs8_der().unwrap().as_bytes().to_vec()),
        }
    }};
}

// ---- messages

fn content_type_attrs() -> SetOfVec<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(Any::encode_from(&ID_DATA).unwrap()).unwrap();
    let mut attrs = SetOfVec::new();
    attrs
        .insert(Attribute {
            oid: ID_CONTENT_TYPE,
            values,
        })
        .unwrap();
    attrs
}

/// A message to `recipients` with `alg`: EnvelopedData for CBC, and AuthEnvelopedData with a
/// content-type authenticated attribute for GCM.
fn envelop<'e>(
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    recipients: Vec<Box<dyn RecipientInfoBuilder<Rng = Rng> + 'e>>,
) -> ContentInfo {
    if alg.is_authenticated() {
        let mut builder = AuthEnvelopedDataBuilder::new(MESSAGE, alg).unwrap();
        builder.auth_attrs(content_type_attrs());
        for r in recipients {
            builder.add_recipient(r);
        }
        builder.build_content_info(env, &mut rng()).unwrap()
    } else {
        let mut builder = EnvelopedDataBuilder::new(MESSAGE, alg).unwrap();
        for r in recipients {
            builder.add_recipient(r);
        }
        builder.build_content_info(env, &mut rng()).unwrap()
    }
}

fn key_trans<'e>(
    env: &'e CmsEnvironment,
    r: &Recipient,
    alg: KeyTransportAlgorithm,
) -> Box<dyn RecipientInfoBuilder<Rng = Rng> + 'e> {
    Box::new(KeyTransRecipient::from_certificate(env, &r.cert, None, alg).unwrap())
}

fn assert_decrypts(
    env: &CmsEnvironment,
    ci: &ContentInfo,
    credential: &dyn RecipientCredential,
    name: &str,
) {
    let decrypted = env
        .decrypt_enveloped_data(ci, Some(credential))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(decrypted.content.as_slice(), MESSAGE, "{name}");
    assert_eq!(decrypted.content_type, ID_DATA, "{name}");
    assert_eq!(decrypted.credential, CredentialOrigin::Explicit, "{name}");
}

// ---- round trips

#[test]
fn key_transport_with_each_algorithm_and_content_encryption() {
    let env = software();
    let recipient = rsa_recipient(1, true);
    let credential = recipient.credential();
    for alg in [
        KeyTransportAlgorithm::RsaPkcs1v15,
        KeyTransportAlgorithm::RsaOaepSha1,
        KeyTransportAlgorithm::RsaOaepSha256,
        KeyTransportAlgorithm::RsaOaepSha384,
        KeyTransportAlgorithm::RsaOaepSha512,
    ] {
        for content in CONTENT {
            let ci = envelop(&env, content, vec![key_trans(&env, &recipient, alg)]);
            assert_decrypts(&env, &ci, &credential, &format!("{alg:?} {content:?}"));
        }
    }
}

#[test]
fn authenticated_attributes_are_returned() {
    let env = software();
    let recipient = rsa_recipient(1, true);
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Gcm,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha256,
        )],
    );
    let decrypted = env
        .decrypt_enveloped_data(&ci, Some(&recipient.credential()))
        .unwrap();
    assert_eq!(decrypted.auth_attrs, Some(content_type_attrs()));
}

macro_rules! key_agreement_round_trips {
    ($curve:ident) => {{
        let env = software();
        let recipient = ec_recipient!($curve, 2);
        let credential = recipient.credential();
        for alg in [
            KeyAgreementAlgorithm::EcdhSha256,
            KeyAgreementAlgorithm::EcdhSha384,
            KeyAgreementAlgorithm::EcdhSha512,
            KeyAgreementAlgorithm::EcdhCofactorSha256,
            KeyAgreementAlgorithm::EcdhCofactorSha384,
            KeyAgreementAlgorithm::EcdhCofactorSha512,
        ] {
            for wrap in WRAPS {
                for ukm in UKMS {
                    let r = KeyAgreeRecipient::from_certificate(
                        &env,
                        &recipient.cert,
                        None,
                        alg,
                        wrap,
                        ukm.map(<[u8]>::to_vec),
                    )
                    .unwrap();
                    let ci = envelop(
                        &env,
                        ContentEncryptionAlgorithm::Aes256Gcm,
                        vec![Box::new(r)],
                    );
                    assert_decrypts(&env, &ci, &credential, &format!("{alg:?} {wrap:?} {ukm:?}"));
                }
            }
        }
    }};
}

#[test]
fn key_agreement_on_p256() {
    key_agreement_round_trips!(p256);
}

#[test]
fn key_agreement_on_p384() {
    key_agreement_round_trips!(p384);
}

#[test]
fn key_agreement_on_p521() {
    key_agreement_round_trips!(p521);
}

/// A KeyAgreeRecipientInfo to a P-256 recipient whose originator key's algorithm identifier is
/// replaced: absent or NULL parameters decrypt, as RFC 5753 allows; another curve or another
/// algorithm is refused.
#[test]
fn an_originator_key_not_on_the_recipients_curve_is_refused() {
    use cms::enveloped_data::{EnvelopedData, OriginatorIdentifierOrKey, RecipientInfo};
    use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_384_R_1};

    let env = software();
    let recipient = ec_recipient!(p256, 25);
    let r = KeyAgreeRecipient::from_certificate(
        &env,
        &recipient.cert,
        None,
        KeyAgreementAlgorithm::EcdhSha256,
        KeyWrapAlgorithm::Aes256,
        None,
    )
    .unwrap();
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Cbc,
        vec![Box::new(r)],
    );
    let relabelled = |oid, parameters: Option<Any>| {
        let mut ed = EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        let mut infos: Vec<_> = ed.recip_infos.0.iter().cloned().collect();
        let RecipientInfo::Kari(kari) = &mut infos[0] else {
            panic!("not key agreement");
        };
        let OriginatorIdentifierOrKey::OriginatorKey(key) = &mut kari.originator else {
            panic!("no originator key");
        };
        key.algorithm.oid = oid;
        key.algorithm.parameters = parameters;
        ed.recip_infos = cms::enveloped_data::RecipientInfos::try_from(infos).unwrap();
        ContentInfo {
            content_type: ci.content_type,
            content: Any::encode_from(&ed).unwrap(),
        }
    };
    let credential = recipient.credential();

    for (name, parameters) in [
        ("absent parameters", None),
        ("NULL parameters", Some(Any::from(der::asn1::Null))),
    ] {
        assert_decrypts(
            &env,
            &relabelled(ID_EC_PUBLIC_KEY, parameters),
            &credential,
            name,
        );
    }
    for (name, oid, parameters) in [
        (
            "P-384",
            ID_EC_PUBLIC_KEY,
            Some(Any::encode_from(&SECP_384_R_1).unwrap()),
        ),
        (
            "rsaEncryption",
            RSA_ENCRYPTION,
            Some(Any::from(der::asn1::Null)),
        ),
    ] {
        assert!(
            matches!(
                env.decrypt_enveloped_data(&relabelled(oid, parameters), Some(&credential)),
                Err(Error::InvalidInput(_))
            ),
            "{name}"
        );
    }
}

macro_rules! kem_round_trips {
    ($kem:ty) => {{
        let env = software();
        let recipient = kem_recipient!($kem, 3);
        let credential = recipient.credential();
        for kdf in [
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha384,
            KdfAlgorithm::HkdfSha512,
        ] {
            for wrap in WRAPS {
                for ukm in UKMS {
                    let r = KemRecipient::from_certificate(
                        &env,
                        &recipient.cert,
                        None,
                        kdf,
                        wrap,
                        ukm.map(<[u8]>::to_vec),
                    )
                    .unwrap();
                    let ci = envelop(
                        &env,
                        ContentEncryptionAlgorithm::Aes128Cbc,
                        vec![Box::new(r)],
                    );
                    assert_decrypts(&env, &ci, &credential, &format!("{kdf:?} {wrap:?} {ukm:?}"));
                }
            }
        }
    }};
}

#[test]
fn kem_with_ml_kem_512() {
    kem_round_trips!(MlKem512);
}

#[test]
fn kem_with_ml_kem_768() {
    kem_round_trips!(MlKem768);
}

#[test]
fn kem_with_ml_kem_1024() {
    kem_round_trips!(MlKem1024);
}

// ---- recipient matching and sources

#[test]
fn a_recipient_identified_by_issuer_and_serial_number_is_matched() {
    let env = software();
    let recipient = rsa_recipient(4, false);
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes128Cbc,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha256,
        )],
    );
    let decrypted = env
        .decrypt_enveloped_data(&ci, Some(&recipient.credential()))
        .unwrap();
    assert!(matches!(
        decrypted.recipient,
        RecipientIdentifier::IssuerAndSerialNumber(_)
    ));
    assert_eq!(decrypted.content.as_slice(), MESSAGE);
}

#[test]
fn the_recipient_whose_credential_is_available_decrypts() {
    let env = software();
    let rsa = rsa_recipient(5, true);
    let ec = ec_recipient!(p384, 6);
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Cbc,
        vec![
            key_trans(&env, &rsa, KeyTransportAlgorithm::RsaOaepSha256),
            Box::new(
                KeyAgreeRecipient::from_certificate(
                    &env,
                    &ec.cert,
                    None,
                    KeyAgreementAlgorithm::EcdhSha384,
                    KeyWrapAlgorithm::Aes256,
                    None,
                )
                .unwrap(),
            ),
        ],
    );
    let decrypted = env
        .decrypt_enveloped_data(&ci, Some(&ec.credential()))
        .unwrap();
    assert_eq!(decrypted.recipient_index, 1);
    assert_eq!(decrypted.content.as_slice(), MESSAGE);
    let decrypted = env
        .decrypt_enveloped_data(&ci, Some(&rsa.credential()))
        .unwrap();
    assert_eq!(decrypted.recipient_index, 0);
}

#[test]
fn a_registered_source_finds_the_credential() {
    let mut env = software();
    let other = rsa_recipient(7, true);
    let recipient = rsa_recipient(8, true);
    env.add_recipient_credential_source(SingleRecipientCredential::new(Arc::new(
        other.credential(),
    )));
    env.add_recipient_credential_source(SingleRecipientCredential::new(Arc::new(
        recipient.credential(),
    )));
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes128Gcm,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha384,
        )],
    );
    let decrypted = env.decrypt_enveloped_data(&ci, None).unwrap();
    assert_eq!(decrypted.credential, CredentialOrigin::Source(1));
    assert_eq!(decrypted.content.as_slice(), MESSAGE);
}

#[test]
fn an_explicit_credential_that_matches_no_recipient_does_not_fall_back_to_the_sources() {
    let mut env = software();
    let recipient = rsa_recipient(9, true);
    let stranger = rsa_recipient(10, true);
    env.add_recipient_credential_source(SingleRecipientCredential::new(Arc::new(
        recipient.credential(),
    )));
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes128Cbc,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaPkcs1v15,
        )],
    );
    assert!(matches!(
        env.decrypt_enveloped_data(&ci, Some(&stranger.credential())),
        Err(Error::NoMatchingRecipient)
    ));
    assert!(env.decrypt_enveloped_data(&ci, None).is_ok());
}

#[test]
fn a_matched_recipient_with_an_unsupported_algorithm_is_unrecognized() {
    let Some(openssl) = openssl() else { return };
    let env = software();
    let ec = ec_recipient!(p256, 20);
    // OpenSSL's default ECDH scheme, dhSinglePass-stdDH-sha1kdf-scheme.
    let ci = openssl_encrypt(&openssl, &ec.cert, &["-aes-128-cbc"]);
    assert!(matches!(
        env.decrypt_enveloped_data(&ci, Some(&ec.credential())),
        Err(Error::Unrecognized)
    ));
}

#[test]
fn no_source_and_no_credential_matches_nothing() {
    let env = software();
    let recipient = rsa_recipient(11, true);
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes128Cbc,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha1,
        )],
    );
    assert!(matches!(
        env.decrypt_enveloped_data(&ci, None),
        Err(Error::NoMatchingRecipient)
    ));
}

#[test]
fn a_private_key_that_is_not_the_certificates_is_refused() {
    let a = rsa_recipient(12, true);
    let b = rsa_recipient(13, true);
    assert!(matches!(
        SoftwareRecipientKey::from_pkcs8_der(a.cert.clone(), &b.pkcs8),
        Err(Error::InvalidInput(_))
    ));
}

// ---- failures

/// Claims a recipient's certificate but fails every key transport, as a wrong key or a malformed
/// padding would.
struct FailingKeyTransport(Certificate);

impl RecipientCredential for FailingKeyTransport {
    fn certificate(&self) -> &Certificate {
        &self.0
    }
    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        _alg: KeyTransportAlgorithm,
        _encrypted_key: &[u8],
    ) -> certval_cms::Result<Zeroizing<Vec<u8>>> {
        Err(Error::Crypto("padding".into()))
    }
}

/// Claims a recipient's certificate and returns a five-octet key from every key transport, a
/// length no content-encryption algorithm uses.
struct WrongLengthKeyTransport(Certificate);

impl RecipientCredential for WrongLengthKeyTransport {
    fn certificate(&self) -> &Certificate {
        &self.0
    }
    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        _alg: KeyTransportAlgorithm,
        _encrypted_key: &[u8],
    ) -> certval_cms::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0x5a; 5]))
    }
}

#[test]
fn a_failed_pkcs1v15_key_transport_fails_as_content_decryption_does() {
    let env = software();
    let recipient = rsa_recipient(14, true);
    let failing = FailingKeyTransport(recipient.cert.clone());
    let wrong_length = WrongLengthKeyTransport(recipient.cert.clone());
    for (content, credential) in CONTENT.into_iter().flat_map(|content| {
        [
            (content, &failing as &dyn RecipientCredential),
            (content, &wrong_length as &dyn RecipientCredential),
        ]
    }) {
        let ci = envelop(
            &env,
            content,
            vec![key_trans(
                &env,
                &recipient,
                KeyTransportAlgorithm::RsaPkcs1v15,
            )],
        );
        // Neither the credential's error nor its wrong-length key is what is used: a random
        // content-encryption key goes on to content decryption, which fails as it does for a wrong
        // key (RFC 3218, section 2.3.2).
        // GCM always detects it. CBC detects it only when the padding comes out malformed; about
        // one time in 256 it does not, and the result is not the message.
        match env.decrypt_enveloped_data(&ci, Some(credential)) {
            Err(Error::Crypto(e)) => assert_eq!(e, "content decryption failed", "{content:?}"),
            Ok(decrypted) => {
                assert!(!content.is_authenticated(), "{content:?}");
                assert_ne!(decrypted.content.as_slice(), MESSAGE, "{content:?}");
            }
            Err(e) => panic!("{content:?}: {e}"),
        }
    }
}

#[test]
fn a_failed_oaep_key_transport_is_reported() {
    let env = software();
    let recipient = rsa_recipient(15, true);
    let failing = FailingKeyTransport(recipient.cert.clone());
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes128Cbc,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha256,
        )],
    );
    match env.decrypt_enveloped_data(&ci, Some(&failing)) {
        Err(Error::Crypto(e)) => assert_eq!(e, "padding"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[test]
fn a_changed_authenticated_attribute_fails_decryption() {
    let env = software();
    let recipient = rsa_recipient(16, true);
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Gcm,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha256,
        )],
    );
    let mut aed =
        cms::authenveloped_data::AuthEnvelopedData::from_der(&ci.content.to_der().unwrap())
            .unwrap();
    aed.auth_attrs = None;
    let changed = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&aed).unwrap(),
    };
    assert!(matches!(
        env.decrypt_enveloped_data(&changed, Some(&recipient.credential())),
        Err(Error::Crypto(_))
    ));
}

/// RFC 5084, section 3.2: aes-ICVlen is 12 to 16. A message giving a shorter tag, and a mac
/// truncated to match, is malformed, not a tag length this implementation declines.
#[test]
fn a_tag_shorter_than_rfc_5084_allows_is_refused() {
    let env = software();
    let recipient = rsa_recipient(17, true);
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Gcm,
        vec![key_trans(
            &env,
            &recipient,
            KeyTransportAlgorithm::RsaOaepSha256,
        )],
    );
    let mut aed =
        cms::authenveloped_data::AuthEnvelopedData::from_der(&ci.content.to_der().unwrap())
            .unwrap();
    let alg = &mut aed.auth_encrypted_content_info.content_enc_alg;
    let mut params =
        GcmParameters::from_der(&alg.parameters.as_ref().unwrap().to_der().unwrap()).unwrap();
    params.icv_len = 8;
    alg.parameters = Some(Any::encode_from(&params).unwrap());
    aed.mac = OctetString::new(&aed.mac.as_bytes()[..8]).unwrap();
    let shortened = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&aed).unwrap(),
    };
    assert!(matches!(
        env.decrypt_enveloped_data(&shortened, Some(&recipient.credential())),
        Err(Error::InvalidInput(_))
    ));
}

/// RFC 5083, section 2.1: the content type is outside what the tag covers. For a type other than
/// id-data the builder adds a content-type authenticated attribute, and decryption requires the
/// attribute to give the type the message carries.
#[test]
fn a_content_type_other_than_id_data_is_bound_by_an_authenticated_attribute() {
    let env = software();
    let recipient = rsa_recipient(18, true);
    let credential = recipient.credential();
    let recipient_builder = || key_trans(&env, &recipient, KeyTransportAlgorithm::RsaOaepSha256);
    let ci = AuthEnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes256Gcm)
        .unwrap()
        .content_type(ID_ENVELOPED_DATA)
        .add_recipient(recipient_builder())
        .build_content_info(&env, &mut rng())
        .unwrap();
    let decrypted = env.decrypt_enveloped_data(&ci, Some(&credential)).unwrap();
    assert_eq!(decrypted.content_type, ID_ENVELOPED_DATA);
    let attrs = decrypted.auth_attrs.unwrap();
    let content_type_attr = attrs.iter().find(|a| a.oid == ID_CONTENT_TYPE).unwrap();
    assert_eq!(
        content_type_attr.values.iter().collect::<Vec<_>>(),
        vec![&Any::encode_from(&ID_ENVELOPED_DATA).unwrap()]
    );

    // The type relabelled after building no longer matches the attribute.
    let mut aed =
        cms::authenveloped_data::AuthEnvelopedData::from_der(&ci.content.to_der().unwrap())
            .unwrap();
    aed.auth_encrypted_content_info.content_type = ID_DATA;
    let relabelled = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&aed).unwrap(),
    };
    assert!(matches!(
        env.decrypt_enveloped_data(&relabelled, Some(&credential)),
        Err(Error::InvalidInput(_))
    ));

    // A type other than id-data with no attribute at all is malformed.
    aed.auth_encrypted_content_info.content_type = ID_ENVELOPED_DATA;
    aed.auth_attrs = None;
    let unbound = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&aed).unwrap(),
    };
    assert!(matches!(
        env.decrypt_enveloped_data(&unbound, Some(&credential)),
        Err(Error::InvalidInput(_))
    ));

    // An attribute the caller gives must agree with the type.
    let mut builder =
        AuthEnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes256Gcm).unwrap();
    builder
        .content_type(ID_ENVELOPED_DATA)
        .auth_attrs(content_type_attrs())
        .add_recipient(recipient_builder());
    assert!(matches!(
        builder.build_content_info(&env, &mut rng()),
        Err(Error::InvalidInput(_))
    ));
}

/// A RecipientInfo for another recipient that is malformed, here OAEP with its parameters
/// missing, concerns only a credential for that recipient; ours decrypts.
#[test]
fn a_malformed_recipient_info_for_another_recipient_does_not_abort_decryption() {
    let env = software();
    let (first, second) = (rsa_recipient(19, true), rsa_recipient(20, true));
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Cbc,
        vec![
            key_trans(&env, &first, KeyTransportAlgorithm::RsaOaepSha256),
            key_trans(&env, &second, KeyTransportAlgorithm::RsaOaepSha256),
        ],
    );
    let mut ed =
        cms::enveloped_data::EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    let mut infos: Vec<_> = ed.recip_infos.0.iter().cloned().collect();
    let cms::enveloped_data::RecipientInfo::Ktri(ktri) = &mut infos[0] else {
        panic!("not key transport");
    };
    ktri.key_enc_alg.parameters = None;
    let malformed_rid = ktri.rid.clone();
    ed.recip_infos = cms::enveloped_data::RecipientInfos::try_from(infos).unwrap();
    let changed = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&ed).unwrap(),
    };
    for recipient in [&first, &second] {
        let result = env.decrypt_enveloped_data(&changed, Some(&recipient.credential()));
        if certval_cms::recipient_identifier(&recipient.cert).unwrap() == malformed_rid {
            assert!(matches!(result, Err(Error::InvalidInput(_))));
        } else {
            assert_eq!(result.unwrap().content.as_slice(), MESSAGE);
        }
    }
}

// ---- PKCS #1 v1.5 unpadding

#[test]
fn unpadding_accepts_valid_padding_and_refuses_the_rest() {
    let k = 32;
    let mut em = vec![0u8, 2];
    em.extend([0xffu8; 13]);
    em.push(0);
    em.extend([0xabu8; 16]);
    assert_eq!(unpad_pkcs1v15(&em, k).unwrap().as_slice(), &[0xab; 16]);

    let mut bad_header = em.clone();
    bad_header[1] = 1;
    assert!(unpad_pkcs1v15(&bad_header, k).is_err());

    // Seven octets of padding string, one short of the minimum.
    let mut short = vec![0u8, 2];
    short.extend([0xffu8; 7]);
    short.push(0);
    short.extend([0xabu8; 22]);
    assert!(unpad_pkcs1v15(&short, k).is_err());

    let mut no_separator = vec![0u8, 2];
    no_separator.extend([0xffu8; 30]);
    assert!(unpad_pkcs1v15(&no_separator, k).is_err());

    assert!(unpad_pkcs1v15(&em[1..], k).is_err());
}

// ---- messages from OpenSSL

fn openssl() -> Option<String> {
    match std::env::var("CERTVAL_CMS_OPENSSL") {
        Ok(openssl) => Some(openssl),
        Err(_) => {
            eprintln!("skipped: CERTVAL_CMS_OPENSSL is not set");
            None
        }
    }
}

/// The version `openssl version` reports, as (major, minor).
fn openssl_version(openssl: &str) -> (u32, u32) {
    let output = Command::new(openssl).arg("version").output().unwrap();
    let version = String::from_utf8_lossy(&output.stdout);
    let mut numbers = version
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|n| n.parse::<u32>().unwrap_or(0));
    (numbers.next().unwrap_or(0), numbers.next().unwrap_or(0))
}

/// Encrypts `MESSAGE` to `cert` with `openssl cms -encrypt` and the given options.
fn openssl_encrypt(openssl: &str, cert: &Certificate, options: &[&str]) -> ContentInfo {
    use x509_cert::der::EncodePem;
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("recipient.pem");
    std::fs::write(&cert_path, cert.to_pem(der::pem::LineEnding::LF).unwrap()).unwrap();
    let input = dir.path().join("message");
    std::fs::write(&input, MESSAGE).unwrap();
    let output = Command::new(openssl)
        .args(["cms", "-encrypt", "-binary", "-outform", "DER", "-in"])
        .arg(&input)
        .arg("-recip")
        .arg(&cert_path)
        .args(options)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "openssl {options:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ContentInfo::from_der(&output.stdout).unwrap()
}

#[test]
fn messages_openssl_builds_are_decrypted() {
    let Some(openssl) = openssl() else { return };
    let env = software();
    let rsa = rsa_recipient(17, true);
    let ec = ec_recipient!(p256, 18);
    let ec384 = ec_recipient!(p384, 21);
    let ec521 = ec_recipient!(p521, 22);
    let mut cases: Vec<(&Recipient, Vec<&str>)> = vec![
        (&rsa, vec!["-aes-128-cbc"]),
        (
            &rsa,
            vec!["-aes-256-cbc", "-keyopt", "rsa_padding_mode:oaep"],
        ),
        (
            &rsa,
            vec![
                "-aes-192-cbc",
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha256",
                "-keyopt",
                "rsa_mgf1_md:sha256",
            ],
        ),
        (
            &rsa,
            vec![
                "-aes-256-cbc",
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha384",
                "-keyopt",
                "rsa_mgf1_md:sha384",
            ],
        ),
        (
            &rsa,
            vec![
                "-aes-256-gcm",
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha512",
                "-keyopt",
                "rsa_mgf1_md:sha512",
            ],
        ),
        (&rsa, vec!["-aes-256-gcm"]),
        (&rsa, vec!["-aes-192-gcm"]),
        (&rsa, vec!["-aes-128-gcm", "-keyid"]),
        // OpenSSL defaults to dhSinglePass-stdDH-sha1kdf-scheme, which this crate does not
        // process, so the SHA-256 scheme is asked for.
        (&ec, vec!["-aes-256-cbc", "-keyopt", "ecdh_kdf_md:sha256"]),
        (&ec, vec!["-aes-128-gcm", "-keyopt", "ecdh_kdf_md:sha384"]),
        (
            &ec384,
            vec!["-aes-256-cbc", "-keyopt", "ecdh_kdf_md:sha384"],
        ),
        (
            &ec384,
            vec!["-aes-256-gcm", "-keyopt", "ecdh_kdf_md:sha512"],
        ),
        (
            &ec521,
            vec!["-aes-256-cbc", "-keyopt", "ecdh_kdf_md:sha512"],
        ),
        (
            &ec521,
            vec!["-aes-192-gcm", "-keyopt", "ecdh_kdf_md:sha256"],
        ),
    ];
    let kem = kem_recipient!(MlKem768, 19);
    let kem512 = kem_recipient!(MlKem512, 23);
    let kem1024 = kem_recipient!(MlKem1024, 24);
    if openssl_version(&openssl) >= (3, 6) {
        cases.push((&kem, vec!["-aes-256-cbc"]));
        cases.push((&kem, vec!["-aes-256-gcm"]));
        cases.push((&kem512, vec!["-aes-128-gcm"]));
        cases.push((&kem1024, vec!["-aes-256-gcm"]));
    } else {
        eprintln!(
            "skipped for ML-KEM: {openssl} is older than OpenSSL 3.6, which added KEMRecipientInfo"
        );
    }
    for (recipient, options) in cases {
        let ci = openssl_encrypt(&openssl, &recipient.cert, &options);
        let decrypted = env
            .decrypt_enveloped_data(&ci, Some(&recipient.credential()))
            .unwrap_or_else(|e| panic!("{options:?}: {e}"));
        assert_eq!(decrypted.content.as_slice(), MESSAGE, "{options:?}");
    }
}

// ---- ML-KEM private key forms (RFC 9935)

#[derive(der::Sequence)]
struct Both {
    seed: OctetString,
    expanded_key: OctetString,
}

/// The PKCS #8 encoding of an ML-KEM-768 key with `private_key` as its privateKey content.
fn ml_kem_pkcs8(private_key: &[u8]) -> Vec<u8> {
    use rsa::pkcs8::{spki::AlgorithmIdentifierRef, PrivateKeyInfoRef};
    PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid: const_oid::db::fips203::ID_ALG_ML_KEM_768,
            parameters: None,
        },
        der::asn1::OctetStringRef::new(private_key).unwrap(),
    )
    .to_der()
    .unwrap()
}

#[test]
fn ml_kem_private_keys_are_read_in_all_three_forms() {
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    let env = software();
    let (dk, ek) = <MlKem768 as Kem>::generate_keypair_from_rng(&mut rng());
    let cert = certificate(
        ek.to_public_key_der().unwrap().as_bytes(),
        "CN=kem",
        21,
        true,
    );
    let seed = dk.to_seed().unwrap();
    #[allow(deprecated)]
    let expanded = dk.to_expanded_bytes();

    let seed_form = der::asn1::ContextSpecific {
        tag_number: der::TagNumber(0),
        tag_mode: der::TagMode::Implicit,
        value: OctetString::new(seed.as_slice()).unwrap(),
    }
    .to_der()
    .unwrap();
    let expanded_form = OctetString::new(expanded.as_slice())
        .unwrap()
        .to_der()
        .unwrap();
    let both_form = Both {
        seed: OctetString::new(seed.as_slice()).unwrap(),
        expanded_key: OctetString::new(expanded.as_slice()).unwrap(),
    }
    .to_der()
    .unwrap();

    let r = KemRecipient::from_certificate(
        &env,
        &cert,
        None,
        KdfAlgorithm::HkdfSha256,
        KeyWrapAlgorithm::Aes256,
        None,
    )
    .unwrap();
    let ci = envelop(
        &env,
        ContentEncryptionAlgorithm::Aes256Gcm,
        vec![Box::new(r)],
    );
    for (name, form) in [
        ("seed", seed_form),
        ("expanded", expanded_form),
        ("both", both_form),
    ] {
        let credential = SoftwareRecipientKey::from_pkcs8_der(cert.clone(), &ml_kem_pkcs8(&form))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_decrypts(&env, &ci, &credential, name);
    }

    // A `both` whose expanded key is another key's is refused.
    let (other, _) = <MlKem768 as Kem>::generate_keypair_from_rng(&mut rng());
    #[allow(deprecated)]
    let other_expanded = other.to_expanded_bytes();
    let mismatched = Both {
        seed: OctetString::new(seed.as_slice()).unwrap(),
        expanded_key: OctetString::new(other_expanded.as_slice()).unwrap(),
    }
    .to_der()
    .unwrap();
    assert!(matches!(
        SoftwareRecipientKey::from_pkcs8_der(cert, &ml_kem_pkcs8(&mismatched)),
        Err(Error::InvalidInput(_))
    ));
}
