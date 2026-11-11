//! The recipient types, built through a software-populated environment and decrypted again with
//! RustCrypto: RSA key transport with each padding, ECDH key agreement on each curve with each KDF
//! and wrap, and ML-KEM with each parameter set, KDF and wrap, with and without user keying
//! material.
//!
//! With `CERTVAL_CMS_OPENSSL` set to an `openssl` command, the same messages are also decrypted by
//! `openssl cms -decrypt`, which shares no code with this crate. ML-KEM recipients need OpenSSL 3.6
//! or later there, which added KEMRecipientInfo; with an older OpenSSL that test is reported as
//! skipped.

use std::path::Path;
use std::process::Command;

use aes::cipher::KeyInit;
use aes_kw::AesKw;
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use certval_cms::{
    CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder, Error, KdfAlgorithm,
    KemRecipient, KeyAgreeRecipient, KeyAgreementAlgorithm, KeyTransRecipient,
    KeyTransportAlgorithm, KeyWrapAlgorithm, ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384,
};
use cms::{
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{
        EnvelopedData, OriginatorIdentifierOrKey, RecipientIdentifier, RecipientInfo,
    },
    kemri::{CmsOriForKemOtherInfo, KemRecipientInfo, ID_ORI_KEM},
};
use const_oid::db::rfc5753::{
    DH_SINGLE_PASS_COFACTOR_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_COFACTOR_DH_SHA_384_KDF_SCHEME,
    DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME,
};
use der::{
    asn1::{ObjectIdentifier, OctetString},
    Decode, Encode, Sequence,
};
use elliptic_curve::Generate as _;
use getrandom::SysRng;
use hkdf::Hkdf;
use ml_kem::{Decapsulate as _, Kem, MlKem1024, MlKem512, MlKem768};
use rand_core::UnwrapErr;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    Oaep, Pkcs1v15Encrypt, PrivateKey as RsaPrivateKey, PublicKey as RsaPublicKey,
};
use sha2::{Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::ext::pkix::SubjectKeyIdentifier;

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] = b"certval-cms recipients, longer than one AES block so that padding is used";

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

fn software() -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env
}

fn rid() -> RecipientIdentifier {
    RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
        OctetString::new(vec![9, 8, 7, 6]).unwrap(),
    ))
}

fn spki(der: &[u8]) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(der).unwrap()
}

/// Encrypts MESSAGE with AES-256-CBC to one recipient.
fn envelop(
    env: &CmsEnvironment,
    recipient: impl certval_cms::RecipientInfoBuilder<Rng = Rng>,
) -> ContentInfo {
    EnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes256Cbc)
        .unwrap()
        .add_recipient(recipient)
        .build_content_info(env, &mut rng())
        .unwrap()
}

fn enveloped_data(ci: &ContentInfo) -> EnvelopedData {
    EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap()
}

fn the_recipient(ed: &EnvelopedData) -> &RecipientInfo {
    assert_eq!(ed.recip_infos.0.len(), 1);
    &ed.recip_infos.0.as_slice()[0]
}

/// The content, decrypted with the content-encryption key.
fn decrypt_content(ed: &EnvelopedData, cek: &[u8]) -> Vec<u8> {
    let eci = &ed.encrypted_content;
    let iv = eci.content_enc_alg.parameters.as_ref().unwrap();
    let iv = OctetString::from_der(&iv.to_der().unwrap()).unwrap();
    cbc::Decryptor::<aes::Aes256>::new_from_slices(cek, iv.as_bytes())
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(eci.encrypted_content.as_ref().unwrap().as_bytes())
        .unwrap()
}

fn aes_unwrap(wrap: ObjectIdentifier, kek: &[u8], wrapped: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; wrapped.len() - 8];
    let len = match kek.len() {
        16 => AesKw::<aes::Aes128>::new_from_slice(kek)
            .unwrap()
            .unwrap_key(wrapped, &mut out)
            .unwrap()
            .len(),
        24 => AesKw::<aes::Aes192>::new_from_slice(kek)
            .unwrap()
            .unwrap_key(wrapped, &mut out)
            .unwrap()
            .len(),
        32 => AesKw::<aes::Aes256>::new_from_slice(kek)
            .unwrap()
            .unwrap_key(wrapped, &mut out)
            .unwrap()
            .len(),
        n => panic!("{wrap}: KEK of {n} octets"),
    };
    out.truncate(len);
    out
}

const WRAPS: [KeyWrapAlgorithm; 3] = [
    KeyWrapAlgorithm::Aes128,
    KeyWrapAlgorithm::Aes192,
    KeyWrapAlgorithm::Aes256,
];

// ---- key transport

const KEY_TRANSPORTS: [KeyTransportAlgorithm; 5] = [
    KeyTransportAlgorithm::RsaPkcs1v15,
    KeyTransportAlgorithm::RsaOaepSha1,
    KeyTransportAlgorithm::RsaOaepSha256,
    KeyTransportAlgorithm::RsaOaepSha384,
    KeyTransportAlgorithm::RsaOaepSha512,
];

fn rsa_key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut rng(), 2048).unwrap()
}

fn rsa_spki(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
    spki(
        RsaPublicKey::from(key)
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    )
}

fn key_transport(
    env: &CmsEnvironment,
    key: &RsaPrivateKey,
    alg: KeyTransportAlgorithm,
) -> ContentInfo {
    envelop(env, KeyTransRecipient::new(env, rid(), rsa_spki(key), alg))
}

fn decrypt_key_transport(
    key: &RsaPrivateKey,
    alg: KeyTransportAlgorithm,
    ci: &ContentInfo,
) -> Vec<u8> {
    let ed = enveloped_data(ci);
    let RecipientInfo::Ktri(ktri) = the_recipient(&ed) else {
        panic!("expected a KeyTransRecipientInfo");
    };
    assert_eq!(ktri.version, CmsVersion::V2);
    assert_eq!(ktri.key_enc_alg, alg.algorithm_identifier().unwrap());
    let enc = ktri.enc_key.as_bytes();
    let cek = match alg {
        KeyTransportAlgorithm::RsaPkcs1v15 => key.decrypt(Pkcs1v15Encrypt, enc),
        KeyTransportAlgorithm::RsaOaepSha1 => key.decrypt(Oaep::<sha1::Sha1>::new(), enc),
        KeyTransportAlgorithm::RsaOaepSha256 => key.decrypt(Oaep::<Sha256>::new(), enc),
        KeyTransportAlgorithm::RsaOaepSha384 => key.decrypt(Oaep::<Sha384>::new(), enc),
        KeyTransportAlgorithm::RsaOaepSha512 => key.decrypt(Oaep::<Sha512>::new(), enc),
        other => panic!("{other:?}"),
    }
    .unwrap();
    decrypt_content(&ed, &cek)
}

#[test]
fn key_transport_round_trips() {
    let env = software();
    let key = rsa_key();
    for alg in KEY_TRANSPORTS {
        let ci = key_transport(&env, &key, alg);
        assert_eq!(decrypt_key_transport(&key, alg, &ci), MESSAGE, "{alg:?}");
    }
}

// ---- key agreement

const KEY_AGREEMENTS: [KeyAgreementAlgorithm; 6] = [
    KeyAgreementAlgorithm::EcdhSha256,
    KeyAgreementAlgorithm::EcdhSha384,
    KeyAgreementAlgorithm::EcdhSha512,
    KeyAgreementAlgorithm::EcdhCofactorSha256,
    KeyAgreementAlgorithm::EcdhCofactorSha384,
    KeyAgreementAlgorithm::EcdhCofactorSha512,
];

const UKMS: [Option<&[u8]>; 2] = [None, Some(b"user keying material")];

#[derive(Sequence)]
struct EccCmsSharedInfo {
    key_info: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    entity_u_info: Option<OctetString>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    supp_pub_info: OctetString,
}

/// The content-encryption key from a KeyAgreeRecipientInfo, given the ECDH shared secret.
fn kari_cek(kari: &cms::enveloped_data::KeyAgreeRecipientInfo, secret: &[u8]) -> Vec<u8> {
    assert_eq!(kari.version, CmsVersion::V3);
    let wrap = AlgorithmIdentifierOwned::from_der(
        &kari
            .key_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .to_der()
            .unwrap(),
    )
    .unwrap();
    assert!(wrap.parameters.is_none());
    let kek_len = match wrap.oid {
        const_oid::db::rfc5911::ID_AES_128_WRAP => 16,
        const_oid::db::rfc5911::ID_AES_192_WRAP => 24,
        _ => 32,
    };
    let shared_info = EccCmsSharedInfo {
        key_info: wrap.clone(),
        entity_u_info: kari.ukm.clone(),
        supp_pub_info: OctetString::new((kek_len as u32 * 8).to_be_bytes()).unwrap(),
    }
    .to_der()
    .unwrap();
    let mut kek = vec![0u8; kek_len];
    match kari.key_enc_alg.oid {
        DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME
        | DH_SINGLE_PASS_COFACTOR_DH_SHA_256_KDF_SCHEME => {
            ansi_x963_kdf::derive_key_into::<Sha256>(secret, &shared_info, &mut kek)
        }
        DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME
        | DH_SINGLE_PASS_COFACTOR_DH_SHA_384_KDF_SCHEME => {
            ansi_x963_kdf::derive_key_into::<Sha384>(secret, &shared_info, &mut kek)
        }
        _ => ansi_x963_kdf::derive_key_into::<Sha512>(secret, &shared_info, &mut kek),
    }
    .unwrap();
    aes_unwrap(
        wrap.oid,
        &kek,
        kari.recipient_enc_keys[0].enc_key.as_bytes(),
    )
}

/// Round trips on one curve, every scheme, wrap and ukm. Returns the key and a message, for the
/// OpenSSL test.
macro_rules! ec_round_trips {
    ($curve:ident) => {{
        let env = software();
        let key = $curve::SecretKey::generate_from_rng(&mut rng());
        let spki = spki(key.public_key().to_public_key_der().unwrap().as_bytes());
        let mut messages = vec![];
        for alg in KEY_AGREEMENTS {
            for wrap in WRAPS {
                for ukm in UKMS {
                    let recipient = KeyAgreeRecipient::new(
                        &env,
                        rid(),
                        spki.clone(),
                        alg,
                        wrap,
                        ukm.map(<[u8]>::to_vec),
                    );
                    let ci = envelop(&env, recipient);
                    let ed = enveloped_data(&ci);
                    let RecipientInfo::Kari(kari) = the_recipient(&ed) else {
                        panic!("expected a KeyAgreeRecipientInfo");
                    };
                    let OriginatorIdentifierOrKey::OriginatorKey(originator) = &kari.originator
                    else {
                        panic!("expected an originator key");
                    };
                    let ephemeral =
                        $curve::PublicKey::from_sec1_bytes(originator.public_key.raw_bytes())
                            .unwrap();
                    let shared = elliptic_curve::ecdh::diffie_hellman(
                        key.to_nonzero_scalar(),
                        ephemeral.as_affine(),
                    );
                    let cek = kari_cek(kari, shared.raw_secret_bytes());
                    assert_eq!(
                        decrypt_content(&ed, &cek),
                        MESSAGE,
                        "{alg:?} {wrap:?} {ukm:?}"
                    );
                    messages.push((format!("{alg:?} {wrap:?} ukm={}", ukm.is_some()), ci));
                }
            }
        }
        (
            key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
            messages,
        )
    }};
}

#[test]
fn key_agreement_round_trips_on_p256() {
    ec_round_trips!(p256);
}

#[test]
fn key_agreement_round_trips_on_p384() {
    ec_round_trips!(p384);
}

#[test]
fn key_agreement_round_trips_on_p521() {
    ec_round_trips!(p521);
}

// ---- KEM

const KDFS: [KdfAlgorithm; 3] = [
    KdfAlgorithm::HkdfSha256,
    KdfAlgorithm::HkdfSha384,
    KdfAlgorithm::HkdfSha512,
];

/// The content-encryption key from a KEMRecipientInfo, given the decapsulated shared secret.
fn kemri_cek(kemri: &KemRecipientInfo, ss: &[u8]) -> Vec<u8> {
    let info = CmsOriForKemOtherInfo {
        wrap: kemri.wrap.clone(),
        kek_length: kemri.kek_length,
        ukm: kemri.ukm.clone(),
    }
    .to_der()
    .unwrap();
    let mut kek = vec![0u8; kemri.kek_length as usize];
    match kemri.kdf.oid {
        ID_ALG_HKDF_WITH_SHA256 => Hkdf::<Sha256>::new(None, ss).expand(&info, &mut kek),
        ID_ALG_HKDF_WITH_SHA384 => Hkdf::<Sha384>::new(None, ss).expand(&info, &mut kek),
        _ => Hkdf::<Sha512>::new(None, ss).expand(&info, &mut kek),
    }
    .unwrap();
    aes_unwrap(kemri.wrap.oid, &kek, kemri.encrypted_key.as_bytes())
}

/// Round trips for one ML-KEM parameter set, every KDF, wrap and ukm. Returns the key and the
/// messages, for the OpenSSL test.
macro_rules! kem_round_trips {
    ($kem:ty) => {{
        let env = software();
        let (dk, ek) = <$kem as Kem>::generate_keypair_from_rng(&mut rng());
        let spki = spki(ek.to_public_key_der().unwrap().as_bytes());
        let mut messages = vec![];
        for kdf in KDFS {
            for wrap in WRAPS {
                for ukm in UKMS {
                    let recipient = KemRecipient::new(
                        &env,
                        rid(),
                        spki.clone(),
                        kdf,
                        wrap,
                        ukm.map(<[u8]>::to_vec),
                    );
                    let ci = envelop(&env, recipient);
                    let ed = enveloped_data(&ci);
                    let RecipientInfo::Ori(ori) = the_recipient(&ed) else {
                        panic!("expected an OtherRecipientInfo");
                    };
                    assert_eq!(ori.ori_type, ID_ORI_KEM);
                    let kemri =
                        KemRecipientInfo::from_der(&ori.ori_value.to_der().unwrap()).unwrap();
                    assert_eq!(kemri.version, CmsVersion::V0);
                    assert_eq!(kemri.kem.oid, spki.algorithm.oid);
                    let ss = dk.decapsulate_slice(kemri.kem_ct.as_bytes()).unwrap();
                    let cek = kemri_cek(&kemri, &ss);
                    assert_eq!(
                        decrypt_content(&ed, &cek),
                        MESSAGE,
                        "{kdf:?} {wrap:?} {ukm:?}"
                    );
                    messages.push((format!("{kdf:?} {wrap:?} ukm={}", ukm.is_some()), ci));
                }
            }
        }
        (
            dk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
            messages,
        )
    }};
}

#[test]
fn kem_round_trips_with_ml_kem_512() {
    kem_round_trips!(MlKem512);
}

#[test]
fn kem_round_trips_with_ml_kem_768() {
    kem_round_trips!(MlKem768);
}

#[test]
fn kem_round_trips_with_ml_kem_1024() {
    kem_round_trips!(MlKem1024);
}

// ---- declines and the environment

#[test]
fn a_recipient_whose_key_no_implementation_takes_fails_to_build() {
    let env = software();
    // An RSA key offered for key agreement, and an EC key for a KEM: software declines both, so the
    // environment does too, and the message is not built.
    let rsa = rsa_spki(&rsa_key());
    let kari = KeyAgreeRecipient::<Rng>::new(
        &env,
        rid(),
        rsa.clone(),
        KeyAgreementAlgorithm::EcdhSha256,
        KeyWrapAlgorithm::Aes256,
        None,
    );
    let built = EnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes256Cbc)
        .unwrap()
        .add_recipient(kari)
        .build(&env, &mut rng());
    assert!(matches!(built, Err(Error::Unrecognized)));

    assert!(matches!(
        env.encrypt_kem(
            KdfAlgorithm::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            &rsa,
            None,
            &[0; 32]
        ),
        Err(Error::Unrecognized)
    ));
}

#[test]
fn an_environment_without_key_transport_declines_it() {
    let mut env = software();
    env.clear_encrypt_key_transport_callbacks();
    let spki = rsa_spki(&rsa_key());
    assert!(matches!(
        env.encrypt_key_transport(KeyTransportAlgorithm::RsaPkcs1v15, &spki, &[0; 32]),
        Err(Error::Unrecognized)
    ));
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

/// Decrypts each message with `openssl cms -decrypt` and the key in `key_pem`. Returns the
/// openssl error output of the first failure, if any.
fn openssl_decrypts(
    openssl: &str,
    key_pem: &str,
    messages: &[(String, ContentInfo)],
) -> Result<(), String> {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.pem");
    std::fs::write(&key_path, key_pem).unwrap();
    for (name, ci) in messages {
        let decrypted = openssl_decrypt(openssl, dir.path(), &key_path, &ci.to_der().unwrap())
            .map_err(|e| format!("{name}: {e}"))?;
        assert_eq!(decrypted, MESSAGE, "{name}");
    }
    Ok(())
}

fn openssl_decrypt(
    openssl: &str,
    dir: &Path,
    key_path: &Path,
    der: &[u8],
) -> Result<Vec<u8>, String> {
    let input = dir.join("message.der");
    std::fs::write(&input, der).unwrap();
    let output = Command::new(openssl)
        .args(["cms", "-decrypt", "-inform", "DER", "-binary", "-in"])
        .arg(&input)
        .arg("-inkey")
        .arg(key_path)
        .output()
        .unwrap();
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

#[test]
fn openssl_decrypts_key_transport() {
    let Some(openssl) = openssl() else { return };
    let env = software();
    let key = rsa_key();
    let messages: Vec<_> = KEY_TRANSPORTS
        .into_iter()
        .map(|alg| (format!("{alg:?}"), key_transport(&env, &key, alg)))
        .collect();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    openssl_decrypts(&openssl, &pem, &messages).unwrap();
}

#[test]
fn openssl_decrypts_key_agreement() {
    let Some(openssl) = openssl() else { return };
    for (pem, messages) in [
        ec_round_trips!(p256),
        ec_round_trips!(p384),
        ec_round_trips!(p521),
    ] {
        openssl_decrypts(&openssl, &pem, &messages).unwrap();
    }
}

/// Whether `openssl` is OpenSSL 3.6 or later, the first with KEMRecipientInfo.
fn openssl_has_kemri(openssl: &str) -> bool {
    let output = Command::new(openssl).arg("version").output().unwrap();
    let version = String::from_utf8_lossy(&output.stdout);
    // "OpenSSL 3.6.5 29 Sep 2026 (Library: ...)"
    let mut numbers = version
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|n| n.parse::<u32>().unwrap_or(0));
    let major = numbers.next().unwrap_or(0);
    let minor = numbers.next().unwrap_or(0);
    major > 3 || (major == 3 && minor >= 6)
}

#[test]
fn openssl_decrypts_kem() {
    let Some(openssl) = openssl() else { return };
    if !openssl_has_kemri(&openssl) {
        eprintln!("skipped: {openssl} is older than OpenSSL 3.6, which added KEMRecipientInfo");
        return;
    }
    for (pem, messages) in [
        kem_round_trips!(MlKem512),
        kem_round_trips!(MlKem768),
        kem_round_trips!(MlKem1024),
    ] {
        openssl_decrypts(&openssl, &pem, &messages).unwrap();
    }
}
