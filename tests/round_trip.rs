//! Messages built here, decrypted again with RustCrypto: RSA key transport recipients from the `cms`
//! crate, every content encryption algorithm, and authenticated attributes for AuthEnvelopedData.
//!
//! With `CERTVAL_CMS_OPENSSL` set to an `openssl` command (OpenSSL 3), the same messages are also
//! decrypted by `openssl cms -decrypt`, an implementation that shares no code with this crate.
//! AuthEnvelopedData with authenticated attributes needs OpenSSL 3.6.4 or later, the first to tag
//! them as RFC 5083 does; with an older `openssl` those messages are skipped.

use std::path::Path;
use std::process::Command;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, inout::InOutBuf},
    AeadInOut, AesGcm, KeyInit,
};
use cbc::cipher::{block_padding::Pkcs7, BlockCipherDecrypt, BlockModeDecrypt, KeyIvInit};
use certval_cms::{
    AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm, EncryptedContent,
    EnvelopedDataBuilder, Error, GcmParameters,
};
use cms::{
    authenveloped_data::AuthEnvelopedData,
    builder::{KeyEncryptionInfo, KeyTransRecipientInfoBuilder},
    cert::x509::attr::Attribute,
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientIdentifier, RecipientInfo},
};
use const_oid::db::rfc5911::{
    ID_CONTENT_TYPE, ID_CT_AUTH_ENVELOPED_DATA, ID_DATA, ID_ENVELOPED_DATA,
};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, Decode, Encode,
};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use rsa::{pkcs1v15::Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use x509_cert::ext::pkix::SubjectKeyIdentifier;

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] =
    b"certval-cms round trip, longer than one AES block so that padding is exercised";

const CBC: [ContentEncryptionAlgorithm; 3] = [
    ContentEncryptionAlgorithm::Aes128Cbc,
    ContentEncryptionAlgorithm::Aes192Cbc,
    ContentEncryptionAlgorithm::Aes256Cbc,
];

const GCM: [ContentEncryptionAlgorithm; 3] = [
    ContentEncryptionAlgorithm::Aes128Gcm,
    ContentEncryptionAlgorithm::Aes192Gcm,
    ContentEncryptionAlgorithm::Aes256Gcm,
];

fn software() -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env
}

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

fn rsa_key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut rng(), 2048).unwrap()
}

fn rid() -> RecipientIdentifier {
    RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
        OctetString::new(vec![1, 2, 3, 4]).unwrap(),
    ))
}

fn recipient(key: &RsaPrivateKey) -> KeyTransRecipientInfoBuilder<Rng> {
    KeyTransRecipientInfoBuilder::new(rid(), KeyEncryptionInfo::Rsa(RsaPublicKey::from(key)))
        .unwrap()
}

/// The content-encryption key, unwrapped from the message's only recipient.
fn unwrap_key(key: &RsaPrivateKey, ri: &RecipientInfo) -> Vec<u8> {
    let RecipientInfo::Ktri(ktri) = ri else {
        panic!("expected a key transport recipient");
    };
    key.decrypt(Pkcs1v15Encrypt, ktri.enc_key.as_bytes())
        .unwrap()
}

fn cbc_decrypt<C>(cek: &[u8], eci: &EncryptedContentInfo) -> Vec<u8>
where
    C: BlockCipherDecrypt,
    cbc::Decryptor<C>: KeyIvInit + BlockModeDecrypt,
{
    let iv = eci.content_enc_alg.parameters.as_ref().unwrap();
    let iv = OctetString::from_der(&iv.to_der().unwrap()).unwrap();
    let ct = eci.encrypted_content.as_ref().unwrap().as_bytes();
    cbc::Decryptor::<C>::new_from_slices(cek, iv.as_bytes())
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(ct)
        .unwrap()
}

fn gcm_decrypt<C>(cek: &[u8], eci: &EncryptedContentInfo, aad: &[u8], tag: &[u8]) -> Vec<u8>
where
    AesGcm<C, U12>: KeyInit + AeadInOut,
{
    let params = eci.content_enc_alg.parameters.as_ref().unwrap();
    let params = GcmParameters::from_der(&params.to_der().unwrap()).unwrap();
    assert_eq!(params.icv_len as usize, tag.len());
    let mut buf = eci.encrypted_content.as_ref().unwrap().as_bytes().to_vec();
    AesGcm::<C, U12>::new_from_slice(cek)
        .unwrap()
        .decrypt_inout_detached(
            params.nonce.as_bytes().try_into().unwrap(),
            aad,
            InOutBuf::from(buf.as_mut_slice()),
            tag.try_into().unwrap(),
        )
        .unwrap();
    buf
}

fn decrypt_enveloped(key: &RsaPrivateKey, ci: &ContentInfo) -> Vec<u8> {
    assert_eq!(ci.content_type, ID_ENVELOPED_DATA);
    let ed = EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    // RFC 5652, section 6.1: version 2, since the recipient is identified by subject key
    // identifier, which makes its KeyTransRecipientInfo version 2 rather than 0.
    assert_eq!(ed.version, CmsVersion::V2);
    let cek = unwrap_key(key, &ed.recip_infos.0.as_slice()[0]);
    let eci = &ed.encrypted_content;
    assert_eq!(eci.content_type, ID_DATA);
    match ContentEncryptionAlgorithm::from_oid(eci.content_enc_alg.oid).unwrap() {
        ContentEncryptionAlgorithm::Aes128Cbc => cbc_decrypt::<Aes128>(&cek, eci),
        ContentEncryptionAlgorithm::Aes192Cbc => cbc_decrypt::<Aes192>(&cek, eci),
        ContentEncryptionAlgorithm::Aes256Cbc => cbc_decrypt::<Aes256>(&cek, eci),
        other => panic!("{other:?} in EnvelopedData"),
    }
}

fn decrypt_auth_enveloped(key: &RsaPrivateKey, ci: &ContentInfo) -> Vec<u8> {
    assert_eq!(ci.content_type, ID_CT_AUTH_ENVELOPED_DATA);
    let aed = AuthEnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    assert_eq!(aed.version, CmsVersion::V0);
    let cek = unwrap_key(key, &aed.recip_infos.0.as_slice()[0]);
    let aad = match &aed.auth_attrs {
        Some(attrs) => attrs.to_der().unwrap(),
        None => vec![],
    };
    let tag = aed.mac.as_bytes();
    let eci = &aed.auth_encrypted_content_info;
    match ContentEncryptionAlgorithm::from_oid(eci.content_enc_alg.oid).unwrap() {
        ContentEncryptionAlgorithm::Aes128Gcm => gcm_decrypt::<aes::Aes128>(&cek, eci, &aad, tag),
        ContentEncryptionAlgorithm::Aes192Gcm => gcm_decrypt::<aes::Aes192>(&cek, eci, &aad, tag),
        ContentEncryptionAlgorithm::Aes256Gcm => gcm_decrypt::<aes::Aes256>(&cek, eci, &aad, tag),
        other => panic!("{other:?} in AuthEnvelopedData"),
    }
}

fn enveloped(key: &RsaPrivateKey, alg: ContentEncryptionAlgorithm) -> ContentInfo {
    EnvelopedDataBuilder::new(MESSAGE, alg)
        .unwrap()
        .add_recipient(recipient(key))
        .build_content_info(&software(), &mut rng())
        .unwrap()
}

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

fn auth_enveloped(
    key: &RsaPrivateKey,
    alg: ContentEncryptionAlgorithm,
    with_attrs: bool,
) -> ContentInfo {
    let mut builder = AuthEnvelopedDataBuilder::new(MESSAGE, alg).unwrap();
    if with_attrs {
        builder.auth_attrs(content_type_attrs());
    }
    builder
        .add_recipient(recipient(key))
        .build_content_info(&software(), &mut rng())
        .unwrap()
}

#[test]
fn enveloped_data_round_trips() {
    let key = rsa_key();
    for alg in CBC {
        assert_eq!(
            decrypt_enveloped(&key, &enveloped(&key, alg)),
            MESSAGE,
            "{alg:?}"
        );
    }
}

#[test]
fn auth_enveloped_data_round_trips_with_and_without_authenticated_attributes() {
    let key = rsa_key();
    for alg in GCM {
        for with_attrs in [false, true] {
            let ci = auth_enveloped(&key, alg, with_attrs);
            assert_eq!(
                decrypt_auth_enveloped(&key, &ci),
                MESSAGE,
                "{alg:?} {with_attrs}"
            );
        }
    }
}

#[test]
fn a_changed_authenticated_attribute_fails_authentication() {
    let key = rsa_key();
    let ci = auth_enveloped(&key, ContentEncryptionAlgorithm::Aes256Gcm, true);
    let mut aed = AuthEnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    let cek = unwrap_key(&key, &aed.recip_infos.0.as_slice()[0]);
    let mut values = SetOfVec::new();
    values
        .insert(Any::encode_from(&ID_ENVELOPED_DATA).unwrap())
        .unwrap();
    let mut attrs = SetOfVec::new();
    attrs
        .insert(Attribute {
            oid: ID_CONTENT_TYPE,
            values,
        })
        .unwrap();
    aed.auth_attrs = Some(attrs);
    let aad = aed.auth_attrs.as_ref().unwrap().to_der().unwrap();
    let eci = &aed.auth_encrypted_content_info;
    let params = GcmParameters::from_der(
        &eci.content_enc_alg
            .parameters
            .as_ref()
            .unwrap()
            .to_der()
            .unwrap(),
    )
    .unwrap();
    let mut buf = eci.encrypted_content.as_ref().unwrap().as_bytes().to_vec();
    let result = AesGcm::<Aes256, U12>::new_from_slice(&cek)
        .unwrap()
        .decrypt_inout_detached(
            params.nonce.as_bytes().try_into().unwrap(),
            &aad,
            InOutBuf::from(buf.as_mut_slice()),
            aed.mac.as_bytes().try_into().unwrap(),
        );
    assert!(result.is_err());
}

#[test]
fn builders_refuse_the_other_kind_of_algorithm() {
    for alg in GCM {
        assert!(matches!(
            EnvelopedDataBuilder::<Rng>::new(MESSAGE, alg),
            Err(Error::InvalidInput(_))
        ));
    }
    for alg in CBC {
        assert!(matches!(
            AuthEnvelopedDataBuilder::<Rng>::new(MESSAGE, alg),
            Err(Error::InvalidInput(_))
        ));
    }
}

#[test]
fn a_message_needs_a_recipient() {
    let result = EnvelopedDataBuilder::<Rng>::new(MESSAGE, ContentEncryptionAlgorithm::Aes128Cbc)
        .unwrap()
        .build(&software(), &mut rng());
    assert!(matches!(result, Err(Error::InvalidInput(_))));
}

/// Declines everything, as a provider does for an algorithm its module lacks.
fn declines(
    _: &CmsEnvironment,
    _: ContentEncryptionAlgorithm,
    _: &[u8],
    _: Option<&[u8]>,
) -> certval_cms::Result<EncryptedContent> {
    Err(Error::Unrecognized)
}

#[test]
fn a_decline_passes_to_the_next_implementation_and_all_declining_declines() {
    let key = rsa_key();
    let mut env = CmsEnvironment::new();
    env.add_encrypt_content_callback(declines);
    let declined = EnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes128Cbc)
        .unwrap()
        .add_recipient(recipient(&key))
        .build(&env, &mut rng());
    assert!(matches!(declined, Err(Error::Unrecognized)));

    env.populate_software();
    let ci = EnvelopedDataBuilder::new(MESSAGE, ContentEncryptionAlgorithm::Aes128Cbc)
        .unwrap()
        .add_recipient(recipient(&key))
        .build_content_info(&env, &mut rng())
        .unwrap();
    assert_eq!(decrypt_enveloped(&key, &ci), MESSAGE);

    env.clear_encrypt_content_callbacks();
    assert!(matches!(
        env.encrypt_content(ContentEncryptionAlgorithm::Aes128Cbc, MESSAGE, None),
        Err(Error::Unrecognized)
    ));
}

/// Decrypts with `openssl cms -decrypt`, given the recipient's key. Skipped unless
/// `CERTVAL_CMS_OPENSSL` names an `openssl` command.
#[test]
fn openssl_decrypts_what_is_built_here() {
    let Ok(openssl) = std::env::var("CERTVAL_CMS_OPENSSL") else {
        eprintln!("skipped: CERTVAL_CMS_OPENSSL is not set");
        return;
    };
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    let dir = tempfile::tempdir().unwrap();
    let key = rsa_key();
    let key_path = dir.path().join("key.pem");
    std::fs::write(
        &key_path,
        key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();

    // Before 3.6.4, OpenSSL tags AuthEnvelopedData's authAttrs [2] rather than RFC 5083's [1], so it
    // cannot read a message that carries them.
    let reads_auth_attrs = openssl_version(&openssl) >= (3, 6, 4);
    if !reads_auth_attrs {
        eprintln!(
            "skipped for authenticated attributes: {openssl} is older than OpenSSL 3.6.4, the \
             first to read AuthEnvelopedData's authAttrs as RFC 5083 tags them"
        );
    }

    let mut messages = vec![];
    for alg in CBC {
        messages.push((format!("{alg:?}"), enveloped(&key, alg)));
    }
    for alg in GCM {
        for with_attrs in [false, true] {
            if with_attrs && !reads_auth_attrs {
                continue;
            }
            messages.push((
                format!("{alg:?} attrs={with_attrs}"),
                auth_enveloped(&key, alg, with_attrs),
            ));
        }
    }
    for (name, ci) in messages {
        let decrypted = openssl_decrypt(
            &openssl,
            dir.path(),
            &key_path,
            &ci.to_der().unwrap(),
            &name,
        );
        assert_eq!(decrypted, MESSAGE, "{name}");
    }
}

/// The version `openssl version` reports, as (major, minor, patch); zeros where it cannot be read.
fn openssl_version(openssl: &str) -> (u32, u32, u32) {
    let output = Command::new(openssl).arg("version").output().unwrap();
    let version = String::from_utf8_lossy(&output.stdout);
    // "OpenSSL 3.6.5 29 Sep 2026 (Library: ...)"
    let mut numbers = version
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|n| n.parse::<u32>().unwrap_or(0));
    (
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
    )
}

fn openssl_decrypt(openssl: &str, dir: &Path, key_path: &Path, der: &[u8], name: &str) -> Vec<u8> {
    let input = dir.join("message.der");
    std::fs::write(&input, der).unwrap();
    let output = Command::new(openssl)
        .args(["cms", "-decrypt", "-inform", "DER", "-binary", "-in"])
        .arg(&input)
        .arg("-inkey")
        .arg(key_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "openssl, {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
