//! RustCrypto implementations of the recipient operations, registered by
//! [`CmsEnvironment::populate_software`](crate::CmsEnvironment::populate_software).

use alloc::{format, vec, vec::Vec};

use aes::{Aes128, Aes192, Aes256};
use aes_kw::{AesKw, KeyInit};
use cms::kemri::CmsOriForKemOtherInfo;
use const_oid::{
    db::{
        fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768},
        rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
    },
    ObjectIdentifier,
};
use der::{asn1::OctetString, Decode, Encode, Sequence};
use elliptic_curve::{
    ecdh::EphemeralSecret,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
    CurveArithmetic, FieldBytesSize, Generate, PublicKey,
};
use getrandom::SysRng;
use hkdf::Hkdf;
use ml_kem::{Encapsulate, Kem, MlKem1024, MlKem512, MlKem768, TryKeyInit};
use rand_core::UnwrapErr;
use rsa::{pkcs1::DecodeRsaPublicKey, Oaep, Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

use crate::algorithms::{
    KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use crate::environment::CmsEnvironment;
use crate::error::{Error, Result};
use crate::recipient::{KemOutput, KeyAgreeOutput};

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn crypto(e: impl core::fmt::Display) -> Error {
    Error::Crypto(format!("{e}"))
}

/// RSA key transport with the `rsa` crate, for every [`KeyTransportAlgorithm`]. Declines a key that
/// is not rsaEncryption.
pub fn encrypt_key_transport_rust_crypto(
    _env: &CmsEnvironment,
    alg: KeyTransportAlgorithm,
    spki: &SubjectPublicKeyInfoOwned,
    cek: &[u8],
) -> Result<Vec<u8>> {
    if spki.algorithm.oid != RSA_ENCRYPTION {
        return Err(Error::Unrecognized);
    }
    let key = RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes()).map_err(crypto)?;
    let mut rng = rng();
    match alg {
        KeyTransportAlgorithm::RsaPkcs1v15 => key.encrypt(&mut rng, Pkcs1v15Encrypt, cek),
        KeyTransportAlgorithm::RsaOaepSha1 => key.encrypt(&mut rng, Oaep::<sha1::Sha1>::new(), cek),
        KeyTransportAlgorithm::RsaOaepSha256 => key.encrypt(&mut rng, Oaep::<Sha256>::new(), cek),
        KeyTransportAlgorithm::RsaOaepSha384 => key.encrypt(&mut rng, Oaep::<Sha384>::new(), cek),
        KeyTransportAlgorithm::RsaOaepSha512 => key.encrypt(&mut rng, Oaep::<Sha512>::new(), cek),
    }
    .map_err(crypto)
}

/// The `ECC-CMS-SharedInfo` type, from RFC 5753, section 7.2.
///
/// ```text
/// ECC-CMS-SharedInfo ::= SEQUENCE {
///   keyInfo         AlgorithmIdentifier,
///   entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
///   suppPubInfo [2] EXPLICIT OCTET STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EccCmsSharedInfo {
    key_info: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    entity_u_info: Option<OctetString>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    supp_pub_info: OctetString,
}

/// Wraps `cek` under `kek` with AES key wrap (RFC 3394).
fn aes_key_wrap(wrap: KeyWrapAlgorithm, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    let mut wrapped = vec![0u8; cek.len() + 8];
    match wrap {
        KeyWrapAlgorithm::Aes128 => AesKw::<Aes128>::new_from_slice(kek)
            .map_err(crypto)?
            .wrap_key(cek, &mut wrapped)
            .map_err(crypto)?,
        KeyWrapAlgorithm::Aes192 => AesKw::<Aes192>::new_from_slice(kek)
            .map_err(crypto)?
            .wrap_key(cek, &mut wrapped)
            .map_err(crypto)?,
        KeyWrapAlgorithm::Aes256 => AesKw::<Aes256>::new_from_slice(kek)
            .map_err(crypto)?
            .wrap_key(cek, &mut wrapped)
            .map_err(crypto)?,
    };
    Ok(wrapped)
}

/// Ephemeral-static ECDH on P-256, P-384 or P-521 with the X9.63 KDF and AES key wrap, for every
/// [`KeyAgreementAlgorithm`] and [`KeyWrapAlgorithm`]. Declines a key on any other curve, or one that
/// is not id-ecPublicKey.
pub fn encrypt_key_agreement_rust_crypto(
    _env: &CmsEnvironment,
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    spki: &SubjectPublicKeyInfoOwned,
    ukm: Option<&[u8]>,
    cek: &[u8],
) -> Result<KeyAgreeOutput> {
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(Error::Unrecognized);
    }
    let curve = match &spki.algorithm.parameters {
        Some(params) => ObjectIdentifier::from_der(&params.to_der()?)?,
        None => return Err(Error::Unrecognized),
    };
    let point = spki.subject_public_key.raw_bytes();
    match curve {
        SECP_256_R_1 => ecdh::<p256::NistP256>(alg, wrap, point, ukm, cek),
        SECP_384_R_1 => ecdh::<p384::NistP384>(alg, wrap, point, ukm, cek),
        SECP_521_R_1 => ecdh::<p521::NistP521>(alg, wrap, point, ukm, cek),
        _ => Err(Error::Unrecognized),
    }
}

fn ecdh<C>(
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    point: &[u8],
    ukm: Option<&[u8]>,
    cek: &[u8],
) -> Result<KeyAgreeOutput>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    EphemeralSecret<C>: Generate,
{
    let recipient = PublicKey::<C>::from_sec1_bytes(point).map_err(crypto)?;
    let ephemeral = EphemeralSecret::<C>::generate_from_rng(&mut rng());
    let ephemeral_public_key = ephemeral
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let shared_secret = ephemeral.diffie_hellman(&recipient);

    // RFC 5753, section 7.2: suppPubInfo is the key-encryption key's length in bits, as four
    // octets, and entityUInfo is the ukm when there is one.
    let kek_bits = (wrap.kek_len() as u32 * 8).to_be_bytes();
    let shared_info = EccCmsSharedInfo {
        key_info: wrap.algorithm_identifier(),
        entity_u_info: match ukm {
            Some(ukm) => Some(OctetString::new(ukm)?),
            None => None,
        },
        supp_pub_info: OctetString::new(kek_bits)?,
    }
    .to_der()?;

    let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
    let secret = shared_secret.raw_secret_bytes();
    match alg {
        KeyAgreementAlgorithm::EcdhSha256 => {
            ansi_x963_kdf::derive_key_into::<Sha256>(secret, &shared_info, &mut kek)
        }
        KeyAgreementAlgorithm::EcdhSha384 => {
            ansi_x963_kdf::derive_key_into::<Sha384>(secret, &shared_info, &mut kek)
        }
        KeyAgreementAlgorithm::EcdhSha512 => {
            ansi_x963_kdf::derive_key_into::<Sha512>(secret, &shared_info, &mut kek)
        }
    }
    .map_err(|e| Error::Crypto(format!("X9.63 KDF: {e:?}")))?;

    Ok(KeyAgreeOutput {
        ephemeral_public_key,
        encrypted_key: aes_key_wrap(wrap, &kek, cek)?,
    })
}

/// ML-KEM-512, -768 or -1024 (FIPS 203) with HKDF and AES key wrap, for every [`KdfAlgorithm`] and
/// [`KeyWrapAlgorithm`]. Declines a key for any other KEM.
pub fn encrypt_kem_rust_crypto(
    _env: &CmsEnvironment,
    kdf: KdfAlgorithm,
    wrap: KeyWrapAlgorithm,
    spki: &SubjectPublicKeyInfoOwned,
    ukm: Option<&[u8]>,
    cek: &[u8],
) -> Result<KemOutput> {
    let key = spki.subject_public_key.raw_bytes();
    let mut rng = rng();
    let (kem_ct, ss): (Vec<u8>, Zeroizing<Vec<u8>>) = match spki.algorithm.oid {
        ID_ALG_ML_KEM_512 => {
            let ek = <MlKem512 as Kem>::EncapsulationKey::new_from_slice(key).map_err(crypto)?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
            (ct.to_vec(), Zeroizing::new(ss.to_vec()))
        }
        ID_ALG_ML_KEM_768 => {
            let ek = <MlKem768 as Kem>::EncapsulationKey::new_from_slice(key).map_err(crypto)?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
            (ct.to_vec(), Zeroizing::new(ss.to_vec()))
        }
        ID_ALG_ML_KEM_1024 => {
            let ek = <MlKem1024 as Kem>::EncapsulationKey::new_from_slice(key).map_err(crypto)?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
            (ct.to_vec(), Zeroizing::new(ss.to_vec()))
        }
        _ => return Err(Error::Unrecognized),
    };

    // RFC 9629, section 5: the KDF's info is the DER encoding of CMSORIforKEMOtherInfo, its input
    // keying material the shared secret, and its salt absent.
    let info = CmsOriForKemOtherInfo {
        wrap: wrap.algorithm_identifier(),
        kek_length: wrap.kek_len() as u16,
        ukm: match ukm {
            Some(ukm) => Some(OctetString::new(ukm)?),
            None => None,
        },
    }
    .to_der()?;
    let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
    let expanded = match kdf {
        KdfAlgorithm::HkdfSha256 => Hkdf::<Sha256>::new(None, &ss).expand(&info, &mut kek),
        KdfAlgorithm::HkdfSha384 => Hkdf::<Sha384>::new(None, &ss).expand(&info, &mut kek),
        KdfAlgorithm::HkdfSha512 => Hkdf::<Sha512>::new(None, &ss).expand(&info, &mut kek),
    };
    expanded.map_err(|e| Error::Crypto(format!("HKDF: {e:?}")))?;

    Ok(KemOutput {
        kem_ct,
        encrypted_key: aes_key_wrap(wrap, &kek, cek)?,
    })
}
