//! RustCrypto implementations of the recipient operations, registered by
//! [`CmsEnvironment::populate_software`](crate::CmsEnvironment::populate_software).

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

use aes::{Aes128, Aes192, Aes256};
use aes_kw::{AesKw, KeyInit};
#[cfg(feature = "pqc")]
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::{
    db::{
        fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768},
        rfc5912::{
            ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_EC_PUBLIC_KEY,
            ID_RSASSA_PSS, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION, SECP_256_R_1,
            SECP_384_R_1, SECP_521_R_1, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
            SHA_512_WITH_RSA_ENCRYPTION,
        },
    },
    ObjectIdentifier,
};
use der::{asn1::OctetString, Choice, Decode, Encode, Sequence};
use elliptic_curve::{
    ecdh::EphemeralSecret,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
    CurveArithmetic, FieldBytesSize, Generate, PublicKey,
};
use getrandom::SysRng;
use hkdf::Hkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem, MlKem1024, MlKem512, MlKem768, TryKeyInit};
use rand_core::UnwrapErr;
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey, PrivateKeyInfoRef},
    Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::algorithms::{
    KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};

use crate::environment::CmsEnvironment;
use crate::environment_traits::{
    KemOutput, KeyAgreeOutput, RecipientCredential, SigningCredential, SigningKey,
};
use crate::error::{Error, Result};
use crate::recipient::{ecc_cms_shared_info, kem_other_info};

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
/// [`KeyAgreementAlgorithm`] and [`KeyWrapAlgorithm`]. Declines a key on any other curve, or one
/// that is not id-ecPublicKey.
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

    Ok(KeyAgreeOutput {
        ephemeral_public_key,
        encrypted_key: wrap_with_ecdh_secret(
            alg,
            wrap,
            shared_secret.raw_secret_bytes(),
            ukm,
            cek,
        )?,
    })
}

/// The key-encryption key RFC 5753 derives from an ECDH shared secret: the X9.63 KDF over the
/// `ECC-CMS-SharedInfo`.
fn x963_kek(
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    secret: &[u8],
    ukm: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let shared_info = ecc_cms_shared_info(wrap, ukm)?;
    let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
    match alg {
        KeyAgreementAlgorithm::EcdhSha256 | KeyAgreementAlgorithm::EcdhCofactorSha256 => {
            ansi_x963_kdf::derive_key_into::<Sha256>(secret, &shared_info, &mut kek)
        }
        KeyAgreementAlgorithm::EcdhSha384 | KeyAgreementAlgorithm::EcdhCofactorSha384 => {
            ansi_x963_kdf::derive_key_into::<Sha384>(secret, &shared_info, &mut kek)
        }
        KeyAgreementAlgorithm::EcdhSha512 | KeyAgreementAlgorithm::EcdhCofactorSha512 => {
            ansi_x963_kdf::derive_key_into::<Sha512>(secret, &shared_info, &mut kek)
        }
    }
    .map_err(|e| Error::Crypto(format!("X9.63 KDF: {e:?}")))?;
    Ok(kek)
}

/// The key-encryption key RFC 9629 derives from a KEM shared secret: the KDF over the
/// `CMSORIforKEMOtherInfo`, with the shared secret as input keying material and the salt absent.
fn hkdf_kek(
    kdf: KdfAlgorithm,
    wrap: KeyWrapAlgorithm,
    ss: &[u8],
    ukm: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let info = kem_other_info(wrap, ukm)?;
    let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
    match kdf {
        KdfAlgorithm::HkdfSha256 => Hkdf::<Sha256>::new(None, ss).expand(&info, &mut kek),
        KdfAlgorithm::HkdfSha384 => Hkdf::<Sha384>::new(None, ss).expand(&info, &mut kek),
        KdfAlgorithm::HkdfSha512 => Hkdf::<Sha512>::new(None, ss).expand(&info, &mut kek),
    }
    .map_err(|e| Error::Crypto(format!("HKDF: {e:?}")))?;
    Ok(kek)
}

/// Unwraps `wrapped` under `kek` with AES key wrap (RFC 3394). An integrity failure, which is
/// what a wrong key-encryption key produces, is [`Error::Crypto`].
fn aes_key_unwrap(
    wrap: KeyWrapAlgorithm,
    kek: &[u8],
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let len = wrapped
        .len()
        .checked_sub(8)
        .ok_or_else(|| Error::Crypto(String::from("wrapped key too short")))?;
    let mut cek = Zeroizing::new(vec![0u8; len]);
    let unwrapped = match wrap {
        KeyWrapAlgorithm::Aes128 => AesKw::<Aes128>::new_from_slice(kek)
            .map_err(crypto)?
            .unwrap_key(wrapped, &mut cek)
            .map(<[u8]>::len),
        KeyWrapAlgorithm::Aes192 => AesKw::<Aes192>::new_from_slice(kek)
            .map_err(crypto)?
            .unwrap_key(wrapped, &mut cek)
            .map(<[u8]>::len),
        KeyWrapAlgorithm::Aes256 => AesKw::<Aes256>::new_from_slice(kek)
            .map_err(crypto)?
            .unwrap_key(wrapped, &mut cek)
            .map(<[u8]>::len),
    }
    .map_err(|_| Error::Crypto(String::from("key unwrap failed")))?;
    cek.truncate(unwrapped);
    Ok(cek)
}

/// A KeyAgreeRecipientInfo's encryptedKey, given the ECDH shared secret `z`: `cek` wrapped (AES key
/// wrap) under the key-encryption key the X9.63 KDF derives from `z` and the `ECC-CMS-SharedInfo`.
/// For an [`EncryptKeyAgreement`](crate::EncryptKeyAgreement) implementation whose module performs
/// the ECDH but has no X9.63 KDF, e.g. CNG; the counterpart of [`cek_from_ecdh_secret`].
pub fn wrap_with_ecdh_secret(
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    z: &[u8],
    ukm: Option<&[u8]>,
    cek: &[u8],
) -> Result<Vec<u8>> {
    let kek = x963_kek(alg, wrap, z, ukm)?;
    aes_key_wrap(wrap, &kek, cek)
}

/// The content-encryption key from a KeyAgreeRecipientInfo, given the ECDH shared secret `z`: the
/// X9.63 KDF over the `ECC-CMS-SharedInfo`, then AES key unwrap of `encrypted_key`. For a
/// [`RecipientCredential`](crate::RecipientCredential) whose key holder returns the shared secret
/// rather than performing the whole operation, e.g. a PKCS #11 token's `CKM_ECDH1_DERIVE` with no
/// KDF.
pub fn cek_from_ecdh_secret(
    alg: KeyAgreementAlgorithm,
    wrap: KeyWrapAlgorithm,
    z: &[u8],
    ukm: Option<&[u8]>,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let kek = x963_kek(alg, wrap, z, ukm)?;
    aes_key_unwrap(wrap, &kek, encrypted_key)
}

/// The content-encryption key from a KEMRecipientInfo, given the decapsulated shared secret `ss`:
/// the KDF over the `CMSORIforKEMOtherInfo`, then AES key unwrap of `encrypted_key`. For a
/// [`RecipientCredential`](crate::RecipientCredential) whose key holder only decapsulates.
pub fn cek_from_kem_secret(
    kdf: KdfAlgorithm,
    wrap: KeyWrapAlgorithm,
    ss: &[u8],
    ukm: Option<&[u8]>,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let kek = hkdf_kek(kdf, wrap, ss, ukm)?;
    aes_key_unwrap(wrap, &kek, encrypted_key)
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

    let kek = hkdf_kek(kdf, wrap, &ss, ukm)?;

    Ok(KemOutput {
        kem_ct,
        encrypted_key: aes_key_wrap(wrap, &kek, cek)?,
    })
}

/// The private key form RFC 9935 gives ML-KEM and RFC 9881 gives ML-DSA, the content of a PKCS #8
/// privateKey: a seed, an expanded key, or both. The sizes, which depend on the algorithm and
/// parameter set, are checked when the key is made.
///
/// ```text
/// ML-KEM-PrivateKey ::= CHOICE {
///   seed        [0] IMPLICIT OCTET STRING (SIZE (64)),
///   expandedKey OCTET STRING,
///   both        SEQUENCE {
///                 seed        OCTET STRING (SIZE (64)),
///                 expandedKey OCTET STRING } }
/// ```
///
/// It holds private key material: `Debug` shows the form and the lengths, not the octets, and
/// there is no `Clone`.
#[derive(Choice)]
pub enum SeedOrExpandedKey {
    /// The seed the key is generated from.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(OctetString),
    /// The expanded private key.
    ExpandedKey(OctetString),
    /// The seed and the expanded key it generates.
    Both(SeedAndExpandedKey),
}

impl core::fmt::Debug for SeedOrExpandedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SeedOrExpandedKey::Seed(seed) => write!(f, "Seed(<{} octets>)", seed.len()),
            SeedOrExpandedKey::ExpandedKey(key) => write!(f, "ExpandedKey(<{} octets>)", key.len()),
            SeedOrExpandedKey::Both(both) => f.debug_tuple("Both").field(both).finish(),
        }
    }
}

/// The `both` form of [`SeedOrExpandedKey`].
#[derive(Sequence)]
pub struct SeedAndExpandedKey {
    /// The seed the key is generated from.
    pub seed: OctetString,
    /// The expanded private key, which must be the one the seed generates.
    pub expanded_key: OctetString,
}

impl core::fmt::Debug for SeedAndExpandedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SeedAndExpandedKey")
            .field("seed", &format_args!("<{} octets>", self.seed.len()))
            .field(
                "expanded_key",
                &format_args!("<{} octets>", self.expanded_key.len()),
            )
            .finish()
    }
}

/// Decodes an RFC 9935 ML-KEM private key into `$key`, from any of its three forms. A key in the
/// `both` form whose expanded key is not the one its seed generates is refused.
macro_rules! ml_kem_key {
    ($key:ty, $private_key:expr) => {{
        #[allow(deprecated)]
        use ml_kem::ExpandedKeyEncoding;
        let malformed = || Error::InvalidInput(String::from("an ML-KEM private key malformed"));
        let from_seed = |seed: &OctetString| -> Result<$key> {
            Ok(<$key>::from_seed(
                seed.as_bytes().try_into().map_err(|_| malformed())?,
            ))
        };
        match SeedOrExpandedKey::from_der($private_key)? {
            SeedOrExpandedKey::Seed(seed) => from_seed(&seed)?,
            #[allow(deprecated)]
            SeedOrExpandedKey::ExpandedKey(expanded) => <$key>::from_expanded_bytes(
                expanded.as_bytes().try_into().map_err(|_| malformed())?,
            )
            .map_err(|_| malformed())?,
            SeedOrExpandedKey::Both(both) => {
                let key = from_seed(&both.seed)?;
                #[allow(deprecated)]
                let expanded = key.to_expanded_bytes();
                if expanded.as_slice() != both.expanded_key.as_bytes() {
                    return Err(Error::InvalidInput(String::from(
                        "an ML-KEM private key whose expanded key is not its seed's",
                    )));
                }
                key
            }
        }
    }};
}

/// The private key a [`SoftwareRecipientKey`] holds.
enum RecipientKeyMaterial {
    Rsa(RsaPrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    MlKem512(Box<ml_kem::DecapsulationKey512>),
    MlKem768(Box<ml_kem::DecapsulationKey768>),
    MlKem1024(Box<ml_kem::DecapsulationKey1024>),
}

/// The kind of key, not the key.
impl core::fmt::Debug for RecipientKeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            RecipientKeyMaterial::Rsa(_) => "Rsa",
            RecipientKeyMaterial::P256(_) => "P256",
            RecipientKeyMaterial::P384(_) => "P384",
            RecipientKeyMaterial::P521(_) => "P521",
            RecipientKeyMaterial::MlKem512(_) => "MlKem512",
            RecipientKeyMaterial::MlKem768(_) => "MlKem768",
            RecipientKeyMaterial::MlKem1024(_) => "MlKem1024",
        })
    }
}

/// A [`RecipientCredential`] holding a private key in memory and decrypting with RustCrypto: RSA
/// key transport, ECDH on P-256, P-384 or P-521, or ML-KEM-512, -768 or -1024.
pub struct SoftwareRecipientKey {
    certificate: Certificate,
    key: RecipientKeyMaterial,
}

/// The certificate's subject and the kind of key, not the key.
impl core::fmt::Debug for SoftwareRecipientKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareRecipientKey")
            .field(
                "subject",
                &format_args!("{}", self.certificate.tbs_certificate().subject()),
            )
            .field("key", &self.key)
            .finish()
    }
}

impl SoftwareRecipientKey {
    /// A credential for the PKCS #8 (RFC 5958) private key `der`, identified by `certificate`. The
    /// key must be the private half of the certificate's public key. An ML-KEM key may be in any of
    /// RFC 9935's three forms: the seed, the expanded key, or both.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let info = PrivateKeyInfoRef::from_der(der)?;
        let key = match info.algorithm.oid {
            RSA_ENCRYPTION => {
                RecipientKeyMaterial::Rsa(RsaPrivateKey::from_pkcs8_der(der).map_err(crypto)?)
            }
            ID_EC_PUBLIC_KEY => match info.algorithm.parameters_oid().map_err(crypto)? {
                SECP_256_R_1 => RecipientKeyMaterial::P256(
                    p256::SecretKey::from_pkcs8_der(der).map_err(crypto)?,
                ),
                SECP_384_R_1 => RecipientKeyMaterial::P384(
                    p384::SecretKey::from_pkcs8_der(der).map_err(crypto)?,
                ),
                SECP_521_R_1 => RecipientKeyMaterial::P521(
                    p521::SecretKey::from_pkcs8_der(der).map_err(crypto)?,
                ),
                _ => return Err(Error::Unrecognized),
            },
            ID_ALG_ML_KEM_512 => RecipientKeyMaterial::MlKem512(Box::new(ml_kem_key!(
                ml_kem::DecapsulationKey512,
                info.private_key.as_bytes()
            ))),
            ID_ALG_ML_KEM_768 => RecipientKeyMaterial::MlKem768(Box::new(ml_kem_key!(
                ml_kem::DecapsulationKey768,
                info.private_key.as_bytes()
            ))),
            ID_ALG_ML_KEM_1024 => RecipientKeyMaterial::MlKem1024(Box::new(ml_kem_key!(
                ml_kem::DecapsulationKey1024,
                info.private_key.as_bytes()
            ))),
            _ => return Err(Error::Unrecognized),
        };
        let credential = Self { certificate, key };
        if credential.public_key()?
            != *credential
                .certificate
                .tbs_certificate()
                .subject_public_key_info()
        {
            return Err(Error::InvalidInput(String::from(
                "the private key is not the certificate's",
            )));
        }
        Ok(credential)
    }

    /// The public half of the key, encoded as the certificate's would be.
    fn public_key(&self) -> Result<SubjectPublicKeyInfoOwned> {
        let der = match &self.key {
            RecipientKeyMaterial::Rsa(k) => k.to_public_key().to_public_key_der(),
            RecipientKeyMaterial::P256(k) => k.public_key().to_public_key_der(),
            RecipientKeyMaterial::P384(k) => k.public_key().to_public_key_der(),
            RecipientKeyMaterial::P521(k) => k.public_key().to_public_key_der(),
            RecipientKeyMaterial::MlKem512(k) => k.encapsulation_key().to_public_key_der(),
            RecipientKeyMaterial::MlKem768(k) => k.encapsulation_key().to_public_key_der(),
            RecipientKeyMaterial::MlKem1024(k) => k.encapsulation_key().to_public_key_der(),
        }
        .map_err(crypto)?;
        Ok(SubjectPublicKeyInfoOwned::from_der(der.as_bytes())?)
    }
}

fn ecdh_secret<C>(
    key: &elliptic_curve::SecretKey<C>,
    originator: &SubjectPublicKeyInfoOwned,
) -> Result<Zeroizing<Vec<u8>>>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
{
    let originator = PublicKey::<C>::from_sec1_bytes(originator.subject_public_key.raw_bytes())
        .map_err(crypto)?;
    let shared =
        elliptic_curve::ecdh::diffie_hellman(key.to_nonzero_scalar(), originator.as_affine());
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

impl RecipientCredential for SoftwareRecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let RecipientKeyMaterial::Rsa(key) = &self.key else {
            return Err(Error::Unrecognized);
        };
        match alg {
            KeyTransportAlgorithm::RsaPkcs1v15 => key.decrypt(Pkcs1v15Encrypt, encrypted_key),
            KeyTransportAlgorithm::RsaOaepSha1 => {
                key.decrypt(Oaep::<sha1::Sha1>::new(), encrypted_key)
            }
            KeyTransportAlgorithm::RsaOaepSha256 => {
                key.decrypt(Oaep::<Sha256>::new(), encrypted_key)
            }
            KeyTransportAlgorithm::RsaOaepSha384 => {
                key.decrypt(Oaep::<Sha384>::new(), encrypted_key)
            }
            KeyTransportAlgorithm::RsaOaepSha512 => {
                key.decrypt(Oaep::<Sha512>::new(), encrypted_key)
            }
        }
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto(String::from("key transport failed")))
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let z = match &self.key {
            RecipientKeyMaterial::P256(k) => ecdh_secret(k, originator)?,
            RecipientKeyMaterial::P384(k) => ecdh_secret(k, originator)?,
            RecipientKeyMaterial::P521(k) => ecdh_secret(k, originator)?,
            _ => return Err(Error::Unrecognized),
        };
        cek_from_ecdh_secret(alg, wrap, &z, ukm, encrypted_key)
    }

    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let ss: Zeroizing<Vec<u8>> = match &self.key {
            RecipientKeyMaterial::MlKem512(k) => {
                Zeroizing::new(k.decapsulate_slice(kem_ct).map_err(crypto)?.to_vec())
            }
            RecipientKeyMaterial::MlKem768(k) => {
                Zeroizing::new(k.decapsulate_slice(kem_ct).map_err(crypto)?.to_vec())
            }
            RecipientKeyMaterial::MlKem1024(k) => {
                Zeroizing::new(k.decapsulate_slice(kem_ct).map_err(crypto)?.to_vec())
            }
            _ => return Err(Error::Unrecognized),
        };
        cek_from_kem_secret(kdf, wrap, &ss, ukm, encrypted_key)
    }
}

/// The private key a [`SoftwareKey`] holds.
enum SigningKeyMaterial {
    Rsa(RsaPrivateKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    #[cfg(feature = "pqc")]
    MlDsa44(Box<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa44>>),
    #[cfg(feature = "pqc")]
    MlDsa65(Box<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>>),
    #[cfg(feature = "pqc")]
    MlDsa87(Box<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>>),
}

/// The kind of key, not the key.
impl core::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SigningKeyMaterial::Rsa(_) => "Rsa",
            SigningKeyMaterial::P256(_) => "P256",
            SigningKeyMaterial::P384(_) => "P384",
            SigningKeyMaterial::P521(_) => "P521",
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa44(_) => "MlDsa44",
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa65(_) => "MlDsa65",
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa87(_) => "MlDsa87",
        })
    }
}

/// Decodes an RFC 9881 ML-DSA private key with parameter set `$params`, from any of its three
/// forms. A key in the `both` form whose expanded key is not the one its seed generates is refused.
#[cfg(feature = "pqc")]
macro_rules! ml_dsa_key {
    ($params:ty, $private_key:expr) => {{
        let malformed = || Error::InvalidInput(String::from("an ML-DSA private key malformed"));
        let from_seed = |seed: &OctetString| -> Result<ml_dsa::ExpandedSigningKey<$params>> {
            let seed = seed.as_bytes().try_into().map_err(|_| malformed())?;
            Ok(ml_dsa::SigningKey::<$params>::from_seed(&seed)
                .expanded_key()
                .clone())
        };
        match SeedOrExpandedKey::from_der($private_key)? {
            SeedOrExpandedKey::Seed(seed) => from_seed(&seed)?,
            #[allow(deprecated)]
            SeedOrExpandedKey::ExpandedKey(expanded) => {
                ml_dsa::ExpandedSigningKey::<$params>::from_expanded(
                    expanded.as_bytes().try_into().map_err(|_| malformed())?,
                )
            }
            SeedOrExpandedKey::Both(both) => {
                let key = from_seed(&both.seed)?;
                #[allow(deprecated)]
                let expanded = key.to_expanded();
                if expanded.as_slice() != both.expanded_key.as_bytes() {
                    return Err(Error::InvalidInput(String::from(
                        "an ML-DSA private key whose expanded key is not its seed's",
                    )));
                }
                key
            }
        }
    }};
}

/// The public key of an ML-DSA signing key, as a certificate would carry it.
#[cfg(feature = "pqc")]
fn ml_dsa_public_key<P: ml_dsa::MlDsaParams>(
    oid: ObjectIdentifier,
    key: &ml_dsa::ExpandedSigningKey<P>,
) -> Result<SubjectPublicKeyInfoOwned> {
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        },
        subject_public_key: der::asn1::BitString::from_bytes(&key.verifying_key().encode())?,
    })
}

/// Signs `message` with pure ML-DSA and an empty context string, as a certificate or CMS signature
/// is made, if `alg` is the key's algorithm with parameters absent.
#[cfg(feature = "pqc")]
fn ml_dsa_sign<P: ml_dsa::MlDsaParams>(
    key: &ml_dsa::ExpandedSigningKey<P>,
    key_oid: ObjectIdentifier,
    alg: &AlgorithmIdentifierOwned,
    message: &[u8],
) -> Result<Vec<u8>> {
    use ml_dsa::signature::Signer;
    if alg.oid != key_oid || alg.parameters.is_some() {
        return Err(Error::Unrecognized);
    }
    let signature = key.try_sign(message).map_err(crypto)?;
    Ok(signature.encode().to_vec())
}

/// Signs the digest of `message` with an ECDSA key on `$curve`, as a DER-encoded signature. The
/// signature algorithm's object identifier names the digest.
macro_rules! ecdsa_sign {
    ($curve:ident, $key:expr, $alg:expr, $message:expr) => {{
        use $curve::ecdsa::signature::hazmat::PrehashSigner;
        let prehash: Vec<u8> = match $alg {
            ECDSA_WITH_SHA_256 => Sha256::digest($message).to_vec(),
            ECDSA_WITH_SHA_384 => Sha384::digest($message).to_vec(),
            ECDSA_WITH_SHA_512 => Sha512::digest($message).to_vec(),
            _ => return Err(Error::Unrecognized),
        };
        let signature: $curve::ecdsa::Signature = $key.sign_prehash(&prehash).map_err(crypto)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }};
}

/// A [`SigningKey`] holding a private key in memory, with no certificate, and signing with
/// RustCrypto as [`SoftwareSigningKey`] does: e.g. a key signing its own certificate request or a
/// root's self-signed certificate.
///
/// It holds private key material: `Debug` shows the kind of key, not the key, and there is no
/// `Clone`.
pub struct SoftwareKey {
    public_key: SubjectPublicKeyInfoOwned,
    key: SigningKeyMaterial,
}

impl core::fmt::Debug for SoftwareKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareKey")
            .field("public_key", &self.public_key.algorithm.oid)
            .field("key", &self.key)
            .finish()
    }
}

impl SoftwareKey {
    /// A key for the PKCS #8 (RFC 5958) private key `der`: RSA, EC on P-256, P-384 or P-521, or
    /// with `pqc`, ML-DSA in any of RFC 9881's three forms.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let info = PrivateKeyInfoRef::from_der(der)?;
        let key = match info.algorithm.oid {
            RSA_ENCRYPTION => {
                SigningKeyMaterial::Rsa(RsaPrivateKey::from_pkcs8_der(der).map_err(crypto)?)
            }
            ID_EC_PUBLIC_KEY => match info.algorithm.parameters_oid().map_err(crypto)? {
                SECP_256_R_1 => SigningKeyMaterial::P256(
                    p256::SecretKey::from_pkcs8_der(der).map_err(crypto)?.into(),
                ),
                SECP_384_R_1 => SigningKeyMaterial::P384(
                    p384::SecretKey::from_pkcs8_der(der).map_err(crypto)?.into(),
                ),
                SECP_521_R_1 => SigningKeyMaterial::P521(
                    p521::ecdsa::SigningKey::from_bytes(
                        &p521::SecretKey::from_pkcs8_der(der)
                            .map_err(crypto)?
                            .to_bytes(),
                    )
                    .map_err(crypto)?,
                ),
                _ => return Err(Error::Unrecognized),
            },
            #[cfg(feature = "pqc")]
            ID_ML_DSA_44 => SigningKeyMaterial::MlDsa44(Box::new(ml_dsa_key!(
                ml_dsa::MlDsa44,
                info.private_key.as_bytes()
            ))),
            #[cfg(feature = "pqc")]
            ID_ML_DSA_65 => SigningKeyMaterial::MlDsa65(Box::new(ml_dsa_key!(
                ml_dsa::MlDsa65,
                info.private_key.as_bytes()
            ))),
            #[cfg(feature = "pqc")]
            ID_ML_DSA_87 => SigningKeyMaterial::MlDsa87(Box::new(ml_dsa_key!(
                ml_dsa::MlDsa87,
                info.private_key.as_bytes()
            ))),
            _ => return Err(Error::Unrecognized),
        };
        let from_der = |der: spki::Result<spki::Document>| -> Result<SubjectPublicKeyInfoOwned> {
            Ok(SubjectPublicKeyInfoOwned::from_der(
                der.map_err(crypto)?.as_bytes(),
            )?)
        };
        let public = match &key {
            SigningKeyMaterial::Rsa(k) => from_der(k.to_public_key().to_public_key_der())?,
            SigningKeyMaterial::P256(k) => {
                from_der(p256::PublicKey::from(k.verifying_key()).to_public_key_der())?
            }
            SigningKeyMaterial::P384(k) => {
                from_der(p384::PublicKey::from(k.verifying_key()).to_public_key_der())?
            }
            SigningKeyMaterial::P521(k) => {
                from_der(p521::PublicKey::from(k.verifying_key()).to_public_key_der())?
            }
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa44(k) => ml_dsa_public_key(ID_ML_DSA_44, k)?,
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa65(k) => ml_dsa_public_key(ID_ML_DSA_65, k)?,
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa87(k) => ml_dsa_public_key(ID_ML_DSA_87, k)?,
        };
        Ok(Self {
            public_key: public,
            key,
        })
    }

    /// Signs `message` with `alg`, if `alg` is one the key signs with.
    fn sign(&self, alg: &AlgorithmIdentifierOwned, message: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            SigningKeyMaterial::Rsa(key) => {
                if alg.oid == ID_RSASSA_PSS {
                    rsa_pss_sign(key, alg, message)
                } else {
                    rsa_pkcs1v15_sign(key, alg, message)
                }
            }
            SigningKeyMaterial::P256(key) => ecdsa_sign!(p256, key, alg.oid, message),
            SigningKeyMaterial::P384(key) => ecdsa_sign!(p384, key, alg.oid, message),
            SigningKeyMaterial::P521(key) => ecdsa_sign!(p521, key, alg.oid, message),
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa44(key) => ml_dsa_sign(key, ID_ML_DSA_44, alg, message),
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa65(key) => ml_dsa_sign(key, ID_ML_DSA_65, alg, message),
            #[cfg(feature = "pqc")]
            SigningKeyMaterial::MlDsa87(key) => ml_dsa_sign(key, ID_ML_DSA_87, alg, message),
        }
    }
}

impl SigningKey for SoftwareKey {
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        &self.public_key
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign(alg, message)
    }
}

/// A [`SigningCredential`] holding a private key in memory and signing with RustCrypto: RSA with
/// PKCS #1 v1.5 or RSASSA-PSS, or ECDSA on P-256, P-384 or P-521, each with SHA-256, -384 or -512,
/// and with `pqc`, ML-DSA. A [`SoftwareKey`] with its certificate.
pub struct SoftwareSigningKey {
    certificate: Certificate,
    key: SoftwareKey,
}

/// The certificate's subject and the kind of key, not the key.
impl core::fmt::Debug for SoftwareSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareSigningKey")
            .field(
                "subject",
                &format_args!("{}", self.certificate.tbs_certificate().subject()),
            )
            .field("key", &self.key.key)
            .finish()
    }
}

impl SoftwareSigningKey {
    /// A credential for the PKCS #8 (RFC 5958) private key `der`, identified by `certificate`. The
    /// key must be the private half of the certificate's public key.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let key = SoftwareKey::from_pkcs8_der(der)?;
        if key.public_key != *certificate.tbs_certificate().subject_public_key_info() {
            return Err(Error::InvalidInput(String::from(
                "the private key is not the certificate's",
            )));
        }
        Ok(Self { certificate, key })
    }
}

/// Signs `message` with RSASSA-PSS as this crate produces it: MGF1 with the same hash, and a salt
/// the length of the hash. Other parameters are declined.
fn rsa_pss_sign(
    key: &RsaPrivateKey,
    alg: &AlgorithmIdentifierOwned,
    message: &[u8],
) -> Result<Vec<u8>> {
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let params = alg.parameters.as_ref().ok_or(Error::Unrecognized)?;
    let params = rsa::pkcs1::RsaPssParamsOwned::from_der(&params.to_der()?)?;
    let digest_len = match params.hash.oid {
        ID_SHA_256 => 32,
        ID_SHA_384 => 48,
        ID_SHA_512 => 64,
        _ => return Err(Error::Unrecognized),
    };
    let mgf_hash = params.mask_gen.parameters.as_ref().map(|h| h.oid);
    if usize::from(params.salt_len) != digest_len || mgf_hash != Some(params.hash.oid) {
        return Err(Error::Unrecognized);
    }
    let mut rng = rng();
    let signature = match params.hash.oid {
        ID_SHA_256 => rsa::pss::SigningKey::<Sha256>::new(key.clone())
            .try_sign_with_rng(&mut rng, message)
            .map(|s| s.to_vec()),
        ID_SHA_384 => rsa::pss::SigningKey::<Sha384>::new(key.clone())
            .try_sign_with_rng(&mut rng, message)
            .map(|s| s.to_vec()),
        _ => rsa::pss::SigningKey::<Sha512>::new(key.clone())
            .try_sign_with_rng(&mut rng, message)
            .map(|s| s.to_vec()),
    };
    signature.map_err(crypto)
}

/// Signs `message` with RSASSA-PKCS1-v1_5, the hash named by the signature algorithm.
fn rsa_pkcs1v15_sign(
    key: &RsaPrivateKey,
    alg: &AlgorithmIdentifierOwned,
    message: &[u8],
) -> Result<Vec<u8>> {
    use rsa::signature::{SignatureEncoding, Signer};
    let signature = match alg.oid {
        SHA_256_WITH_RSA_ENCRYPTION => rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
            .try_sign(message)
            .map(|s| s.to_vec()),
        SHA_384_WITH_RSA_ENCRYPTION => rsa::pkcs1v15::SigningKey::<Sha384>::new(key.clone())
            .try_sign(message)
            .map(|s| s.to_vec()),
        SHA_512_WITH_RSA_ENCRYPTION => rsa::pkcs1v15::SigningKey::<Sha512>::new(key.clone())
            .try_sign(message)
            .map(|s| s.to_vec()),
        _ => return Err(Error::Unrecognized),
    };
    signature.map_err(crypto)
}

impl SigningCredential for SoftwareSigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.key.sign(alg, message)
    }
}
