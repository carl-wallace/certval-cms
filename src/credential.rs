//! Credentials: the private keys that decrypt, and the sources that find them.
//!
//! A [`RecipientCredential`] holds one private key, wherever it lives (a token, a platform key
//! store, a hardware security module, software), and performs a recipient type's whole operation
//! with it. A [`RecipientCredentialSource`] is a store of such keys, e.g. a certificate store or a
//! key chain holding many, and finds the one a recipient identifier names. Sources are registered
//! on a [`CmsEnvironment`]; a single credential can also be passed to a decryption directly.

use alloc::{string::String, vec::Vec};

use cms::enveloped_data::RecipientIdentifier;
use const_oid::db::{
    rfc3280::EMAIL_ADDRESS,
    rfc5912::{ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER},
};
use der::{asn1::Ia5StringRef, Decode};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use x509_cert::{
    ext::pkix::{name::GeneralName, SubjectAltName, SubjectKeyIdentifier},
    name::Name,
    Certificate,
};
use zeroize::Zeroizing;

use crate::environment::CmsEnvironment;
use crate::environment_traits::{
    RecipientCredential, RecipientCredentialSource, SharedRecipientCredential,
};
use crate::error::{Error, Result};

/// A source holding one credential, which it returns for an identifier that names its
/// certificate.
pub struct SingleRecipientCredential(SharedRecipientCredential);

impl core::fmt::Debug for SingleRecipientCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SingleRecipientCredential")
            .field(
                "subject",
                &format_args!("{}", self.0.certificate().tbs_certificate().subject()),
            )
            .finish()
    }
}

impl SingleRecipientCredential {
    /// A source for `credential` alone.
    pub fn new(credential: SharedRecipientCredential) -> Self {
        Self(credential)
    }
}

impl RecipientCredentialSource for SingleRecipientCredential {
    fn find_recipient_credential(
        &self,
        _env: &CmsEnvironment,
        rid: &RecipientIdentifier,
    ) -> Result<Option<SharedRecipientCredential>> {
        Ok(recipient_matches(rid, self.0.certificate()).then(|| self.0.clone()))
    }
}

/// Where the credential that performed an operation came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialOrigin {
    /// The credential passed to the operation.
    Explicit,
    /// The source registered at this position on the environment.
    Source(usize),
}

/// Whether `cert` contains `email`, as an rfc822Name in its subject alternative name extension or
/// as an emailAddress attribute in its subject, the legacy form RFC 5280, section 4.1.2.6,
/// describes. Local parts compare exactly and domains without regard to ASCII case (RFC 5280,
/// section 7.5).
pub fn contains_email_address(cert: &Certificate, email: &str) -> bool {
    let tbs = cert.tbs_certificate();
    let in_san = tbs
        .extensions()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == ID_CE_SUBJECT_ALT_NAME))
        .and_then(|ext| SubjectAltName::from_der(ext.extn_value.as_bytes()).ok())
        .is_some_and(|san| {
            san.0.iter().any(|name| {
                let GeneralName::Rfc822Name(rfc822) = name else {
                    return false;
                };
                email_addresses_match(rfc822.as_str(), email)
            })
        });
    in_san
        || tbs.subject().iter().any(|atv| {
            atv.oid == EMAIL_ADDRESS
                && atv
                    .value
                    .decode_as::<Ia5StringRef<'_>>()
                    .is_ok_and(|value| email_addresses_match(value.as_str(), email))
        })
}

/// Whether two email addresses are the same mailbox: local parts equal, domains equal without
/// regard to ASCII case.
fn email_addresses_match(left: &str, right: &str) -> bool {
    match (left.rsplit_once('@'), right.rsplit_once('@')) {
        (Some((l_local, l_domain)), Some((r_local, r_domain))) => {
            l_local == r_local && l_domain.eq_ignore_ascii_case(r_domain)
        }
        _ => false,
    }
}

/// Whether `cert`'s subject is `subject`, compared as RFC 5280, section 7.1, describes.
pub fn subject_matches(subject: &Name, cert: &Certificate) -> bool {
    certval::compare_names(subject, cert.tbs_certificate().subject())
}

/// Whether `rid` names `cert`: its issuer and serial number, or its subject key identifier
/// extension. A certificate without that extension matches no subject key identifier.
pub fn recipient_matches(rid: &RecipientIdentifier, cert: &Certificate) -> bool {
    let tbs = cert.tbs_certificate();
    match rid {
        RecipientIdentifier::IssuerAndSerialNumber(iasn) => {
            iasn.issuer == *tbs.issuer() && iasn.serial_number == *tbs.serial_number()
        }
        RecipientIdentifier::SubjectKeyIdentifier(skid) => tbs
            .extensions()
            .and_then(|exts| {
                exts.iter()
                    .find(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
            })
            .and_then(|ext| SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok())
            .is_some_and(|cert_skid| cert_skid == *skid),
    }
}

/// Removes RSAES-PKCS1-v1_5 encryption padding (RFC 8017, section 7.2.2) from `em`, the output of
/// a raw RSA decryption with a `k`-octet modulus, for a [`RecipientCredential`] whose key holder
/// performs only the RSA operation.
///
/// The padding is examined in constant time, and every malformed encoding is the same
/// [`Error::Crypto`]. What remains observable, whether the padding was valid at all, is not an
/// oracle through this crate: decryption replaces a failed key transport with a random
/// content-encryption key and goes on, so a bad padding and a wrong key fail alike, at content
/// decryption (RFC 3218, section 2.3.2).
pub fn unpad_pkcs1v15(em: &[u8], k: usize) -> Result<Zeroizing<Vec<u8>>> {
    // Two octets of header, eight of padding string, and the zero separator at least.
    if k < 11 || em.len() != k {
        return Err(Error::Crypto(String::from("key transport failed")));
    }
    let header = em[0].ct_eq(&0) & em[1].ct_eq(&2);
    let mut looking = Choice::from(1);
    let mut separator = 0u32;
    for (i, octet) in em.iter().enumerate().skip(2) {
        let zero = octet.ct_eq(&0);
        separator.conditional_assign(&(i as u32), looking & zero);
        looking &= !zero;
    }
    // The separator follows a padding string of at least eight octets, so is at index 10 or later.
    let valid = header & !looking & !separator.ct_lt(&10);
    if bool::from(valid) {
        Ok(Zeroizing::new(em[separator as usize + 1..].to_vec()))
    } else {
        Err(Error::Crypto(String::from("key transport failed")))
    }
}
