//! Decryption of EnvelopedData (RFC 5652, section 6) and AuthEnvelopedData (RFC 5083).

use alloc::{string::String, vec, vec::Vec};

use cms::{
    authenveloped_data::{AuthAttributes, AuthEnvelopedData},
    content_info::ContentInfo,
    enveloped_data::{
        EnvelopedData, KeyAgreeRecipientIdentifier, OriginatorIdentifierOrKey, RecipientIdentifier,
        RecipientInfo, RecipientInfos,
    },
    kemri::{KemRecipientInfo, ID_ORI_KEM},
};
use const_oid::db::rfc5911::{
    ID_CONTENT_TYPE, ID_CT_AUTH_ENVELOPED_DATA, ID_DATA, ID_ENVELOPED_DATA,
};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use zeroize::Zeroizing;

use crate::algorithms::{
    ContentEncryptionAlgorithm, KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm,
};
use crate::credential::{recipient_matches, CredentialOrigin};
use crate::environment::CmsEnvironment;
use crate::environment_traits::{RecipientCredential, SharedRecipientCredential};
use crate::error::{Error, Result};

/// The result of decrypting an EnvelopedData or AuthEnvelopedData.
#[non_exhaustive]
pub struct DecryptedContent {
    /// The encryptedContentInfo's contentType, the type of `content`.
    pub content_type: ObjectIdentifier,
    /// The decrypted content.
    pub content: Zeroizing<Vec<u8>>,
    /// The identifier of the recipient whose key decrypted the message.
    pub recipient: RecipientIdentifier,
    /// The position of that recipient's RecipientInfo in the message.
    pub recipient_index: usize,
    /// Where the credential that decrypted it came from.
    pub credential: CredentialOrigin,
    /// AuthEnvelopedData's authenticated attributes, which the authentication tag covered.
    pub auth_attrs: Option<AuthAttributes>,
}

/// Shows the content's length, not the content.
impl core::fmt::Debug for DecryptedContent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedContent")
            .field("content_type", &self.content_type)
            .field("content", &format_args!("<{} octets>", self.content.len()))
            .field("recipient", &self.recipient)
            .field("recipient_index", &self.recipient_index)
            .field("credential", &self.credential)
            .field("auth_attrs", &self.auth_attrs)
            .finish()
    }
}

/// A credential found for a recipient, borrowed when passed in and shared when a source found it.
enum Found<'a> {
    Explicit(&'a dyn RecipientCredential),
    Source(SharedRecipientCredential, usize),
}

impl Found<'_> {
    fn credential(&self) -> &dyn RecipientCredential {
        match self {
            Found::Explicit(c) => *c,
            Found::Source(c, _) => c.as_ref(),
        }
    }

    fn origin(&self) -> CredentialOrigin {
        match self {
            Found::Explicit(_) => CredentialOrigin::Explicit,
            Found::Source(_, index) => CredentialOrigin::Source(*index),
        }
    }
}

/// One recipient's key management, ready to run with a credential.
enum Operation<'m> {
    KeyTransport(KeyTransportAlgorithm, &'m [u8]),
    KeyAgreement {
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: SubjectPublicKeyInfoOwned,
        ukm: Option<&'m [u8]>,
        encrypted_key: &'m [u8],
    },
    Kem {
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem: ObjectIdentifier,
        kem_ct: Vec<u8>,
        ukm: Option<Vec<u8>>,
        encrypted_key: Vec<u8>,
    },
    /// An algorithm, or a form of the recipient type, that this crate does not process.
    Unsupported,
}

/// A KeyAgreeRecipientInfo's recipient identifier, in the form the other recipient types use.
fn key_agree_rid(rid: &KeyAgreeRecipientIdentifier) -> RecipientIdentifier {
    match rid {
        KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(iasn) => {
            RecipientIdentifier::IssuerAndSerialNumber(iasn.clone())
        }
        KeyAgreeRecipientIdentifier::RKeyId(rkid) => {
            RecipientIdentifier::SubjectKeyIdentifier(rkid.subject_key_identifier.clone())
        }
    }
}

/// `result` as an operation, with an algorithm this crate does not recognize as
/// [`Operation::Unsupported`].
fn supported<'m, T>(
    result: Result<T>,
    operation: impl FnOnce(T) -> Operation<'m>,
) -> Result<Operation<'m>> {
    match result {
        Ok(algs) => Ok(operation(algs)),
        Err(Error::Unrecognized) => Ok(Operation::Unsupported),
        Err(e) => Err(e),
    }
}

/// The recipient identifiers in one RecipientInfo, each with its operation, or with the error in
/// that recipient's own fields, which concerns only a credential that matches it. A
/// KeyAgreeRecipientInfo can carry several; the others carry one. Password, KEK and other
/// recipients carry no identifier a credential could match, and yield none. The error returned is
/// a RecipientInfo whose identifiers cannot be read at all.
fn recipients(ri: &RecipientInfo) -> Result<Vec<(RecipientIdentifier, Result<Operation<'_>>)>> {
    match ri {
        RecipientInfo::Ktri(ktri) => {
            let operation = supported(
                KeyTransportAlgorithm::from_algorithm_identifier(&ktri.key_enc_alg),
                |alg| Operation::KeyTransport(alg, ktri.enc_key.as_bytes()),
            );
            Ok(vec![(ktri.rid.clone(), operation)])
        }
        RecipientInfo::Kari(kari) => {
            // RFC 5753, section 3.1.1: the originator's ephemeral key. An originator identified by
            // certificate (static-static ECDH) is not processed.
            let originator = match &kari.originator {
                OriginatorIdentifierOrKey::OriginatorKey(key) => Some(SubjectPublicKeyInfoOwned {
                    algorithm: key.algorithm.clone(),
                    subject_public_key: key.public_key.clone(),
                }),
                _ => None,
            };
            let ukm = kari.ukm.as_ref().map(|ukm| ukm.as_bytes());
            Ok(kari
                .recipient_enc_keys
                .iter()
                .map(|rek| {
                    let operation = supported(
                        KeyAgreementAlgorithm::from_algorithm_identifier(&kari.key_enc_alg),
                        |(alg, wrap)| match &originator {
                            Some(originator) => Operation::KeyAgreement {
                                alg,
                                wrap,
                                originator: originator.clone(),
                                ukm,
                                encrypted_key: rek.enc_key.as_bytes(),
                            },
                            None => Operation::Unsupported,
                        },
                    );
                    (key_agree_rid(&rek.rid), operation)
                })
                .collect())
        }
        RecipientInfo::Ori(ori) => {
            if ori.ori_type != ID_ORI_KEM {
                return Ok(vec![]);
            }
            let kemri = KemRecipientInfo::from_der(&ori.ori_value.to_der()?)?;
            let algs = KdfAlgorithm::from_algorithm_identifier(&kemri.kdf).and_then(|kdf| {
                Ok((
                    kdf,
                    KeyWrapAlgorithm::from_algorithm_identifier(&kemri.wrap)?,
                ))
            });
            let mut operation = supported(algs, |(kdf, wrap)| Operation::Kem {
                kdf,
                wrap,
                kem: kemri.kem.oid,
                kem_ct: kemri.kem_ct.as_bytes().to_vec(),
                ukm: kemri.ukm.as_ref().map(|ukm| ukm.as_bytes().to_vec()),
                encrypted_key: kemri.encrypted_key.as_bytes().to_vec(),
            });
            // RFC 9629, section 3: kekLength is the length of the key-encryption key, which the
            // wrap algorithm determines.
            if let Ok(Operation::Kem { wrap, .. }) = &operation {
                if usize::from(kemri.kek_length) != wrap.kek_len() {
                    operation = Err(Error::InvalidInput(String::from(
                        "a KEMRecipientInfo whose kekLength does not match its wrap algorithm",
                    )));
                }
            }
            Ok(vec![(kemri.rid.clone(), operation)])
        }
        RecipientInfo::Kekri(_) | RecipientInfo::Pwri(_) => Ok(vec![]),
    }
}

/// The content type a content-type attribute among `attrs` gives, or `None` when there is none.
/// More than one, or one with other than one value, is malformed.
pub(crate) fn content_type_attribute(attrs: &AuthAttributes) -> Result<Option<ObjectIdentifier>> {
    let mut found = attrs.iter().filter(|a| a.oid == ID_CONTENT_TYPE);
    let attr = match (found.next(), found.next()) {
        (None, _) => return Ok(None),
        (Some(attr), None) => attr,
        (Some(_), Some(_)) => {
            return Err(Error::InvalidInput(String::from(
                "more than one content-type authenticated attribute",
            )))
        }
    };
    let mut values = attr.values.iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(Error::InvalidInput(String::from(
            "a content-type authenticated attribute without exactly one value",
        )));
    };
    Ok(Some(ObjectIdentifier::from_der(&value.to_der()?)?))
}

/// A random content-encryption key, the length `alg` takes.
fn random_key(alg: ContentEncryptionAlgorithm) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new(vec![0u8; alg.key_len()]);
    getrandom::fill(&mut key)
        .map_err(|e| Error::Crypto(alloc::format!("random number generator: {e}")))?;
    Ok(key)
}

impl CmsEnvironment {
    /// The credential for `rid`: `explicit` if given and it matches, otherwise the first the
    /// registered sources return. An explicit credential that does not match finds nothing; the
    /// sources are not consulted in its place.
    fn find_credential<'a>(
        &self,
        rid: &RecipientIdentifier,
        explicit: Option<&'a dyn RecipientCredential>,
    ) -> Result<Option<Found<'a>>> {
        match explicit {
            Some(credential) => Ok(recipient_matches(rid, credential.certificate())
                .then_some(Found::Explicit(credential))),
            None => Ok(self
                .find_recipient_credential(rid)?
                .map(|(credential, index)| Found::Source(credential, index))),
        }
    }

    /// Recovers the content-encryption key from the first recipient a credential is found for.
    fn recover_key(
        &self,
        recip_infos: &RecipientInfos,
        explicit: Option<&dyn RecipientCredential>,
        content_alg: ContentEncryptionAlgorithm,
    ) -> Result<(
        Zeroizing<Vec<u8>>,
        RecipientIdentifier,
        usize,
        CredentialOrigin,
    )> {
        // Whether a credential was found for some recipient whose operation could not be
        // performed, which is reported rather than as no recipient matching.
        let mut unsupported = false;
        // A RecipientInfo whose identifiers could not be read, reported when no other recipient
        // is one a credential decrypts for, since it might have been.
        let mut unreadable = None;
        for (index, ri) in recip_infos.0.iter().enumerate() {
            let recipients = match recipients(ri) {
                Ok(recipients) => recipients,
                Err(e) => {
                    unreadable = Some(e);
                    continue;
                }
            };
            for (rid, operation) in recipients {
                let Some(found) = self.find_credential(&rid, explicit)? else {
                    continue;
                };
                // This recipient is ours, so what is wrong with its fields is our error.
                let operation = operation?;
                let credential = found.credential();
                let result = match &operation {
                    Operation::KeyTransport(alg, encrypted_key) => {
                        credential.decrypt_key_transport(self, *alg, encrypted_key)
                    }
                    Operation::KeyAgreement {
                        alg,
                        wrap,
                        originator,
                        ukm,
                        encrypted_key,
                    } => credential.decrypt_key_agreement(
                        self,
                        *alg,
                        *wrap,
                        originator,
                        *ukm,
                        encrypted_key,
                    ),
                    Operation::Kem {
                        kdf,
                        wrap,
                        kem,
                        kem_ct,
                        ukm,
                        encrypted_key,
                    } => {
                        // The KEM must be the one the credential's key is for.
                        let key_alg = credential
                            .certificate()
                            .tbs_certificate()
                            .subject_public_key_info()
                            .algorithm
                            .oid;
                        if *kem == key_alg {
                            credential.decrypt_kem(
                                self,
                                *kdf,
                                *wrap,
                                kem_ct,
                                ukm.as_deref(),
                                encrypted_key,
                            )
                        } else {
                            Err(Error::Unrecognized)
                        }
                    }
                    Operation::Unsupported => Err(Error::Unrecognized),
                };
                // The credential does not perform this operation; another recipient may suit.
                if matches!(result, Err(Error::Unrecognized)) {
                    unsupported = true;
                    continue;
                }
                let key = if matches!(
                    operation,
                    Operation::KeyTransport(KeyTransportAlgorithm::RsaPkcs1v15, _)
                ) {
                    // RFC 3218, section 2.3.2: a failed RSAES-PKCS1-v1_5 decryption, or one
                    // yielding a key of the wrong length, goes on with a random content-encryption
                    // key, so that it fails at content decryption, as a wrong key does, rather than
                    // revealing that the padding was malformed.
                    match result {
                        Ok(key) => {
                            if key.len() == content_alg.key_len() {
                                key
                            } else {
                                random_key(content_alg)?
                            }
                        }
                        Err(_) => random_key(content_alg)?,
                    }
                } else {
                    result?
                };
                return Ok((key, rid, index, found.origin()));
            }
        }
        if unsupported {
            return Err(Error::Unrecognized);
        }
        match unreadable {
            Some(e) => Err(e),
            None => Err(Error::NoMatchingRecipient),
        }
    }

    /// Decrypts an EnvelopedData or AuthEnvelopedData in a ContentInfo.
    ///
    /// The recipient is found by identifier: each RecipientInfo's identifiers are offered, in
    /// order, to `credential` if given, otherwise to the registered
    /// [`RecipientCredentialSource`](crate::RecipientCredentialSource)s, and the first recipient a
    /// credential is found for, and whose operation it performs, decrypts. An explicit credential
    /// that matches no recipient is [`Error::NoMatchingRecipient`]; the sources are not consulted
    /// instead. Content decryption goes through the registered
    /// [`DecryptContent`](crate::DecryptContent) implementations, with AuthEnvelopedData's
    /// authenticated attributes as the associated data.
    ///
    /// EnvelopedData's content encryption does not authenticate, so a wrong key is not always
    /// detected: AES-CBC with a wrong key fails only when the padding comes out malformed, and
    /// otherwise yields content that is not the message. That includes the random
    /// content-encryption key that stands in for a failed RSAES-PKCS1-v1_5 key transport. Content
    /// whose integrity matters is either AuthEnvelopedData or carries its own protection, such as
    /// an enclosed SignedData.
    pub fn decrypt_enveloped_data(
        &self,
        content_info: &ContentInfo,
        credential: Option<&dyn RecipientCredential>,
    ) -> Result<DecryptedContent> {
        let message = content_info.content.to_der()?;
        let (eci, recip_infos, auth_attrs, tag) = match content_info.content_type {
            ID_ENVELOPED_DATA => {
                let ed = EnvelopedData::from_der(&message)?;
                (ed.encrypted_content, ed.recip_infos, None, None)
            }
            ID_CT_AUTH_ENVELOPED_DATA => {
                let aed = AuthEnvelopedData::from_der(&message)?;
                let tag = aed.mac.as_bytes().to_vec();
                (
                    aed.auth_encrypted_content_info,
                    aed.recip_infos,
                    aed.auth_attrs,
                    Some(tag),
                )
            }
            other => {
                return Err(Error::InvalidInput(alloc::format!(
                    "{other} is neither EnvelopedData nor AuthEnvelopedData"
                )))
            }
        };
        let content_alg = ContentEncryptionAlgorithm::from_oid(eci.content_enc_alg.oid)
            .ok_or(Error::Unrecognized)?;
        if content_alg.is_authenticated() != tag.is_some() {
            return Err(Error::InvalidInput(alloc::format!(
                "{content_alg:?} in {}",
                content_info.content_type
            )));
        }
        let ciphertext = eci.encrypted_content.as_ref().ok_or_else(|| {
            Error::InvalidInput(String::from("detached content is not supported"))
        })?;
        // RFC 5083, section 2.1: the content type is outside what the tag covers, so a type other
        // than id-data must be bound by a content-type authenticated attribute, which must give
        // the type the message carries.
        let bound_type = match &auth_attrs {
            Some(attrs) => content_type_attribute(attrs)?,
            None => None,
        };
        match bound_type {
            Some(bound) => {
                if bound != eci.content_type {
                    return Err(Error::InvalidInput(alloc::format!(
                        "a content-type attribute of {bound} for {} content",
                        eci.content_type
                    )));
                }
            }
            None => {
                if tag.is_some() && eci.content_type != ID_DATA {
                    return Err(Error::InvalidInput(alloc::format!(
                        "{} content without a content-type authenticated attribute",
                        eci.content_type
                    )));
                }
            }
        }
        // RFC 5083, section 2.1: the authenticated attributes are authenticated as their DER
        // encoding with an EXPLICIT SET OF tag.
        let aad = match &auth_attrs {
            Some(attrs) => Some(attrs.to_der()?),
            None => None,
        };

        let (key, recipient, recipient_index, origin) =
            self.recover_key(&recip_infos, credential, content_alg)?;
        let content = self.decrypt_content(
            &eci.content_enc_alg,
            &key,
            ciphertext.as_bytes(),
            aad.as_deref(),
            tag.as_deref(),
        )?;
        Ok(DecryptedContent {
            content_type: eci.content_type,
            content,
            recipient,
            recipient_index,
            credential: origin,
            auth_attrs,
        })
    }
}
