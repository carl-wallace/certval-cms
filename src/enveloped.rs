//! Builders for AuthEnvelopedData (RFC 5083) and EncryptedData (RFC 5652, section 8), and
//! [`content_info`] for wrapping what any builder makes. EnvelopedData is built with cms's own
//! `EnvelopedDataBuilder`.
//!
//! Content encryption is a cms [`ContentEncryptor`], as it is for cms's `EnvelopedDataBuilder`:
//! [`CmsEnvironment::content_encryptor`](crate::CmsEnvironment::content_encryptor) gives one whose
//! encryption goes through the implementations registered on a `CmsEnvironment`. Recipients are
//! any cms [`RecipientInfoBuilder`], this crate's included.

use alloc::{boxed::Box, string::String, vec::Vec};

use cms::{
    authenticated_data::MessageAuthenticationCode,
    authenveloped_data::{AuthAttributes, AuthEnvelopedData, UnauthAttributes},
    builder::{ContentEncryptionOutput, ContentEncryptor, RecipientInfoBuilder},
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::{EncryptedContentInfo, OriginatorInfo, RecipientInfo, RecipientInfos},
};
use const_oid::db::rfc5911::{
    ID_CONTENT_TYPE, ID_CT_AUTH_ENVELOPED_DATA, ID_DATA, ID_ENCRYPTED_DATA,
};
use const_oid::ObjectIdentifier;
use der::{
    asn1::{Any, OctetString},
    Decode, Encode,
};
use rand_core::CryptoRng;
use x509_cert::attr::Attributes as UnprotectedAttributes;
use zeroize::Zeroizing;

use crate::decrypt::content_type_attribute;
use crate::error::{Error, Result};
use crate::signed::attribute;

type Recipients<'c, R> = Vec<Box<dyn RecipientInfoBuilder<Rng = R> + 'c>>;

/// Wraps an encoded message, such as the EnvelopedData cms's `EnvelopedDataBuilder` builds, in a
/// ContentInfo of type `content_type`.
pub fn content_info(content_type: ObjectIdentifier, message: &impl Encode) -> Result<ContentInfo> {
    Ok(ContentInfo {
        content_type,
        content: Any::from_der(&message.to_der()?)?,
    })
}

/// Encrypts with `encryptor` and checks that the output is for the algorithm the encryptor names.
fn encrypt<R: ?Sized>(
    encryptor: &(dyn ContentEncryptor<R> + '_),
    key: Option<&[u8]>,
    content: &[u8],
    aad: Option<&[u8]>,
    rng: &mut R,
) -> Result<ContentEncryptionOutput> {
    let output = encryptor.encrypt_content(key, content, aad, rng)?;
    if output.algorithm.oid != encryptor.oid() {
        return Err(Error::Crypto(alloc::format!(
            "the content encryptor for {} output {}",
            encryptor.oid(),
            output.algorithm.oid
        )));
    }
    Ok(output)
}

/// Builds AuthEnvelopedData (RFC 5083), with content encrypted by a cms [`ContentEncryptor`] for
/// an authenticated algorithm.
pub struct AuthEnvelopedDataBuilder<'c, R: ?Sized> {
    content: &'c [u8],
    content_type: ObjectIdentifier,
    encryptor: Box<dyn ContentEncryptor<R> + 'c>,
    originator_info: Option<OriginatorInfo>,
    auth_attrs: Option<AuthAttributes>,
    unauth_attrs: Option<UnauthAttributes>,
    recipients: Recipients<'c, R>,
}

impl<R: ?Sized> core::fmt::Debug for AuthEnvelopedDataBuilder<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthEnvelopedDataBuilder")
            .field("content", &format_args!("<{} octets>", self.content.len()))
            .field("content_type", &self.content_type)
            .field("algorithm", &self.encryptor.oid())
            .field("originator_info", &self.originator_info.is_some())
            .field("auth_attrs", &self.auth_attrs)
            .field("unauth_attrs", &self.unauth_attrs)
            .field("recipients", &self.recipients.len())
            .finish()
    }
}

impl<'c, R: CryptoRng + ?Sized> AuthEnvelopedDataBuilder<'c, R> {
    /// A builder encrypting `content`, of type id-data, with `encryptor`, whose algorithm must
    /// authenticate: one that produces no authentication tag is refused when building.
    pub fn new(content: &'c [u8], encryptor: impl ContentEncryptor<R> + 'c) -> Self {
        Self {
            content,
            content_type: ID_DATA,
            encryptor: Box::new(encryptor),
            originator_info: None,
            auth_attrs: None,
            unauth_attrs: None,
            recipients: Vec::new(),
        }
    }

    /// Sets the type of the content, id-data by default. RFC 5083 requires authenticated
    /// attributes, including content-type, for any other type.
    pub fn content_type(&mut self, content_type: ObjectIdentifier) -> &mut Self {
        self.content_type = content_type;
        self
    }

    /// Sets the originator information.
    pub fn originator_info(&mut self, originator_info: OriginatorInfo) -> &mut Self {
        self.originator_info = Some(originator_info);
        self
    }

    /// Sets the authenticated attributes, which the content encryption authenticates.
    pub fn auth_attrs(&mut self, attrs: AuthAttributes) -> &mut Self {
        self.auth_attrs = Some(attrs);
        self
    }

    /// Sets the unauthenticated attributes.
    pub fn unauth_attrs(&mut self, attrs: UnauthAttributes) -> &mut Self {
        self.unauth_attrs = Some(attrs);
        self
    }

    /// Adds a recipient. Whether the recipient's certificate was vetted is the recipient's to say,
    /// e.g. [`KeyTransRecipient::vetting`](crate::KeyTransRecipient::vetting), and is read before
    /// adding it; the message built does not report it.
    pub fn add_recipient(
        &mut self,
        recipient: impl RecipientInfoBuilder<Rng = R> + 'c,
    ) -> &mut Self {
        self.recipients.push(Box::new(recipient));
        self
    }

    /// Encrypts the content and builds the AuthEnvelopedData. `rng` is passed to the content
    /// encryptor and to the recipient builders.
    pub fn build(&mut self, rng: &mut R) -> Result<AuthEnvelopedData> {
        // RFC 5652, section 6.1, which RFC 5083 uses: recipientInfos is a SET SIZE (1..MAX).
        if self.recipients.is_empty() {
            return Err(Error::InvalidInput(String::from("no recipients")));
        }
        let auth_attrs = self.authenticated_attributes()?;
        // RFC 5083, section 2.1: the authenticated attributes are input to the authentication as
        // their DER encoding with an EXPLICIT SET OF tag, not the IMPLICIT [1] they are sent with.
        let aad = match &auth_attrs {
            Some(attrs) => Some(attrs.to_der()?),
            None => None,
        };
        let content = encrypt(&*self.encryptor, None, self.content, aad.as_deref(), rng)?;
        let tag = content.tag.clone().ok_or_else(|| {
            Error::InvalidInput(String::from(
                "AuthEnvelopedData needs an authenticated algorithm",
            ))
        })?;
        let infos = self
            .recipients
            .iter_mut()
            .map(|ri| ri.build_with_rng(&content.key, rng))
            .collect::<core::result::Result<Vec<RecipientInfo>, _>>()?;
        Ok(AuthEnvelopedData {
            // RFC 5083, section 2.1: "version is the syntax version number. It MUST be set to 0."
            version: CmsVersion::V0,
            originator_info: self.originator_info.clone(),
            recip_infos: RecipientInfos::try_from(infos)?,
            auth_encrypted_content_info: EncryptedContentInfo {
                content_type: self.content_type,
                content_enc_alg: content.algorithm,
                encrypted_content: Some(OctetString::new(content.ciphertext)?),
            },
            auth_attrs,
            mac: MessageAuthenticationCode::new(tag)?,
            unauth_attrs: self.unauth_attrs.clone(),
        })
    }

    /// The authenticated attributes to send. RFC 5083, section 2.1: the content type is outside
    /// what the tag covers, so for a type other than id-data the attributes must be present, and a
    /// content-type attribute binds the type; one is added when the caller gave none, and one
    /// giving another type is refused.
    fn authenticated_attributes(&self) -> Result<Option<AuthAttributes>> {
        let given = match &self.auth_attrs {
            Some(attrs) => content_type_attribute(attrs)?,
            None => None,
        };
        if let Some(given) = given {
            if given != self.content_type {
                return Err(Error::InvalidInput(alloc::format!(
                    "a content-type attribute of {given} for {} content",
                    self.content_type
                )));
            }
            return Ok(self.auth_attrs.clone());
        }
        if self.content_type == ID_DATA {
            return Ok(self.auth_attrs.clone());
        }
        let mut attrs = self.auth_attrs.clone().unwrap_or_default();
        attrs.insert(attribute(ID_CONTENT_TYPE, &self.content_type)?)?;
        Ok(Some(attrs))
    }

    /// As [`build`](Self::build), wrapped in a ContentInfo.
    pub fn build_content_info(&mut self, rng: &mut R) -> Result<ContentInfo> {
        let auth_enveloped_data = self.build(rng)?;
        content_info(ID_CT_AUTH_ENVELOPED_DATA, &auth_enveloped_data)
    }
}

/// Builds EncryptedData (RFC 5652, section 8): content encrypted under a key the parties already
/// share, with no recipients. Content encryption is a cms [`ContentEncryptor`] given the key, so
/// the algorithm must not authenticate: EncryptedData has no place for a tag.
pub struct EncryptedDataBuilder<'c, R: ?Sized> {
    content: &'c [u8],
    content_type: ObjectIdentifier,
    key: Zeroizing<Vec<u8>>,
    encryptor: Box<dyn ContentEncryptor<R> + 'c>,
    unprotected_attrs: Option<UnprotectedAttributes>,
}

impl<R: ?Sized> core::fmt::Debug for EncryptedDataBuilder<'_, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedDataBuilder")
            .field("content", &format_args!("<{} octets>", self.content.len()))
            .field("content_type", &self.content_type)
            .field("algorithm", &self.encryptor.oid())
            .field("unprotected_attrs", &self.unprotected_attrs)
            .finish_non_exhaustive()
    }
}

impl<'c, R: CryptoRng + ?Sized> EncryptedDataBuilder<'c, R> {
    /// A builder encrypting `content`, of type id-data, under `key` with `encryptor`.
    pub fn new(content: &'c [u8], key: &[u8], encryptor: impl ContentEncryptor<R> + 'c) -> Self {
        Self {
            content,
            content_type: ID_DATA,
            key: Zeroizing::new(key.to_vec()),
            encryptor: Box::new(encryptor),
            unprotected_attrs: None,
        }
    }

    /// Sets the type of the content, id-data by default.
    pub fn content_type(&mut self, content_type: ObjectIdentifier) -> &mut Self {
        self.content_type = content_type;
        self
    }

    /// Sets the unprotected attributes.
    pub fn unprotected_attrs(&mut self, attrs: UnprotectedAttributes) -> &mut Self {
        self.unprotected_attrs = Some(attrs);
        self
    }

    /// Encrypts the content and builds the EncryptedData. `rng` is passed to the content
    /// encryptor.
    pub fn build(&mut self, rng: &mut R) -> Result<EncryptedData> {
        let content = encrypt(&*self.encryptor, Some(&self.key), self.content, None, rng)?;
        if content.tag.is_some() {
            return Err(Error::InvalidInput(String::from(
                "EncryptedData has no place for an authentication tag",
            )));
        }
        Ok(EncryptedData {
            // RFC 5652, section 8: version 2 with unprotected attributes, otherwise 0.
            version: if self.unprotected_attrs.is_some() {
                CmsVersion::V2
            } else {
                CmsVersion::V0
            },
            enc_content_info: EncryptedContentInfo {
                content_type: self.content_type,
                content_enc_alg: content.algorithm,
                encrypted_content: Some(OctetString::new(content.ciphertext)?),
            },
            unprotected_attrs: self.unprotected_attrs.clone(),
        })
    }

    /// As [`build`](Self::build), wrapped in a ContentInfo.
    pub fn build_content_info(&mut self, rng: &mut R) -> Result<ContentInfo> {
        let encrypted_data = self.build(rng)?;
        content_info(ID_ENCRYPTED_DATA, &encrypted_data)
    }
}
