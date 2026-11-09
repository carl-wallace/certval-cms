//! Builders for EnvelopedData (RFC 5652, section 6) and AuthEnvelopedData (RFC 5083).
//!
//! Recipients are any [`RecipientInfoBuilder`] from the `cms` crate, or one a provider supplies.
//! Content encryption goes through the implementations registered on a [`CmsEnvironment`] rather
//! than being fixed to RustCrypto, which is the difference from `cms`'s own `EnvelopedDataBuilder`.

use alloc::{boxed::Box, string::String, vec::Vec};

use cms::{
    authenticated_data::MessageAuthenticationCode,
    authenveloped_data::{AuthAttributes, AuthEnvelopedData, UnauthAttributes},
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{
        EncryptedContentInfo, EnvelopedData, OriginatorInfo, RecipientInfo, RecipientInfos,
    },
    revocation::RevocationInfoChoice,
};
use const_oid::db::rfc5911::{
    ID_CONTENT_TYPE, ID_CT_AUTH_ENVELOPED_DATA, ID_DATA, ID_ENVELOPED_DATA,
};
use const_oid::ObjectIdentifier;
use der::{
    asn1::{Any, OctetString},
    Decode, Encode,
};
use rand_core::CryptoRng;
use x509_cert::attr::Attributes as UnprotectedAttributes;

use crate::algorithms::ContentEncryptionAlgorithm;
use crate::decrypt::content_type_attribute;
use crate::environment::CmsEnvironment;
use crate::environment_traits::ContentEncryptionOutput;
use crate::error::{Error, Result};
use crate::recipient::RecipientInfoBuilder;
use crate::signed::attribute;

type Recipients<'c, R> = Vec<Box<dyn RecipientInfoBuilder<Rng = R> + 'c>>;

fn build_recipients<R: CryptoRng + ?Sized>(
    recipients: &mut Recipients<'_, R>,
    content: &ContentEncryptionOutput,
    rng: &mut R,
) -> Result<RecipientInfos> {
    if recipients.is_empty() {
        return Err(Error::InvalidInput(String::from("no recipients")));
    }
    let infos = recipients
        .iter_mut()
        .map(|ri| ri.build_with_rng(&content.key, rng))
        .collect::<Result<Vec<RecipientInfo>>>()?;
    Ok(RecipientInfos::try_from(infos)?)
}

/// Wraps an encoded message in a ContentInfo.
fn content_info(content_type: ObjectIdentifier, message: &impl Encode) -> Result<ContentInfo> {
    Ok(ContentInfo {
        content_type,
        content: Any::from_der(&message.to_der()?)?,
    })
}

/// Builds EnvelopedData, with content encrypted through a [`CmsEnvironment`].
pub struct EnvelopedDataBuilder<'c, R: ?Sized> {
    content: &'c [u8],
    content_type: ObjectIdentifier,
    algorithm: ContentEncryptionAlgorithm,
    originator_info: Option<OriginatorInfo>,
    unprotected_attrs: Option<UnprotectedAttributes>,
    recipients: Recipients<'c, R>,
}

impl<'c, R: CryptoRng + ?Sized> EnvelopedDataBuilder<'c, R> {
    /// A builder encrypting `content`, of type id-data, with `algorithm`, which must not be an
    /// authenticated algorithm (those are for [`AuthEnvelopedDataBuilder`]).
    pub fn new(content: &'c [u8], algorithm: ContentEncryptionAlgorithm) -> Result<Self> {
        if algorithm.is_authenticated() {
            return Err(Error::InvalidInput(String::from(
                "an authenticated algorithm is for AuthEnvelopedData",
            )));
        }
        Ok(Self {
            content,
            content_type: ID_DATA,
            algorithm,
            originator_info: None,
            unprotected_attrs: None,
            recipients: Vec::new(),
        })
    }

    /// Sets the type of the content, id-data by default.
    pub fn content_type(&mut self, content_type: ObjectIdentifier) -> &mut Self {
        self.content_type = content_type;
        self
    }

    /// Sets the originator information.
    pub fn originator_info(&mut self, originator_info: OriginatorInfo) -> &mut Self {
        self.originator_info = Some(originator_info);
        self
    }

    /// Sets the unprotected attributes.
    pub fn unprotected_attrs(&mut self, attrs: UnprotectedAttributes) -> &mut Self {
        self.unprotected_attrs = Some(attrs);
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

    /// Encrypts the content through `env` and builds the EnvelopedData. `rng` is passed to the
    /// recipient builders, which use it for, e.g., RSA padding or an ephemeral key.
    pub fn build(&mut self, env: &CmsEnvironment, rng: &mut R) -> Result<EnvelopedData> {
        let content = env.encrypt_content(self.algorithm, self.content, None)?;
        let recip_infos = build_recipients(&mut self.recipients, &content, rng)?;
        let version = enveloped_data_version(
            self.originator_info.as_ref(),
            &recip_infos,
            self.unprotected_attrs.is_some(),
        );
        Ok(EnvelopedData {
            version,
            originator_info: self.originator_info.clone(),
            recip_infos,
            encrypted_content: EncryptedContentInfo {
                content_type: self.content_type,
                content_enc_alg: content.algorithm,
                encrypted_content: Some(OctetString::new(content.ciphertext)?),
            },
            unprotected_attrs: self.unprotected_attrs.clone(),
        })
    }

    /// As [`build`](Self::build), wrapped in a ContentInfo.
    pub fn build_content_info(&mut self, env: &CmsEnvironment, rng: &mut R) -> Result<ContentInfo> {
        let enveloped_data = self.build(env, rng)?;
        content_info(ID_ENVELOPED_DATA, &enveloped_data)
    }
}

/// The EnvelopedData version, from RFC 5652, section 6.1. `cms` defines no version 2 attribute
/// certificate choice, so the attribute certificate condition for version 3 cannot arise.
fn enveloped_data_version(
    originator_info: Option<&OriginatorInfo>,
    recip_infos: &RecipientInfos,
    unprotected_attrs: bool,
) -> CmsVersion {
    let other_in_originator = originator_info.is_some_and(|oi| {
        oi.certs.as_ref().is_some_and(|certs| {
            certs
                .0
                .iter()
                .any(|c| matches!(c, CertificateChoices::Other(_)))
        }) || oi.crls.as_ref().is_some_and(|crls| {
            crls.0
                .iter()
                .any(|c| matches!(c, RevocationInfoChoice::Other(_)))
        })
    });
    if other_in_originator {
        CmsVersion::V4
    } else if recip_infos
        .0
        .iter()
        .any(|r| matches!(r, RecipientInfo::Pwri(_) | RecipientInfo::Ori(_)))
    {
        CmsVersion::V3
    } else if originator_info.is_none()
        && !unprotected_attrs
        && recip_infos.0.iter().all(|r| match r {
            RecipientInfo::Ktri(k) => k.version == CmsVersion::V0,
            _ => false,
        })
    {
        CmsVersion::V0
    } else {
        CmsVersion::V2
    }
}

/// Builds AuthEnvelopedData (RFC 5083), with content encrypted through a [`CmsEnvironment`] using
/// an authenticated algorithm.
pub struct AuthEnvelopedDataBuilder<'c, R: ?Sized> {
    content: &'c [u8],
    content_type: ObjectIdentifier,
    algorithm: ContentEncryptionAlgorithm,
    originator_info: Option<OriginatorInfo>,
    auth_attrs: Option<AuthAttributes>,
    unauth_attrs: Option<UnauthAttributes>,
    recipients: Recipients<'c, R>,
}

impl<'c, R: CryptoRng + ?Sized> AuthEnvelopedDataBuilder<'c, R> {
    /// A builder encrypting `content`, of type id-data, with `algorithm`, which must be an
    /// authenticated algorithm.
    pub fn new(content: &'c [u8], algorithm: ContentEncryptionAlgorithm) -> Result<Self> {
        if !algorithm.is_authenticated() {
            return Err(Error::InvalidInput(String::from(
                "AuthEnvelopedData needs an authenticated algorithm",
            )));
        }
        Ok(Self {
            content,
            content_type: ID_DATA,
            algorithm,
            originator_info: None,
            auth_attrs: None,
            unauth_attrs: None,
            recipients: Vec::new(),
        })
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

    /// Encrypts the content through `env` and builds the AuthEnvelopedData. `rng` is passed to
    /// the recipient builders.
    pub fn build(&mut self, env: &CmsEnvironment, rng: &mut R) -> Result<AuthEnvelopedData> {
        let auth_attrs = self.authenticated_attributes()?;
        // RFC 5083, section 2.1: the authenticated attributes are input to the authentication as
        // their DER encoding with an EXPLICIT SET OF tag, not the IMPLICIT [1] they are sent with.
        let aad = match &auth_attrs {
            Some(attrs) => Some(attrs.to_der()?),
            None => None,
        };
        let content = env.encrypt_content(self.algorithm, self.content, aad.as_deref())?;
        let tag = content
            .tag
            .clone()
            .ok_or_else(|| Error::Crypto(String::from("no authentication tag produced")))?;
        let recip_infos = build_recipients(&mut self.recipients, &content, rng)?;
        Ok(AuthEnvelopedData {
            // RFC 5083, section 2.1: "version is the syntax version number. It MUST be set to 0."
            version: CmsVersion::V0,
            originator_info: self.originator_info.clone(),
            recip_infos,
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
    pub fn build_content_info(&mut self, env: &CmsEnvironment, rng: &mut R) -> Result<ContentInfo> {
        let auth_enveloped_data = self.build(env, rng)?;
        content_info(ID_CT_AUTH_ENVELOPED_DATA, &auth_enveloped_data)
    }
}
