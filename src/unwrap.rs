//! Processing nested CMS content: SignedData, EnvelopedData and AuthEnvelopedData inside one another,
//! verified or decrypted layer by layer through a [`CmsEnvironment`].

use alloc::{string::String, vec::Vec};

use certval::CertificationPathSettings;
use cms::content_info::ContentInfo;
use const_oid::{
    db::rfc5911::{ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA, ID_SIGNED_DATA},
    ObjectIdentifier,
};
use der::{Any, Decode};

use crate::decrypt::DecryptedContent;
use crate::environment::CmsEnvironment;
use crate::environment_traits::RecipientCredential;
use crate::error::{Error, Result};
use crate::verify::{SignerPolicy, VerifiedSignedData};

/// The deepest nesting processed.
const MAX_LAYERS: usize = 8;

/// One layer of nested content, as it was processed.
#[non_exhaustive]
pub enum Layer {
    /// A SignedData, verified.
    Signed(VerifiedSignedData),
    /// An EnvelopedData or AuthEnvelopedData, decrypted.
    Enveloped(DecryptedContent),
}

/// Nested content, with each layer's result, outermost first, and the innermost content.
#[non_exhaustive]
pub struct Unwrapped {
    /// The layers, outermost first.
    pub layers: Vec<Layer>,
    /// The innermost content's type, one that is not processed here, e.g. id-data.
    pub content_type: ObjectIdentifier,
    /// The innermost content.
    pub content: Vec<u8>,
}

/// Whether content of `content_type` is a layer processed here.
fn is_layer(content_type: ObjectIdentifier) -> bool {
    [ID_SIGNED_DATA, ID_ENVELOPED_DATA, ID_CT_AUTH_ENVELOPED_DATA].contains(&content_type)
}

impl CmsEnvironment {
    /// Verifies or decrypts `content_info`, and the content inside it in turn while that content is
    /// itself SignedData, EnvelopedData or AuthEnvelopedData, returning each layer's result and the
    /// innermost content.
    ///
    /// Each SignedData is verified with `settings` and `policy` (see
    /// [`verify_signed_data`](Self::verify_signed_data)), and each EnvelopedData and
    /// AuthEnvelopedData is decrypted with `credential` or the registered sources (see
    /// [`decrypt_enveloped_data`](Self::decrypt_enveloped_data)). Detached content and SignedData
    /// without signers are not processed here. Content of any other type ends the unwrapping, even
    /// when, as in a SCEP message, it is id-data whose octets happen to be a ContentInfo: that is
    /// for the caller to recognize and pass back in.
    pub fn unwrap_content_info(
        &self,
        content_info: &ContentInfo,
        credential: Option<&dyn RecipientCredential>,
        settings: Option<&CertificationPathSettings>,
        policy: SignerPolicy,
    ) -> Result<Unwrapped> {
        let mut layers = Vec::new();
        let mut current = content_info.clone();
        while layers.len() < MAX_LAYERS {
            let (content_type, content) = if current.content_type == ID_SIGNED_DATA {
                let verified = self.verify_signed_data(&current, None, settings, policy)?;
                let next = (verified.content_type, verified.content.clone());
                layers.push(Layer::Signed(verified));
                next
            } else {
                let decrypted = self.decrypt_enveloped_data(&current, credential)?;
                let next = (decrypted.content_type, decrypted.content.to_vec());
                layers.push(Layer::Enveloped(decrypted));
                next
            };
            if !is_layer(content_type) {
                return Ok(Unwrapped {
                    layers,
                    content_type,
                    content,
                });
            }
            // RFC 5652, section 5.2: nested content is the inner structure itself, its type given
            // by the enclosing layer, so it is wrapped back into a ContentInfo to process.
            current = ContentInfo {
                content_type,
                content: Any::from_der(&content)?,
            };
        }
        Err(Error::InvalidInput(String::from(
            "content nested more deeply than is processed",
        )))
    }
}
