//! Cryptographic Message Syntax (CMS) for [certval](https://github.com/carl-wallace/rust-pki).
//!
//! This first part builds EnvelopedData (RFC 5652) and AuthEnvelopedData (RFC 5083) with content
//! encryption performed through [`EncryptContent`], an interface a crypto provider implements to do
//! the work with its own module, e.g., the platform's validated one. Implementations are registered
//! on a [`CmsEnvironment`], the CMS counterpart of certval's `PkiEnvironment`. Recipients are the `cms`
//! crate's [`RecipientInfoBuilder`](cms::builder::RecipientInfoBuilder) implementations, or a
//! provider's.
//!
//! ```
//! use certval_cms::{
//!     CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder,
//! };
//! # use cms::builder::{KeyEncryptionInfo, KeyTransRecipientInfoBuilder};
//! # use cms::enveloped_data::RecipientIdentifier;
//! # use cms::cert::IssuerAndSerialNumber;
//! # fn example(
//! #     rid: RecipientIdentifier,
//! #     key: rsa::RsaPublicKey,
//! # ) -> certval_cms::Result<()> {
//! # let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
//!
//! // A provider's implementation would be registered first; software answers what it declines.
//! let mut env = CmsEnvironment::new();
//! env.populate_software();
//!
//! let recipient = KeyTransRecipientInfoBuilder::new(rid, KeyEncryptionInfo::Rsa(key))?;
//! let content_info = EnvelopedDataBuilder::new(b"message", ContentEncryptionAlgorithm::Aes256Cbc)?
//!     .add_recipient(recipient)
//!     .build_content_info(&env, &mut rng)?;
//! # let _ = content_info;
//! # Ok(())
//! # }
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

mod algorithms;
mod content;
mod enveloped;
mod environment;
mod error;
mod recipient;
mod software;

pub use algorithms::{
    KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
    ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512,
};
pub use content::{
    encrypt_content_rust_crypto, ContentEncryptionAlgorithm, EncryptContent, EncryptedContent,
    GcmParameters,
};
pub use enveloped::{AuthEnvelopedDataBuilder, EnvelopedDataBuilder};
pub use environment::CmsEnvironment;
pub use error::{Error, Result};
pub use recipient::{
    recipient_identifier, EncryptKem, EncryptKeyAgreement, EncryptKeyTransport, KemOutput,
    KemRecipient, KeyAgreeOutput, KeyAgreeRecipient, KeyTransRecipient,
};
pub use software::{
    encrypt_kem_rust_crypto, encrypt_key_agreement_rust_crypto, encrypt_key_transport_rust_crypto,
};
