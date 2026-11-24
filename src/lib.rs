//! Cryptographic Message Syntax (CMS) for [certval](https://github.com/carl-wallace/rust-pki).
//!
//! Builds, decrypts, signs and verifies EnvelopedData (RFC 5652), AuthEnvelopedData (RFC 5083)
//! and SignedData (RFC 5652). The crate does the message processing but does not fix the
//! cryptography: every cryptographic operation goes through a plug point on a [`CmsEnvironment`],
//! the CMS counterpart of certval's `PkiEnvironment`, where implementations of that operation's
//! interface are registered. The plug points are content encryption and decryption
//! ([`EncryptContent`], [`DecryptContent`]); each kind of recipient key management
//! ([`EncryptKeyTransport`], [`EncryptKeyAgreement`], [`EncryptKem`]); the private keys that decrypt
//! and sign ([`RecipientCredential`], [`SigningCredential`]), found through sources
//! ([`RecipientCredentialSource`], [`SigningCredentialSource`]); the certificates of recipients and
//! signers ([`RecipientCertificateSource`], [`SignerCertificateSource`]); and certval's
//! `PkiEnvironment`, which the environment holds, for hashing, signature verification and
//! certificate vetting ([`Vetting`]). A crypto provider registers its implementations so that the
//! work is done by its own module, such as the platform's validated one. The crate's software
//! implementations are one more set, registered with
//! [`populate_software`](CmsEnvironment::populate_software), not a fixed default.
//!
//! Recipients are this crate's [`KeyTransRecipient`], [`KeyAgreeRecipient`] and [`KemRecipient`],
//! whose key management goes through the environment. Each is a cms
//! [`RecipientInfoBuilder`](cms::builder::RecipientInfoBuilder), so EnvelopedData is built with
//! cms's own `EnvelopedDataBuilder`, its content encrypted through the environment by the cms
//! [`ContentEncryptor`](cms::builder::ContentEncryptor) that
//! [`content_encryptor`](CmsEnvironment::content_encryptor) gives. A recipient whose key management
//! lies elsewhere, such as one of cms's own recipient builders, is added the same way; it reaches no
//! plug point. [`AuthEnvelopedDataBuilder`] and [`EncryptedDataBuilder`] take the same traits.
//!
//! ```
//! use certval_cms::{
//!     content_info, CmsEnvironment, ContentEncryptionAlgorithm, KeyTransRecipient,
//!     KeyTransportAlgorithm, RecipientCredential,
//! };
//! use cms::builder::EnvelopedDataBuilder;
//! use const_oid::db::rfc5911::ID_ENVELOPED_DATA;
//! # use x509_cert::Certificate;
//! # fn example(
//! #     recipient_cert: &Certificate,
//! #     recipient_key: &dyn RecipientCredential,
//! # ) -> certval_cms::Result<()> {
//! # let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
//!
//! // Cryptographic operations are handled by providers in the order they are registered.
//! // In some cases, a platform provider would be registered first, with a software implementation
//! // used as a fallback.
//! let mut env = CmsEnvironment::new();
//! env.populate_software();
//!
//! // The recipient's key transport goes through the environment, as the content encryption does.
//! // No settings, so the certificate is not vetted; with settings, the environment's
//! // PkiEnvironment would validate it first.
//! let recipient = KeyTransRecipient::from_certificate(
//!     &env,
//!     recipient_cert,
//!     None,
//!     KeyTransportAlgorithm::RsaOaepSha256,
//! )?;
//! let encryptor = env.content_encryptor(ContentEncryptionAlgorithm::Aes256Cbc);
//! let enveloped_data = EnvelopedDataBuilder::new(None, b"message", encryptor, None)?
//!     .add_recipient_info(recipient)?
//!     .build_with_rng(&mut rng)?;
//! let content_info = content_info(ID_ENVELOPED_DATA, &enveloped_data)?;
//!
//! // The recipient's private key is a credential, here passed directly; a registered source
//! // would otherwise find it by the recipient identifier.
//! let decrypted = env.decrypt_enveloped_data(&content_info, Some(recipient_key))?;
//! # let _ = decrypted;
//! # Ok(())
//! # }
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

mod algorithms;
mod content;
mod credential;
mod decrypt;
mod encryptor;
mod enveloped;
mod environment;
mod environment_traits;
mod error;
mod ess;
mod recipient;
mod signed;
mod software;
mod unwrap;
mod verify;
mod vetting;

pub use algorithms::{
    ContentEncryptionAlgorithm, KdfAlgorithm, KeyAgreementAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm, ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512,
};
pub use content::{
    content_decryption_parameters, decrypt_content_rust_crypto, encrypt_content_rust_crypto,
    encrypt_content_with_key_rust_crypto, ContentParameters, GcmParameters,
    RustCryptoContentEncryption,
};
pub use credential::{
    contains_email_address, recipient_matches, subject_matches, unpad_pkcs1v15, CredentialOrigin,
    SingleRecipientCredential,
};
pub use decrypt::DecryptedContent;
pub use encryptor::CmsContentEncryptor;
pub use enveloped::{content_info, AuthEnvelopedDataBuilder, EncryptedDataBuilder};
pub use environment::CmsEnvironment;
pub use environment_traits::{
    CertificateLookup, ContentEncryptionOutput, DecryptContent, EncryptContent, EncryptKem,
    EncryptKeyAgreement, EncryptKeyTransport, KemOutput, KeyAgreeOutput,
    RecipientCertificateSource, RecipientCredential, RecipientCredentialSource,
    SharedRecipientCredential, SharedSigningCredential, SignerCertificateSource, SigningCredential,
    SigningCredentialLookup, SigningCredentialSource, SigningKey,
};
pub use error::{Error, Result};
pub use recipient::{
    ecc_cms_shared_info, kem_other_info, recipient_identifier, KemRecipient, KeyAgreeRecipient,
    KeyTransRecipient,
};
pub use signed::{
    default_signature_algorithm, rsa_pss, signer_identifier, signer_matches, BuiltSignedData,
    CredentialSignature, CredentialSigner, DigestAlgorithm, IncludeCertificates, SignedDataBuilder,
    Signer, SignerCredential, SignerPublicKey, SignerReport, SingleSigningCredential,
};
pub use software::{
    cek_from_ecdh_secret, cek_from_kem_secret, encrypt_kem_rust_crypto,
    encrypt_key_agreement_rust_crypto, encrypt_key_transport_rust_crypto, wrap_with_ecdh_secret,
    SeedAndExpandedKey, SeedOrExpandedKey, SoftwareKey, SoftwareRecipientKey, SoftwareSigningKey,
};
pub use unwrap::{Layer, Unwrapped};
pub use verify::{
    certificates_only, CertificateOrigin, SignerPolicy, VerifiedSignedData, VerifiedSigner,
};
pub use vetting::{KeyUse, Vetting};
