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
//! whose key management goes through the environment. Any other
//! [`RecipientInfoBuilder`](cms::builder::RecipientInfoBuilder) can be added too, such as the `cms`
//! crate's, but it does its own cryptography and reaches no plug point.
//!
//! ```
//! use certval_cms::{
//!     CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyTransRecipient,
//!     KeyTransportAlgorithm, RecipientCredential,
//! };
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
//! let content_info = EnvelopedDataBuilder::new(b"message", ContentEncryptionAlgorithm::Aes256Cbc)?
//!     .add_recipient(recipient)
//!     .build_content_info(&env, &mut rng)?;
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
    ContentParameters, GcmParameters,
};
pub use credential::{
    contains_email_address, recipient_matches, subject_matches, unpad_pkcs1v15, CredentialOrigin,
    SingleRecipientCredential,
};
pub use decrypt::DecryptedContent;
pub use enveloped::{AuthEnvelopedDataBuilder, EnvelopedDataBuilder};
pub use environment::CmsEnvironment;
pub use environment_traits::{
    CertificateLookup, ContentEncryptionOutput, DecryptContent, EncryptContent, EncryptKem,
    EncryptKeyAgreement, EncryptKeyTransport, KemOutput, KeyAgreeOutput,
    RecipientCertificateSource, RecipientCredential, RecipientCredentialSource,
    SharedRecipientCredential, SharedSigningCredential, SignerCertificateSource, SigningCredential,
    SigningCredentialLookup, SigningCredentialSource,
};
pub use error::{Error, Result};
pub use ess::{EssCertIdV2, IssuerSerial, SigningCertificateV2};
pub use recipient::{
    ecc_cms_shared_info, kem_other_info, recipient_identifier, EccCmsSharedInfo, KemRecipient,
    KeyAgreeRecipient, KeyTransRecipient,
};
pub use signed::{
    default_signature_algorithm, rsa_pss, signer_identifier, signer_matches, BuiltSignedData,
    CertificatePublicKey, CredentialSignature, CredentialSigner, DigestAlgorithm,
    IncludeCertificates, SignedDataBuilder, Signer, SignerCredential, SignerReport,
    SingleSigningCredential,
};
pub use software::{
    cek_from_ecdh_secret, cek_from_kem_secret, encrypt_kem_rust_crypto,
    encrypt_key_agreement_rust_crypto, encrypt_key_transport_rust_crypto, wrap_with_ecdh_secret,
    SeedAndExpandedKey, SeedOrExpandedKey, SoftwareRecipientKey, SoftwareSigningKey,
};
pub use unwrap::{Layer, Unwrapped};
pub use verify::{
    certificates_only, CertificateOrigin, SignerPolicy, VerifiedSignedData, VerifiedSigner,
};
pub use vetting::{KeyUse, Vetting};
