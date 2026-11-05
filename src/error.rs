//! Error type.

use alloc::string::String;
use core::fmt;

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by this crate and by implementations of its traits.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The implementation does not perform the requested operation. An ordered set of
    /// implementations passes the request to the next one, as certval's callbacks do.
    Unrecognized,
    /// A request the implementation does perform, made with unusable inputs, e.g. associated data
    /// for a content encryption algorithm that does not authenticate.
    InvalidInput(String),
    /// The cryptographic operation failed.
    Crypto(String),
    /// Encoding or decoding failed.
    Asn1(der::Error),
    /// A recipient builder failed.
    Builder(cms::builder::Error),
    /// No recipient of a message is one an available credential decrypts for.
    NoMatchingRecipient,
    /// No credential is available for a signer, or no certificate for a SignerInfo's signer.
    NoMatchingSigner,
    /// Vetting was asked for, with settings, but the environment holds no `PkiEnvironment`.
    NoPkiEnvironment,
    /// certval reported a failure: no valid certification path, a key usage that does not permit
    /// the use, or a signature that did not verify. The error says which.
    Certval(certval::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unrecognized => f.write_str("operation not performed by this implementation"),
            Error::InvalidInput(e) => write!(f, "invalid input: {e}"),
            Error::Crypto(e) => write!(f, "cryptographic operation failed: {e}"),
            Error::Asn1(e) => write!(f, "ASN.1 error: {e}"),
            Error::Builder(e) => write!(f, "recipient builder error: {e}"),
            Error::NoMatchingSigner => {
                f.write_str("no credential or certificate is available for a signer")
            }
            Error::NoPkiEnvironment => {
                f.write_str("vetting was asked for, but no PkiEnvironment is set")
            }
            Error::Certval(e) => write!(f, "certval: {e}"),
            Error::NoMatchingRecipient => {
                f.write_str("no recipient of the message matches an available credential")
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Asn1(e)
    }
}

impl From<cms::builder::Error> for Error {
    fn from(e: cms::builder::Error) -> Self {
        Error::Builder(e)
    }
}
