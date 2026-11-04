# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [Unreleased]

Builders for EnvelopedData (AES-CBC) and AuthEnvelopedData (AES-GCM) with content encryption
through `EncryptContent`, an interface for crypto providers, registered on a `CmsEnvironment`, and
`encrypt_content_rust_crypto`, its RustCrypto implementation. Recipient types for key transport
(RSA PKCS #1 v1.5 and OAEP), key agreement (ECDH on P-256/384/521 with the X9.63 KDF) and KEM
(ML-KEM with HKDF) recipients, whose cryptography goes through `EncryptKeyTransport`,
`EncryptKeyAgreement` and `EncryptKem` implementations registered on the environment, with
RustCrypto implementations of each. MSRV 1.89.
