# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1]

Initial release. Builds, decrypts, signs and verifies EnvelopedData, AuthEnvelopedData and
SignedData with every cryptographic operation performed through a plug point on a `CmsEnvironment`:
content encryption and decryption (`EncryptContent`, `DecryptContent`), key transport, key agreement
and KEM recipient key management (`EncryptKeyTransport`, `EncryptKeyAgreement`, `EncryptKem`), the
private keys that decrypt and sign (`RecipientCredential`, `SigningCredential`) and the sources that
find them by identifier, sources of recipients' and signers' certificates, and a shared certval
`PkiEnvironment` for hashing, signature verification and certificate vetting. RustCrypto
implementations of each, and `SoftwareRecipientKey` and `SoftwareSigningKey` for keys in memory,
with ML-KEM and ML-DSA keys read in all three RFC 9935 and RFC 9881 forms.

Decryption matches recipients by identifier rather than trying each one, and continues a failed
RSAES-PKCS1-v1_5 key transport with a random content-encryption key (RFC 3218), so that malformed
padding cannot be told apart from a wrong key and the recipient cannot serve as a padding oracle.
An AuthEnvelopedData content type other than id-data is bound by a content-type authenticated
attribute, which the builder adds and decryption requires (RFC 5083).
SignedData objects may have any number of signers, with an ESSCertIDv2 binding each signer's certificate 
unless omitted by configuration; and detached or pre-hashed content; `SignerCredential` adapts any `signature::Signer`, and
`CredentialSigner` presents any `SigningKey` as one, for x509-cert's and x509-ocsp's builders.
`SigningKey` is a signing key known by its public key, which every `SigningCredential` is; a key
with no certificate yet, such as `SoftwareKey`, implements it alone.
Certificates are vetted when settings are given, signers' through the CA certificates a message
contains when the `PkiEnvironment` lacks a path, and the outcome is reported (`Vetting`).
`unwrap_content_info` processes nested messages. Features `rsa` and `pqc` turn on certval's software
RSA and post-quantum verification, and `pqc` ML-DSA and SLH-DSA signing, with the SHAKE128/256
message digests RFC 9814 pairs with SLH-DSA's SHAKE parameter sets. The crate reuses `cms`'s ASN.1
types and
defines its own `RecipientInfoBuilder`; it and its dependencies are `no_std` with `alloc`, given a
`getrandom` backend. MSRV 1.89.