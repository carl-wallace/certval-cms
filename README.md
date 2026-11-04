# certval-cms

Cryptographic Message Syntax (CMS) for [certval](https://github.com/carl-wallace/rust-pki).

This first part builds EnvelopedData (RFC 5652) and AuthEnvelopedData (RFC 5083) for key transport,
key agreement and KEM recipients, with every cryptographic operation performed through an interface
a crypto provider implements, so that the work is done by its own module, such as the platform's
validated one, rather than an in-process software implementation. Implementations are registered on a `CmsEnvironment`, the CMS counterpart
of certval's `PkiEnvironment`.

```rust
use certval_cms::{CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder};

// A provider's implementation would be registered first; software answers what it declines.
let mut env = CmsEnvironment::new();
env.populate_software();

let recipient = KeyTransRecipientInfoBuilder::new(rid, KeyEncryptionInfo::Rsa(key))?;
let content_info = EnvelopedDataBuilder::new(b"message", ContentEncryptionAlgorithm::Aes256Cbc)?
    .add_recipient(recipient)
    .build_content_info(&env, &mut rng)?;
```

## Why not the `cms` crate's builder

The `cms` crate's `EnvelopedDataBuilder` generates the content-encryption key and encrypts the
content itself with RustCrypto, and offers AES-CBC only. The builders here use `cms`'s types and its
`RecipientInfoBuilder` trait unchanged, so any of its recipient builders, or a provider's, can be
added; only content encryption is this crate's own, so that it can be routed to a provider.

## Recipients

| Recipient | Type | Algorithms |
|---|---|---|
| Key transport (KeyTransRecipientInfo) | `KeyTransRecipient` | RSAES-PKCS1-v1_5; RSAES-OAEP with SHA-1, -256, -384 or -512 |
| Key agreement (KeyAgreeRecipientInfo) | `KeyAgreeRecipient` | ephemeral-static ECDH on P-256, P-384 or P-521, X9.63 KDF with SHA-256, -384 or -512 (RFC 5753), AES-128/192/256 key wrap |
| KEM (KEMRecipientInfo, RFC 9629) | `KemRecipient` | ML-KEM-512, -768 or -1024, HKDF with SHA-256, -384 or -512 (RFC 8619), AES-128/192/256 key wrap |

Each recipient type is a `cms` `RecipientInfoBuilder` that does its cryptography through the
`CmsEnvironment` it was made with: `EncryptKeyTransport`, `EncryptKeyAgreement` and `EncryptKem`
are the interfaces, and the first registered implementation that does not decline answers, with
software (`populate_software`) last. Each implementation performs a recipient's whole operation from
the recipient's public key, so a secret derived along the way, such as an ECDH shared secret or a
key-encryption key, stays inside the implementation that derived it. `from_certificate` identifies
the recipient by the certificate's subject key identifier, or else its issuer and serial number.

User keying material, when given, is sent in the message and is input to the key derivation.

## Content encryption

| Algorithm | Message | Parameters |
|---|---|---|
| AES-128/192/256-CBC | EnvelopedData | the IV (RFC 3565) |
| AES-128/192/256-GCM | AuthEnvelopedData | `GCMParameters`, 12-octet nonce, 16-octet tag (RFC 5084) |

An `EncryptContent` implementation generates the key and the IV or nonce, encrypts, and returns the
key for the recipients to wrap. The key is in host memory from then until the message is built,
because every recipient wraps the same key. An implementation returns `Error::Unrecognized` for an
algorithm it does not perform, and the `CmsEnvironment` passes the request to the next one
registered, the way certval's `PkiEnvironment` consults its verification callbacks.
`encrypt_content_rust_crypto`, registered by `populate_software`, is the RustCrypto implementation.

An operation that validates a signer or recipient certificate will take a `PkiEnvironment` as well,
rather than the `CmsEnvironment` holding one, so that one can be shared across uses.

For AuthEnvelopedData, authenticated attributes are authenticated as their DER encoding with an
EXPLICIT SET OF tag, as RFC 5083, section 2.1 requires.

## Testing

The tests build messages for every recipient type and algorithm combination above and decrypt them
with RustCrypto. With `CERTVAL_CMS_OPENSSL` set to an `openssl` command, the same messages are also
decrypted by `openssl cms -decrypt`, an implementation that shares no code with this crate. ML-KEM
recipients need OpenSSL 3.6 or later there:

```text
CERTVAL_CMS_OPENSSL=openssl cargo test -- --nocapture
```

## Status

Encryption only. Decryption, signing and verification, with signer and recipient certificates
validated by certval, are to follow.

## License

Apache-2.0 OR MIT.
