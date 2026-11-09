# certval-cms

Cryptographic Message Syntax (CMS) support for [certval](https://github.com/carl-wallace/rust-pki).

Builds, decrypts, signs and verifies EnvelopedData (RFC 5652), AuthEnvelopedData (RFC 5083) and
SignedData (RFC 5652), for key transport, key agreement and KEM recipients. The crate does the
message processing but does not fix the cryptography: every cryptographic operation goes through a
plug point on a `CmsEnvironment`, the CMS counterpart of certval's `PkiEnvironment`, where
implementations of that operation's interface are registered. A crypto provider registers its
implementations so that the work is done by its own module, such as the platform's validated one,
whether or not a given deployment uses it. The crate's software implementations are one more set,
registered with `populate_software`, not a fixed default.

| Plug point | Interface | Dispatch |
|---|---|---|
| Content encryption and decryption | `EncryptContent`, `DecryptContent` | per algorithm |
| Recipient key management | `EncryptKeyTransport`, `EncryptKeyAgreement`, `EncryptKem` | per algorithm |
| A recipient's private key, for decryption | `RecipientCredential`, found through a `RecipientCredentialSource` | per key |
| A signer's private key, for signing | `SigningCredential`, found through a `SigningCredentialSource` | per key |
| A recipient's or signer's certificate | `RecipientCertificateSource`, `SignerCertificateSource` | per lookup |
| Hashing, signature verification and certificate vetting | certval's `PkiEnvironment`, which the environment holds | per algorithm |

Implementations per algorithm are offered a request in the order registered, and the first that
does not return `Error::Unrecognized` answers. Credentials and certificates are found by identifier
through the registered sources, or passed to an operation directly.

```rust
use certval_cms::{
    CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyTransRecipient,
    KeyTransportAlgorithm, SignedDataBuilder, Signer, SignerPolicy,
};

// Cryptographic operations are handled by providers in the order they are registered.
// In some cases, a platform provider would be registered first, with a software implementation
// used as a fallback.
let mut env = CmsEnvironment::new();
env.populate_software();
env.set_pki_environment(pki_environment);

// The recipient's key transport goes through the environment, as the content encryption does.
// No settings, so the certificate is not vetted; with settings, the environment's PkiEnvironment
// would validate it first.
let recipient = KeyTransRecipient::from_certificate(
    &env,
    &recipient_cert,
    None,
    KeyTransportAlgorithm::RsaOaepSha256,
)?;
let content_info = EnvelopedDataBuilder::new(b"message", ContentEncryptionAlgorithm::Aes256Cbc)?
    .add_recipient(recipient)
    .build_content_info(&env, &mut rng)?;

// The recipient's private key is a credential, here passed directly; a registered source would
// otherwise find it by the recipient identifier.
let decrypted = env.decrypt_enveloped_data(&content_info, Some(&recipient_key))?;

// Signing and verifying, the signer's certificate vetted with `settings`.
let signed = SignedDataBuilder::new(b"message")
    .add_signer(Signer::explicit(&signing_key))
    .build(&env)?;
let verified =
    env.verify_signed_data(&signed.content_info, None, Some(&settings), SignerPolicy::All)?;
```

## What is reused from the `cms` crate, and what is not

The `cms` crate's builders do their cryptography in process with RustCrypto: its
`EnvelopedDataBuilder` generates the content-encryption key and encrypts with AES-CBC only, its key
transport recipient takes an `rsa` public key and does PKCS #1 v1.5 only, and its key agreement
recipient is generic over RustCrypto curve, KDF and key wrap types. It has no AuthEnvelopedData or
KEM recipient builder, and no decryption. Its one provider hook covers password recipients.

This crate reuses `cms`'s ASN.1 types unchanged and builds everything else itself: content
encryption, and the key transport, key agreement and KEM recipients, which implement this crate's
one-method `RecipientInfoBuilder` with their cryptography going through the environment. A
recipient whose key management lies elsewhere implements the same trait and is added the same way,
reaching no plug point. Signing in `cms` is already pluggable through
`signature::Signer`, and `SignerCredential` adapts any such signer to this crate's signing.
`CredentialSigner` goes the other way: it presents a `SigningKey` as a `signature::Signer`, with
its public key as the verifying key, so that x509-cert's certificate, request and CRL builders and
x509-ocsp's builders can sign with a key any provider holds. Every `SigningCredential` is a
`SigningKey`, with its certificate's public key; a key with no certificate yet, such as a
`SoftwareKey`, implements `SigningKey` alone, to sign its own certificate request or a self-signed
root.

## Enveloping

| Recipient | Type | Algorithms |
|---|---|---|
| Key transport (KeyTransRecipientInfo) | `KeyTransRecipient` | RSAES-PKCS1-v1_5; RSAES-OAEP with SHA-1, -256, -384 or -512 |
| Key agreement (KeyAgreeRecipientInfo) | `KeyAgreeRecipient` | ephemeral-static ECDH on P-256, P-384 or P-521, X9.63 KDF with SHA-256, -384 or -512 (RFC 5753), AES-128/192/256 key wrap |
| KEM (KEMRecipientInfo, RFC 9629) | `KemRecipient` | ML-KEM-512, -768 or -1024, HKDF with SHA-256, -384 or -512 (RFC 8619), AES-128/192/256 key wrap |

| Content encryption | Message | Parameters |
|---|---|---|
| AES-128/192/256-CBC | EnvelopedData | the IV (RFC 3565) |
| AES-128/192/256-GCM | AuthEnvelopedData | `GCMParameters`, 12-octet nonce, 16-octet tag (RFC 5084) |

Each implementation performs a recipient's whole operation, so a secret derived along the way, such
as an ECDH shared secret or a key-encryption key, stays inside the implementation that derived it.
A key holder that performs only part of an operation composes with the public helpers:
`unpad_pkcs1v15` after a raw RSA decryption, `cek_from_ecdh_secret` and `wrap_with_ecdh_secret`
after an ECDH that returns the shared secret, and `cek_from_kem_secret` after a decapsulation. `ecc_cms_shared_info` and
`kem_other_info` give the exact KDF inputs, and `content_decryption_parameters` checks and decodes
the inputs to content decryption.

Decryption matches recipients by identifier: each RecipientInfo's subject key identifier, issuer and
serial number, or rKeyId is offered to the credential passed in, or to the registered sources, and
the first match whose operation the credential performs decrypts. Recipients are not tried one after
another. An explicit credential that matches no recipient is an error, without falling back to the
sources. A failed RSAES-PKCS1-v1_5 key transport goes on with a random content-encryption key (RFC
3218), so it fails as a wrong key does. EnvelopedData's AES-CBC does not authenticate, so a wrong
key is not always detected; content whose integrity matters is AuthEnvelopedData or contains its own
protection, such as a SignedData.

ECDH with the SHA-1 X9.63 KDF, OpenSSL's default for `cms -encrypt`, is not supported.

## SignedData

`SignedDataBuilder` signs with one or more signers, each with its own credential and signature
algorithm, which defaults from the key, or from what the credential prefers; the digest algorithm
is the one the signature algorithm uses, or SHA-256 for ML-DSA, which uses none, unless set. Every
signer's signed attributes contain content-type and message-digest, an ESSCertIDv2 of
its certificate in a signing-certificate-v2 attribute (RFC 5035) unless `without_ess_cert_id` is
set, a signing time when one is given, and any others the caller adds. The content is encapsulated,
or left out of the message with `detached`, or hashed elsewhere and given to `from_digest`. Hashing
goes through the `PkiEnvironment`, and a credential signs either the message or its digest,
whichever its key holder does.

`verify_signed_data` finds each signer's certificate among the message's certificates or through the
sources, checks content-type, message-digest and signing-certificate-v2, verifies the signature with
the `PkiEnvironment`, and vets the certificate when settings are given. Every signer must verify,
or, with `SignerPolicy::Any`, at least one, the failures reported. Detached content is passed to it.
A SignedData with no signers is not verified; `certificates_only` reads its certificates. The
signing-certificate attribute of RFC 2634, which identifies the certificate by its SHA-1 hash, and
the policies field of signing-certificate-v2 are not processed.

`unwrap_content_info` verifies and decrypts nested SignedData, EnvelopedData and AuthEnvelopedData,
in either order, returning each layer's result and the innermost content.

## Certificate vetting

A recipient's or signer's certificate is vetted when the operation is given
`CertificationPathSettings`, and not otherwise; the result says which (`Vetting`). Settings given
to an environment without a `PkiEnvironment` are an error, never a silent skip. Vetting builds and
validates certification paths (RFC 5280) with the `PkiEnvironment`, checks revocation with what it
holds (nothing is fetched), and requires the key usage the use needs: keyEncipherment for key
transport and KEMs, keyAgreement for key agreement, digitalSignature or nonRepudiation for signing.
certval's settings check revocation by default, and without `std` its time of interest is disabled
unless set.

When the `PkiEnvironment` has no path for a signer, paths are prepared through the CA certificates
the message contains, together with the `PkiEnvironment`'s own, and validated by it unchanged. The
message's CA certificates a validated path needed are reported, for a caller to add if it chooses;
verification does not add them.

## Software, and key formats

`populate_software` registers RustCrypto implementations of the per-algorithm interfaces.
`SoftwareRecipientKey` and `SoftwareSigningKey` are credentials for keys held in memory, from
PKCS #8: RSA, EC on P-256, P-384 and P-521, ML-KEM, and, with `pqc`, ML-DSA. ML-KEM and ML-DSA
private keys are read in any of the three forms of RFC 9935 and RFC 9881, the seed, the expanded
key, or both, which is the form OpenSSL writes.

| Feature | |
|---|---|
| `rsa` | certval's software RSA signature verification |
| `pqc` | ML-DSA signing in `SoftwareSigningKey`, and certval's software ML-DSA and SLH-DSA verification |

## Providers

| Crate (`cms` feature) | Content | Key transport | Key agreement | KEM | Credentials and sources |
|---|---|---|---|---|---|
| certval-openssl | AES-CBC, AES-GCM | encrypt | encrypt (ECDH and X9.63 in OpenSSL) | encrypt (ML-KEM, OpenSSL 3.5 or later) | OpenSSL keys: decrypt all three recipient types, sign |
| certval-security-framework | AES-CBC (CommonCrypto) | encrypt | encrypt (ECDH and X9.63 in Security.framework) | | `SecKey`s and the keychain's identities: decrypt, sign |
| certval-cng | AES-CBC, AES-GCM (BCrypt) | encrypt | encrypt (ECDH in BCrypt, X9.63 here) | | NCrypt keys and the certificate store: decrypt, sign |
| certval-awslc | AES-CBC, AES-GCM | encrypt | encrypt (ECDH in AWS-LC, X9.63 here) | encrypt (ML-KEM) | AWS-LC keys: decrypt all three recipient types, sign |
| certval-pkcs11 | | | | | keys on a token: decrypt all three recipient types, sign; the token's certificates as a source |

Providers can be mixed in one environment, a different one at each plug point.

## Testing

The tests build messages for every recipient type and algorithm combination and decrypt them, sign
and verify with every signature algorithm, and vet against a test PKI. With `CERTVAL_CMS_OPENSSL`
set to an `openssl` command, messages are also decrypted and verified by `openssl cms`, which shares
no code with this crate, and messages it builds are decrypted and verified here. ML-KEM recipients
need OpenSSL 3.6 or later there, and AuthEnvelopedData with authenticated attributes 3.6.4:

```text
CERTVAL_CMS_OPENSSL=openssl cargo test --all-features -- --nocapture
```

## Status

Enveloping, decryption, signing, verification and vetting are in place. Composite ML-KEM
(draft-ietf-lamps-pq-composite-kem and its CMS profile) is to follow.

The crate and its dependencies are `no_std` with `alloc`. Its software implementations draw
content-encryption keys, IVs and nonces from `getrandom`, which has a backend on every operating
system Rust targets and none on a bare target or `wasm32-unknown-unknown`; building there means
providing one, as getrandom's documentation on custom backends describes.

## License

Apache-2.0 OR MIT.
