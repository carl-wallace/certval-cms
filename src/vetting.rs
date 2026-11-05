//! Certificate vetting: certification path validation of the certificates whose keys CMS operations
//! rely on, by certval, through the [`PkiEnvironment`] a [`CmsEnvironment`] holds.
//!
//! Whether a certificate is vetted is the caller's choice at each operation, made by passing
//! [`CertificationPathSettings`] or not, and the operation's result says which happened
//! ([`Vetting`]). Settings passed to an environment holding no `PkiEnvironment` are an error, never
//! a silent skip.

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::fmt;

use certval::{
    check_revocation_local, validate_path_rfc5280, CertificationPath, CertificationPathResults,
    CertificationPathSettings, ExtensionProcessing, PDVCertificate, PathValidationStatus,
    PkiEnvironment, EXTS_OF_INTEREST,
};
use const_oid::db::{
    fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768},
    rfc5912::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE, ID_EC_PUBLIC_KEY, RSA_ENCRYPTION},
};
use der::{Decode, Encode};
use log::debug;
use x509_cert::{
    ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
    Certificate,
};

use crate::environment::CmsEnvironment;
use crate::environment_traits::{CertificateLookup, RecipientCertificateSource};
use crate::error::{Error, Result};

/// How the certificate behind an operation's key was established.
#[derive(Clone)]
#[non_exhaustive]
pub enum Vetting {
    /// No settings were passed, so the key was taken from the certificate as given.
    NotPerformed,
    /// certval validated a path from the certificate to a trust anchor. The results hold the
    /// path's outcome, including the policy processing.
    Validated(Box<CertificationPathResults>),
}

impl fmt::Debug for Vetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Vetting::NotPerformed => f.write_str("NotPerformed"),
            Vetting::Validated(_) => f.write_str("Validated"),
        }
    }
}

/// What a vetted certificate's key is to be used for, which decides the key usage the certificate
/// must permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyUse {
    /// RSA key transport: keyEncipherment.
    KeyTransport,
    /// Key agreement: keyAgreement.
    KeyAgreement,
    /// A KEM (RFC 9629): keyEncipherment, as RFC 9935 gives ML-KEM certificates.
    Kem,
    /// Signing: digitalSignature or nonRepudiation.
    Signing,
}

impl KeyUse {
    /// Whether `ku` permits this use.
    fn permitted_by(self, ku: &KeyUsage) -> bool {
        match self {
            KeyUse::KeyTransport | KeyUse::Kem => ku.0.contains(KeyUsages::KeyEncipherment),
            KeyUse::KeyAgreement => ku.0.contains(KeyUsages::KeyAgreement),
            KeyUse::Signing => {
                ku.0.contains(KeyUsages::DigitalSignature)
                    || ku.0.contains(KeyUsages::NonRepudiation)
            }
        }
    }
}

/// Whether `cert`'s key usage extension, if it has one, permits `key_use`. A certificate without
/// the extension places no restriction on its key (RFC 5280, section 4.2.1.3).
pub(crate) fn key_usage_permits(cert: &Certificate, key_use: KeyUse) -> Result<bool> {
    let Some(ext) = cert
        .tbs_certificate()
        .extensions()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == ID_CE_KEY_USAGE))
    else {
        return Ok(true);
    };
    Ok(key_use.permitted_by(&KeyUsage::from_der(ext.extn_value.as_bytes())?))
}

/// Whether `cert`'s key usage extension, if it has one, permits encryption with its key: the
/// [`KeyUse`] its key's algorithm is put to, or either keyEncipherment or keyAgreement for an
/// algorithm not encrypted to here.
fn permits_encryption(cert: &Certificate) -> Result<bool> {
    let key_use = match cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
    {
        RSA_ENCRYPTION => KeyUse::KeyTransport,
        ID_EC_PUBLIC_KEY => KeyUse::KeyAgreement,
        ID_ALG_ML_KEM_512 | ID_ALG_ML_KEM_768 | ID_ALG_ML_KEM_1024 => KeyUse::Kem,
        _ => {
            return Ok(key_usage_permits(cert, KeyUse::KeyTransport)?
                || key_usage_permits(cert, KeyUse::KeyAgreement)?)
        }
    };
    key_usage_permits(cert, key_use)
}

impl CmsEnvironment {
    /// Sets the [`PkiEnvironment`] that vets certificates: its trust anchors, certificate sources,
    /// revocation sources and the implementations that verify certificate signatures. It is shared,
    /// so the same one can serve other environments and certificate validation elsewhere.
    pub fn set_pki_environment(&mut self, pki_environment: Arc<PkiEnvironment>) {
        self.pki_environment = Some(pki_environment);
    }

    /// The [`PkiEnvironment`] that vets certificates, if one is set.
    pub fn pki_environment(&self) -> Option<&Arc<PkiEnvironment>> {
        self.pki_environment.as_ref()
    }

    /// Vets `cert` for `key_use` under `settings`, or does not, when `settings` is `None`.
    ///
    /// Vetting builds the certification paths from `cert` to a trust anchor through the
    /// [`PkiEnvironment`]'s sources and validates them (RFC 5280) until one is valid, checking
    /// revocation as `settings` ask, then requires that the certificate's key usage permit
    /// `key_use`. Revocation is checked with what the `PkiEnvironment` already holds, its cached
    /// statuses and registered CRL sources; nothing is fetched. certval's settings check revocation
    /// by default, so a caller without revocation information turns that off or registers it.
    /// Likewise the time of interest is the settings', which under certval without `std` is
    /// disabled unless set.
    ///
    /// Returns [`Vetting::NotPerformed`] when `settings` is `None`, and
    /// [`Error::NoPkiEnvironment`] when `settings` is given but no `PkiEnvironment` is set.
    pub fn vet_certificate(
        &self,
        cert: &Certificate,
        key_use: KeyUse,
        settings: Option<&CertificationPathSettings>,
    ) -> Result<Vetting> {
        Ok(self.vet_with_candidates(cert, key_use, settings, &[])?.0)
    }

    /// Vets as [`vet_certificate`](Self::vet_certificate) does, and if the `PkiEnvironment`'s
    /// sources yield no path, prepares paths by hand through `candidates`, CA certificates a message
    /// carried, together with the `PkiEnvironment`'s own intermediates, and validates those with the
    /// `PkiEnvironment` as it is; nothing is added to it. Returns the candidates on the path that
    /// validated, which the `PkiEnvironment` lacked.
    pub(crate) fn vet_with_candidates(
        &self,
        cert: &Certificate,
        key_use: KeyUse,
        settings: Option<&CertificationPathSettings>,
        candidates: &[Certificate],
    ) -> Result<(Vetting, Vec<Certificate>)> {
        let Some(settings) = settings else {
            return Ok((Vetting::NotPerformed, vec![]));
        };
        let Some(pe) = &self.pki_environment else {
            return Err(Error::NoPkiEnvironment);
        };
        let target = pdv_certificate(cert)?;

        let mut paths = vec![];
        pe.get_paths_for_target(&target, &mut paths, 0, settings.get_time_of_interest())?;
        let mut failure = certval::Error::PathValidation(PathValidationStatus::NoPathsFound);
        if let Some(results) = validate_first(pe, settings, &paths, &mut failure) {
            return Ok((vetted(cert, key_use, results)?, vec![]));
        }

        // The message's CA certificates are consulted only when the environment has no valid path.
        let candidates: Vec<&Certificate> = candidates.iter().filter(|c| is_ca(c)).collect();
        if candidates.is_empty() {
            return Err(Error::Certval(failure));
        }
        let decoded = candidates
            .iter()
            .map(|c| pdv_certificate(c))
            .collect::<Result<Vec<_>>>()?;
        let mut prepared = vec![];
        prepare_paths(pe, &target, &target, &decoded, &mut vec![], &mut prepared);
        for (path, used) in prepared {
            let from_message = used.into_iter().map(|i| candidates[i].clone()).collect();
            let mut results = CertificationPathResults::new();
            let outcome = validate_path_rfc5280(pe, settings, &path, &mut results)
                .and_then(|()| check_revocation_local(pe, settings, &path, &mut results));
            match outcome {
                Ok(()) => return Ok((vetted(cert, key_use, results)?, from_message)),
                Err(e) => failure = e,
            }
        }
        Err(Error::Certval(failure))
    }

    /// Registers a source of recipient certificates after those already registered.
    pub fn add_recipient_certificate_source<
        S: RecipientCertificateSource + Send + Sync + 'static,
    >(
        &mut self,
        source: S,
    ) {
        self.recipient_certificate_sources.push(Box::new(source));
    }

    /// Removes every source of recipient certificates.
    pub fn clear_recipient_certificate_sources(&mut self) {
        self.recipient_certificate_sources.clear();
    }

    /// Every certificate the registered sources return for `lookup`, in the order registered,
    /// whose key usage permits encryption with its key: keyEncipherment for an RSA or ML-KEM key,
    /// keyAgreement for an EC key, and either for a key of another algorithm. A certificate whose
    /// key usage extension does not decode is passed over. Any narrower choice, e.g. by extended
    /// key usage, is the caller's. The certificates are not vetted here; a recipient made from one
    /// is, when settings are passed.
    pub fn find_recipient_certificates(
        &self,
        lookup: CertificateLookup<'_>,
    ) -> Result<Vec<Certificate>> {
        let mut found = vec![];
        for source in &self.recipient_certificate_sources {
            for cert in source.find_recipient_certificates(self, lookup)? {
                match permits_encryption(&cert) {
                    Ok(true) => found.push(cert),
                    Ok(false) => {}
                    Err(e) => debug!("passing over a recipient certificate: {e}"),
                }
            }
        }
        Ok(found)
    }

    /// The first of [`find_recipient_certificates`](Self::find_recipient_certificates).
    pub fn find_recipient_certificate(
        &self,
        lookup: CertificateLookup<'_>,
    ) -> Result<Option<Certificate>> {
        Ok(self.find_recipient_certificates(lookup)?.into_iter().next())
    }
}

/// The longest chain of intermediates path preparation follows.
const MAX_PREPARED_INTERMEDIATES: usize = 8;

fn pdv_certificate(cert: &Certificate) -> Result<PDVCertificate> {
    let mut pdv = PDVCertificate::try_from(cert.to_der()?.as_slice())?;
    pdv.parse_extensions(EXTS_OF_INTEREST);
    Ok(pdv)
}

/// Whether `cert` is a CA certificate: basic constraints with cA set.
fn is_ca(cert: &Certificate) -> bool {
    cert.tbs_certificate()
        .extensions()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS))
        .and_then(|ext| BasicConstraints::from_der(ext.extn_value.as_bytes()).ok())
        .is_some_and(|bc| bc.ca)
}

/// Validates each of `paths`, with revocation as the settings ask, and returns the results for the
/// first that is valid, leaving the last failure in `failure` otherwise.
fn validate_first(
    pe: &PkiEnvironment,
    settings: &CertificationPathSettings,
    paths: &[CertificationPath],
    failure: &mut certval::Error,
) -> Option<CertificationPathResults> {
    for path in paths {
        let mut results = CertificationPathResults::new();
        let outcome = validate_path_rfc5280(pe, settings, path, &mut results)
            .and_then(|()| check_revocation_local(pe, settings, path, &mut results));
        match outcome {
            Ok(()) => return Some(results),
            Err(e) => *failure = e,
        }
    }
    None
}

/// The outcome for a certificate whose path validated: [`Vetting::Validated`] if its key usage
/// permits `key_use`, otherwise an error.
fn vetted(
    cert: &Certificate,
    key_use: KeyUse,
    results: CertificationPathResults,
) -> Result<Vetting> {
    if !key_usage_permits(cert, key_use)? {
        return Err(Error::Certval(certval::Error::PathValidation(
            PathValidationStatus::InvalidKeyUsage,
        )));
    }
    Ok(Vetting::Validated(Box::new(results)))
}

/// Prepares the paths from `current` up to a trust anchor, following issuer names through
/// `candidates` and the `PkiEnvironment`'s intermediates. `chain` holds the certificates above the
/// target so far, each with its position in `candidates` if it came from there; each path found is
/// pushed to `paths` with the positions of the candidates it used.
fn prepare_paths(
    pe: &PkiEnvironment,
    target: &PDVCertificate,
    current: &PDVCertificate,
    candidates: &[PDVCertificate],
    chain: &mut Vec<(PDVCertificate, Option<usize>)>,
    paths: &mut Vec<(CertificationPath, Vec<usize>)>,
) {
    if let Ok(anchor) = pe.get_trust_anchor_for_target(current) {
        // The chain runs from the target's issuer upward; a path's intermediates run from the one
        // the anchor issued down.
        let intermediates = chain.iter().rev().map(|(c, _)| c.clone()).collect();
        let used = chain
            .iter()
            .filter_map(|(_, candidate)| *candidate)
            .collect();
        paths.push((
            CertificationPath::new(anchor.clone(), intermediates, target.clone()),
            used,
        ));
        return;
    }
    if chain.len() == MAX_PREPARED_INTERMEDIATES {
        return;
    }
    let issuer = current.decoded().tbs_certificate().issuer();
    let from_candidates = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.decoded().tbs_certificate().subject() == issuer)
        .map(|(i, c)| (c, Some(i)));
    let from_environment = pe.get_cert_by_name(issuer).into_iter().map(|c| (c, None));
    for (next, candidate) in from_candidates.chain(from_environment) {
        if next == target || chain.iter().any(|(c, _)| c == next) {
            continue;
        }
        chain.push((next.clone(), candidate));
        prepare_paths(pe, target, next, candidates, chain, paths);
        chain.pop();
    }
}

impl From<certval::Error> for Error {
    fn from(e: certval::Error) -> Self {
        Error::Certval(e)
    }
}
