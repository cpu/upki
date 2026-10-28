use core::error::Error as StdError;
#[cfg(feature = "__fetch")]
use core::iter;
use core::str::FromStr;
use core::{fmt, str};
#[cfg(feature = "__fetch")]
use std::fs::File;
use std::io;
#[cfg(feature = "__fetch")]
use std::io::BufReader;
#[cfg(feature = "__fetch")]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clubcard_crlite::CRLiteKey;
pub use clubcard_crlite::IssuerSpkiHash;
#[cfg(feature = "__fetch")]
use jiff::Timestamp;
use rustls_pki_types::{CertificateDer, SubjectPublicKeyInfoDer, TrustAnchor};
use serde::{Deserialize, Serialize};
#[cfg(feature = "__fetch")]
use tracing::info;

#[cfg(feature = "__fetch")]
use crate::FetchError;
use crate::{Config, sha256};

#[cfg(feature = "__fetch")]
mod fetch;
#[cfg(feature = "__fetch")]
use fetch::Plan;
#[cfg(feature = "__fetch")]
pub(crate) use fetch::fetch;

mod index;
use index::Index;

/// Revocation data store used for querying the revocation status of certificates.
pub struct Store {
    cache_dir: PathBuf,
}

impl Store {
    /// Create a new `Store` from the given configuration.
    ///
    /// The `Store` will use the cache directory specified in the configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            cache_dir: config.revocation_cache_dir(),
        }
    }

    /// Verify the current contents of the cache against this manifest.
    ///
    /// This performs disk IO but does not perform network IO.
    #[cfg(feature = "__fetch")]
    pub fn verify(&self) -> Result<(), FetchError> {
        let manifest = Manifest::from_cache(&self.cache_dir)?;
        manifest.introduce()?;
        let plan = Plan::construct(
            &manifest,
            None::<iter::Empty<&str>>,
            "https://.../",
            &self.cache_dir,
        )?;
        match plan.download_bytes() {
            0 => Ok(()),
            bytes => Err(FetchError::Outdated(bytes)),
        }
    }

    /// Perform a revocation check.
    pub fn check(&self, input: &RevocationCheckInput) -> Result<RevocationStatus, Error> {
        Index::from_path(&self.cache_dir)?.check(input, &self.cache_dir)
    }

    /// Validate the revocation data store.
    pub fn validate(&self) -> Result<(), Error> {
        Index::from_path(&self.cache_dir).map(|_| ())
    }
}

/// The structure contained in a manifest.json
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// When this file was generated.
    ///
    /// UNIX timestamp in seconds.
    pub generated_at: u64,

    /// Some human-readable text.
    pub comment: String,

    /// List of required files.
    #[serde(alias = "filters")]
    pub files: Vec<ManifestFile>,
}

impl Manifest {
    #[cfg(feature = "__fetch")]
    fn from_cache(cache_dir: &Path) -> Result<Self, FetchError> {
        let file_name = cache_dir.join("manifest.json");
        let file = match File::open(&file_name) {
            Ok(f) => f,
            Err(error) => {
                return Err(FetchError::FileRead {
                    error,
                    path: Some(file_name),
                });
            }
        };

        serde_json::from_reader(BufReader::new(file)).map_err(|error| FetchError::FileDecode {
            error: Box::new(error),
            path: Some(file_name),
        })
    }

    /// Logs metadata fields in this manifest.
    #[cfg(feature = "__fetch")]
    fn introduce(&self) -> Result<(), FetchError> {
        let dt = i64::try_from(self.generated_at)
            .ok()
            .and_then(|secs| Timestamp::from_second(secs).ok());
        let Some(dt) = dt else {
            return Err(FetchError::InvalidTimestamp {
                input: self.generated_at.to_string(),
                context: "manifest generated (in s)",
            });
        };

        info!(
            comment = self.comment,
            date = %dt,
            "parsed manifest"
        );
        Ok(())
    }
}

/// Manifest data for a single crlite filter file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestFile {
    /// Relative filename.
    ///
    /// This is also the suggested local filename.
    pub filename: String,

    /// File size, indicative.  Allows a fetcher to predict data usage.
    pub size: usize,

    /// SHA256 hash of file contents.
    #[serde(with = "hex::serde")]
    pub hash: Vec<u8>,
}

/// Input parameters for a revocation check.
#[derive(Debug)]
pub struct RevocationCheckInput {
    /// Big-endian bytes encoding of the end-entity certificate serial number.
    pub cert_serial: CertSerial,
    /// SHA256 hash of the `SubjectPublicKeyInfo` of the issuer of the end-entity certificate.
    pub issuer_spki_hash: IssuerSpkiHash,
    /// CT log IDs and inclusion timestamps present in the end-entity certificate.
    pub sct_timestamps: Vec<CtTimestamp>,
    issuer_serial_hash: [u8; 32],
}

impl RevocationCheckInput {
    /// Construct a `RevocationCheckInput` from a sequence of DER-encoded certificates.
    ///
    /// The first element in `certificates` **must** be the end-entity certificate.  The
    /// end-entity certificate's issuer **must** be present in the other certificates
    /// (but does not need to be in any specific position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks before calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    pub fn from_certificates(certificates: &[CertificateDer<'_>]) -> Result<Self, Error> {
        for c in certificates {
            check_cert_denylist(c)?;
        }

        let (end_entity, rest) = certificates
            .split_first()
            .ok_or(Error::TooFewCertificates)?;
        let end_entity = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|error| Error::InvalidEndEntityCertificate(Box::new(error)))?;

        let issuer = find_issuer(end_entity.issuer(), rest.iter())?;
        let issuer_spki_hash = IssuerSpkiHash(
            sha256::Digest::from(&[webpki::spki_for_anchor(&issuer).as_ref()][..]).0,
        );

        let mut sct_timestamps = vec![];
        let iter = end_entity
            .sct_log_timestamps()
            .map_err(|e| Error::InvalidEndEntityCertificate(Box::new(e)))?;

        for ts in iter {
            let ts = ts.map_err(|e| Error::InvalidSctInCertificate(Box::new(e)))?;
            sct_timestamps.push(CtTimestamp {
                log_id: ts.log_id,
                timestamp: ts.timestamp_ms,
            });
        }

        Ok(Self::new(
            CertSerial(end_entity.serial().to_vec()),
            issuer_spki_hash,
            sct_timestamps,
        ))
    }

    /// Construct a `RevocationCheckInput` from its constituent parts.
    pub fn new(
        cert_serial: CertSerial,
        issuer_spki_hash: IssuerSpkiHash,
        sct_timestamps: Vec<CtTimestamp>,
    ) -> Self {
        let mut issuer_serial_context = sha256::Context::new();
        issuer_serial_context.update(&issuer_spki_hash.0);
        issuer_serial_context.update(&cert_serial.0);
        let issuer_serial_hash = issuer_serial_context.finish().0;

        Self {
            cert_serial,
            issuer_spki_hash,
            sct_timestamps,
            issuer_serial_hash,
        }
    }

    fn key(&self) -> CRLiteKey<'_> {
        CRLiteKey::with_hash(
            &self.issuer_spki_hash,
            &self.cert_serial.0,
            self.issuer_serial_hash,
        )
    }
}

/// A certificate serial number.
#[derive(Clone, Debug)]
pub struct CertSerial(pub Vec<u8>);

impl FromStr for CertSerial {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match BASE64_STANDARD.decode(value) {
            Ok(bytes) => Ok(Self(bytes)),
            Err(e) => Err(Error::InvalidBase64 {
                error: Box::new(e),
                context: "certificate serial",
            }),
        }
    }
}

/// An issuance timestamp established in certificate transparency.
#[derive(Clone, Debug)]
pub struct CtTimestamp {
    /// CT log ID
    pub log_id: [u8; 32],
    /// Issuance timestamp
    pub timestamp: u64,
}

impl FromStr for CtTimestamp {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((log_id, issuance_timestamp)) = value.split_once(":") else {
            return Err(Error::InvalidSctEncoding);
        };

        Ok(Self {
            log_id: BASE64_STANDARD
                .decode(log_id)
                .map_err(|e| Error::InvalidBase64 {
                    error: Box::new(e),
                    context: "CT log ID",
                })?
                .try_into()
                .map_err(|wrong: Vec<u8>| Error::InvalidLength {
                    expected: 32,
                    actual: wrong.len(),
                    context: "CT log ID",
                })?,
            timestamp: u64::from_str(issuance_timestamp).map_err(|_| Error::InvalidTimestamp {
                input: issuance_timestamp.to_string(),
                context: "CT timestamp (in ms)",
            })?,
        })
    }
}

/// The successful outcome of a revocation check.
///
/// Look at a value of this type to determine whether a certificate was revoked or not.
#[derive(Debug, PartialEq)]
#[must_use]
pub enum RevocationStatus {
    /// We couldn't determine the revocation status.
    ///
    /// Most likely, this certificate is very new and is not covered by the current filter dataset.
    NotCoveredByRevocationData,

    /// This certificate has been revoked.
    CertainlyRevoked,

    /// This certificate was covered by revocation data, and it is not currently revoked.
    NotRevoked,
}

impl RevocationStatus {
    /// Convert this revocation status to an exit code for the CLI.
    ///
    /// Also print the status to stdout.
    pub fn to_cli(&self) -> ExitCode {
        println!("{self:?}");
        match self {
            Self::NotRevoked | Self::NotCoveredByRevocationData => ExitCode::SUCCESS,
            Self::CertainlyRevoked => ExitCode::from(Self::EXIT_CODE_REVOCATION_REVOKED),
        }
    }

    const EXIT_CODE_REVOCATION_REVOKED: u8 = 2;
}

/// Details about crlite-style revocation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RevocationConfig {
    /// Where to fetch revocation data files.
    fetch_url: String,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            fetch_url: "https://upki.rustls.dev/revocation/".into(),
        }
    }
}

/// Checks an internal denylist for a certificate's public key.
///
/// Returns [`Error::CompromisedKey`] if the presented key is in the denylist.
fn check_cert_denylist(cert: &CertificateDer<'_>) -> Result<(), Error> {
    // nb. do not copy this code. it is not correct to treat intermediate certificates
    // as trust anchors.
    if let Ok(anchor) = webpki::anchor_from_trusted_cert(cert) {
        check_spki_denylist(&webpki::spki_for_anchor(&anchor))?;
    }
    Ok(())
}

/// Checks an internal denylist for public keys in SubjectPublicKeyInfo (SPKI) format.
///
/// Returns [`Error::CompromisedKey`] if the presented key is in the denylist.
fn check_spki_denylist(spki: &SubjectPublicKeyInfoDer<'_>) -> Result<(), Error> {
    let hash = sha256::Digest::from(&[spki.as_ref()][..]).0;
    for (blocked, why) in SPKI_DENYLIST {
        if hash == *blocked {
            return Err(Error::CompromisedKey(why));
        }
    }

    Ok(())
}

// SHA-256 fingerprints of the complete DER-encoded SubjectPublicKeyInfo.
const SPKI_DENYLIST: &[([u8; 32], &str)] = &[
    // EMDVTLSCAG3B.spki.der
    (
        [
            0xeb, 0xed, 0x64, 0x75, 0xc2, 0xc2, 0xd8, 0x0f, 0xcb, 0x19, 0x9f, 0x3f, 0xe8, 0xdd,
            0x6e, 0x6b, 0x3c, 0xe6, 0x0b, 0x77, 0xeb, 0x15, 0xd4, 0xe4, 0x2c, 0x3d, 0xec, 0x0c,
            0x6f, 0x5b, 0x51, 0x05,
        ],
        "the private key is 156",
    ),
    // EMDVTLSCAG3C.spki.der
    (
        [
            0x49, 0xdd, 0x35, 0x3d, 0xc2, 0xb9, 0x19, 0xa3, 0x77, 0x06, 0x45, 0x11, 0x7d, 0x0e,
            0x60, 0xc1, 0x61, 0x15, 0xe7, 0xd1, 0xbc, 0x25, 0x9e, 0xef, 0xe7, 0x34, 0xb0, 0x0e,
            0xa4, 0x34, 0xfe, 0x5f,
        ],
        "the private key is 230",
    ),
    // EMEVTLSCAG3B.spki.der
    (
        [
            0xe0, 0x25, 0x4c, 0x7f, 0xcd, 0xc2, 0x65, 0xe2, 0xf0, 0xf8, 0xa4, 0x28, 0xda, 0xbb,
            0x75, 0xab, 0x4a, 0xe0, 0x39, 0xb4, 0x87, 0x2d, 0x62, 0xf5, 0xee, 0x57, 0xf0, 0x87,
            0x7d, 0x5a, 0x8a, 0x41,
        ],
        "the private key is 115",
    ),
    // EMEVTLSCAG3C.spki.der
    (
        [
            0x5c, 0x06, 0x60, 0xa2, 0xb1, 0x64, 0x91, 0x0d, 0x8f, 0xf5, 0x89, 0xc1, 0x8e, 0x14,
            0x55, 0x2e, 0x9e, 0x0e, 0xc2, 0x37, 0xdc, 0xef, 0xe2, 0xcb, 0x73, 0x6d, 0x41, 0xa4,
            0x81, 0x1f, 0x81, 0xa0,
        ],
        "the private key is 56",
    ),
    // EMOVTLSCAG3B.spki.der
    (
        [
            0x43, 0xbf, 0xfa, 0x19, 0xd6, 0xef, 0x65, 0x14, 0x51, 0xf6, 0x84, 0x1e, 0x01, 0x99,
            0x31, 0xe9, 0x6f, 0x6f, 0x2e, 0xae, 0xff, 0x28, 0xab, 0x4b, 0x6f, 0x1c, 0xe4, 0x57,
            0x6d, 0xe2, 0x71, 0x7b,
        ],
        "the private key is 155",
    ),
    // EMOVTLSCAG3C.spki.der
    (
        [
            0x63, 0xec, 0xef, 0xee, 0x43, 0x1d, 0x49, 0x52, 0x3b, 0xc1, 0x13, 0x6c, 0x4e, 0x72,
            0xd0, 0x20, 0x6a, 0x47, 0x70, 0x86, 0xca, 0xf6, 0x06, 0xcd, 0x5c, 0xf0, 0x25, 0x68,
            0x6c, 0x10, 0x9c, 0xf8,
        ],
        "the private key is 4",
    ),
    // EMOVCSCAG3B.spki.der
    (
        [
            0xec, 0x4f, 0xfa, 0x1a, 0xd0, 0xac, 0x88, 0x08, 0x13, 0x14, 0xb7, 0xaa, 0xff, 0xef,
            0x6a, 0x91, 0xf9, 0x7c, 0xd5, 0x72, 0x91, 0xbb, 0x5b, 0xa6, 0x86, 0xc5, 0x41, 0x5f,
            0x5e, 0xb4, 0xf6, 0xb6,
        ],
        "the private key is 66",
    ),
    // EMOVCSCAG3C.spki.der
    (
        [
            0x92, 0xc0, 0x63, 0xd6, 0x7e, 0x8f, 0x14, 0xdb, 0x71, 0xd2, 0x88, 0xe1, 0x12, 0x66,
            0xff, 0xda, 0xf6, 0x9c, 0xbf, 0x11, 0x5f, 0x7b, 0xab, 0x14, 0xf3, 0xbc, 0x2f, 0x68,
            0xd2, 0x5e, 0x0e, 0x30,
        ],
        "the private key is 237",
    ),
];

fn find_issuer<'a>(
    name: &[u8],
    candidates: impl Iterator<Item = &'a CertificateDer<'a>>,
) -> Result<TrustAnchor<'a>, Error> {
    for (i, c) in candidates.enumerate() {
        // nb. do not copy this code. it is not correct to treat intermediate certificates
        // as trust anchors.
        let root = webpki::anchor_from_trusted_cert(c).map_err(|error| {
            Error::InvalidIntermediateCertificate {
                error: Box::new(error),
                index: i,
            }
        })?;

        if root.subject.as_ref() == name {
            return Ok(root);
        }
    }

    Err(Error::NoIssuer)
}

/// Errors for the revocation API.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Failed to decode a file.
    FileDecode {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Path to the file.
        path: Option<PathBuf>,
    },
    /// Failed to read a file.
    FileRead {
        /// Underlying error.
        error: io::Error,
        /// Path to the file.
        path: Option<PathBuf>,
    },
    /// Failed to decode the index file.
    IndexDecode(Box<dyn StdError + Send + Sync>),
    /// Invalid base64 encoding.
    InvalidBase64 {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Context in which the base64 was being parsed.
        context: &'static str,
    },
    /// The end-entity certificate was invalid and could not be parsed.
    InvalidEndEntityCertificate(Box<dyn StdError + Send + Sync>),
    /// An intermediate certificate was invalid and could not be parsed.
    InvalidIntermediateCertificate {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Index of the intermediate certificate in the provided chain.
        index: usize,
    },
    /// A base64-decoded value did not have the expected length.
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
        /// Context in which the hash was being parsed.
        context: &'static str,
    },
    /// No ':' found in [`CtTimestamp`] string representation.
    InvalidSctEncoding,
    /// An SCT in the end-entity certificate could not be parsed.
    InvalidSctInCertificate(Box<dyn StdError + Send + Sync>),
    /// A timestamp could not be parsed.
    InvalidTimestamp {
        /// Input value that failed to parse as a timestamp.
        input: String,
        /// Context in which the timestamp was being parsed.
        context: &'static str,
    },
    /// No revocation data is present in the cache.
    ///
    /// This happens before revocation data is fetched for the first time.
    /// In contrast, other errors like [`Error::FileRead`] mean the cache
    /// is present but damaged or incomplete.
    NoData {
        /// Path to the index file that was not found.
        path: PathBuf,
    },
    /// No issuer found for the end-entity certificate in the provided chain.
    NoIssuer,
    /// Certificate chains must contain at least 2 certificates.
    TooFewCertificates,
    /// A public key presented to [`check_spki_denylist()`] is compromised.
    CompromisedKey(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileDecode { path, .. } => match path {
                Some(path) => write!(f, "cannot decode file {path:?}"),
                None => write!(f, "cannot decode file"),
            },
            Self::FileRead { path, .. } => match path {
                Some(path) => write!(f, "cannot read file {path:?}"),
                None => write!(f, "cannot read file"),
            },
            Self::IndexDecode(_) => write!(f, "cannot decode index file"),
            Self::InvalidBase64 { context, .. } => {
                write!(f, "invalid base64 for {context}")
            }
            Self::InvalidEndEntityCertificate(_) => {
                write!(f, "invalid end-entity certificate")
            }
            Self::InvalidIntermediateCertificate { index, .. } => {
                write!(f, "invalid intermediate certificate at index {index}")
            }
            Self::InvalidLength {
                expected,
                actual,
                context,
            } => write!(
                f,
                "invalid length for {context}: expected {expected}, got {actual}"
            ),
            Self::InvalidSctEncoding => write!(f, "invalid SCT encoding: no ':' found"),
            Self::InvalidSctInCertificate(_) => {
                write!(f, "invalid SCT in certificate")
            }
            Self::InvalidTimestamp { input, context } => {
                write!(f, "invalid timestamp for {context}: '{input}'")
            }
            Self::NoData { path } => write!(f, "no revocation data found at {path:?}"),
            Self::NoIssuer => write!(f, "no issuer found for end-entity certificate"),
            Self::TooFewCertificates => {
                write!(f, "certificate chain must contain at least 2 certificates")
            }
            Self::CompromisedKey(why) => {
                write!(f, "certificate has a compromised key ({why})")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::FileDecode { error, .. } => Some(&**error),
            Self::FileRead { error, .. } => Some(error),
            Self::IndexDecode(error) => Some(&**error),
            Self::InvalidBase64 { error, .. } => Some(&**error),
            Self::InvalidEndEntityCertificate(error) => Some(&**error),
            Self::InvalidIntermediateCertificate { error, .. } => Some(&**error),
            Self::InvalidLength { .. } => None,
            Self::InvalidSctEncoding => None,
            Self::InvalidSctInCertificate(error) => Some(&**error),
            Self::InvalidTimestamp { .. } => None,
            Self::NoData { .. } => None,
            Self::NoIssuer => None,
            Self::TooFewCertificates => None,
            Self::CompromisedKey(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spki_denylist() {
        let fixtures: &[(&[u8], &str)] = &[
            (
                include_bytes!("data/EMDVTLSCAG3B.spki.der"),
                "the private key is 156",
            ),
            (
                include_bytes!("data/EMDVTLSCAG3C.spki.der"),
                "the private key is 230",
            ),
            (
                include_bytes!("data/EMEVTLSCAG3B.spki.der"),
                "the private key is 115",
            ),
            (
                include_bytes!("data/EMEVTLSCAG3C.spki.der"),
                "the private key is 56",
            ),
            (
                include_bytes!("data/EMOVTLSCAG3B.spki.der"),
                "the private key is 155",
            ),
            (
                include_bytes!("data/EMOVTLSCAG3C.spki.der"),
                "the private key is 4",
            ),
            (
                include_bytes!("data/EMOVCSCAG3B.spki.der"),
                "the private key is 66",
            ),
            (
                include_bytes!("data/EMOVCSCAG3C.spki.der"),
                "the private key is 237",
            ),
        ];
        assert_eq!(fixtures.len(), SPKI_DENYLIST.len());
        for ((der, expected_reason), (expected_hash, _)) in fixtures.iter().zip(SPKI_DENYLIST) {
            assert_eq!(sha256::Digest::from(&[*der][..]).0, *expected_hash);
            assert!(matches!(
                check_spki_denylist(&SubjectPublicKeyInfoDer::from(*der)),
                Err(Error::CompromisedKey(reason)) if reason == *expected_reason
            ));
        }
        assert!(check_spki_denylist(&SubjectPublicKeyInfoDer::from(&[0, 1, 2][..])).is_ok());
    }
}
