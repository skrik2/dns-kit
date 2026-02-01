use std::fmt;

// internal
use crate::msg;

/// Error defined
#[derive(Debug)]
pub enum Error {
    /// BadAlgorithm indicates an error with the (DNSSEC) algorithm.
    BadAlgorithm,
    /// BadAuthentication indicates an error in the TSIG authentication.
    BadAuthentication,
    /// BufferToolSmall indicates that the buffer used is too small for the message.
    BufferTooSmall,
    /// ConnEmpty indicates a connection is being used before it is initialized.
    ConnEmpty,
    /// BadExtendedRcode ...
    BadExtendedRcode,
    /// NotFqdn indicates that a domain name does not have a closing dot.
    NotFqdn,
    /// IdMismatch indicates there is a mismatch with the message's ID.
    IdMismatch,
    /// BadKeyAlgorithm indicates that the algorithm in the key is not valid.
    BadKeyAlgorithm,
    BadKey,
    BadKeySize,
    LongDomain,
    NoSignature,
    BadPrivateKey,
    BadRcode,
    BadRdata,
    BadRrset,
    NoSecrets,
    ShortRead,
    /// BadSignature indicates that a signature can not be cryptographically validated.
    BadSignature,
    /// NoSOA indicates that no SOA RR was seen when doing zone transfers.
    NoSoa,
    /// BadTime indicates a timing error in TSIG authentication.
    BadTime,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        let msg = match self {
            BadAlgorithm => "bad algorithm",
            BadAuthentication => "bad authentication",
            BufferTooSmall => "buffer size too small",
            ConnEmpty => "conn has no connection",
            BadExtendedRcode => "bad extended rcode",
            NotFqdn => "domain must be fully qualified",
            IdMismatch => "id mismatch",
            BadKeyAlgorithm => "bad key algorithm",
            BadKey => "bad key",
            BadKeySize => "bad key size",
            LongDomain => &format!(
                "domain name exceeded {} wire-format octets",
                msg::MAX_DOMAIN_NAME_WIRE_OCTETS
            ),
            NoSignature => "no signature found",
            BadPrivateKey => "bad private key",
            BadRcode => "bad rcode",
            BadRdata => "bad rdata",
            BadRrset => "bad rrset",
            NoSecrets => "no secrets defined",
            ShortRead => "short read",
            BadSignature => "bad signature",
            NoSoa => "no SOA",
            BadTime => "bad time",
        };
        write!(f, "{}", msg)
    }
}
