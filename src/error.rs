pub type Result<T> = std::result::Result<T, Error>;

/// dns-kit Error defined
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// There is no more work to do.
    Done,
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            Done => write!(f, "done"),
            BadAlgorithm => write!(f, "bad algorithm"),
            BadAuthentication => write!(f, "bad authentication"),
            BufferTooSmall => write!(f, "buffer size too small"),
            ConnEmpty => write!(f, "conn has no connection"),
            BadExtendedRcode => write!(f, "bad extended rcode"),
            NotFqdn => write!(f, "domain must be fully qualified"),
            IdMismatch => write!(f, "id mismatch"),
            BadKeyAlgorithm => write!(f, "bad key algorithm"),
            BadKey => write!(f, "bad key"),
            BadKeySize => write!(f, "bad key size"),
            LongDomain => write!(
                f,
                "domain name exceeded {} wire-format octets",
                crate::msg::MAX_DOMAIN_NAME_WIRE_OCTETS
            ),
            NoSignature => write!(f, "no signature found"),
            BadPrivateKey => write!(f, "bad private key"),
            BadRcode => write!(f, "bad rcode"),
            BadRdata => write!(f, "bad rdata"),
            BadRrset => write!(f, "bad rrset"),
            NoSecrets => write!(f, "no secrets defined"),
            ShortRead => write!(f, "short read"),
            BadSignature => write!(f, "bad signature"),
            NoSoa => write!(f, "no SOA"),
            BadTime => write!(f, "bad time"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}