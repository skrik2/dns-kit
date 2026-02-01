use std::fmt;

/// We have 14 bits for the compression pointer
const MAX_COMPRESSION_OFFSET: u16 = 2 << 13;

/// Maximum number of octets in a domain name
const MAX_DOMAIN_NAME_WIRE_OCTETS: u8 = 255;

/// Maximum number of compression pointers in a semantically valid message
/// Each label in a domain name must be at least one octet and is separated by a period.
/// The root label won't be represented by a compression pointer to a compression pointer,
/// hence the -2 to exclude the smallest valid root label.
const MAX_COMPRESSION_POINTERS: u8 =
    (MAX_DOMAIN_NAME_WIRE_OCTETS + 1) / 2 - 2;

/// Maximum length of a domain name in presentation format
/// The maximum wire length of a domain name is 255 octets, with the maximum label length being 63.
/// The wire format requires one extra byte over the presentation format, reducing the number of octets by 1.
/// Each label in the name will be separated by a single period, with each octet in the label expanding to at most 4 bytes (\DDD).
/// If all other labels are of the maximum length, then the final label can only be 61 octets long
/// to not exceed the maximum allowed wire length.
const MAX_DOMAIN_NAME_PRESENTATION_LENGTH: usize = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1;

/// DNS Error
#[derive(Debug)]
pub enum Error {
    BadAlgorithm,
    BadAuthentication,
    BufferTooSmall,
    ConnEmpty,
    BadExtendedRcode,
    NotFqdn,
    IdMismatch,
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
    BadSignature,
    NoSoa,
    BadTime,
}

impl std::error::Error for DnsError {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DnsError::*;
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
            LongDomain => &format!("domain name exceeded {} wire-format octets", MAX_DOMAIN_NAME_WIRE_OCTETS),
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

