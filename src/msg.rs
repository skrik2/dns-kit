/// We have 14 bits for the compression pointer
pub(crate) const MAX_COMPRESSION_OFFSET: u16 = 2 << 13;

/// Maximum number of octets in a domain name
pub(crate) const MAX_DOMAIN_NAME_WIRE_OCTETS: u8 = 255;

/// Maximum number of compression pointers in a semantically valid message
/// Each label in a domain name must be at least one octet and is separated by a period.
/// The root label won't be represented by a compression pointer to a compression pointer,
/// hence the -2 to exclude the smallest valid root label.
pub(crate) const MAX_COMPRESSION_POINTERS: u8 = ((MAX_DOMAIN_NAME_WIRE_OCTETS as u16 + 1) / 2 - 2) as u8;

/// Maximum length of a domain name in presentation format
/// The maximum wire length of a domain name is 255 octets, with the maximum label length being 63.
/// The wire format requires one extra byte over the presentation format, reducing the number of octets by 1.
/// Each label in the name will be separated by a single period, with each octet in the label expanding to at most 4 bytes (\DDD).
/// If all other labels are of the maximum length, then the final label can only be 61 octets long
/// to not exceed the maximum allowed wire length.
pub(crate) const MAX_DOMAIN_NAME_PRESENTATION_LENGTH: usize =
    61 * 4 + 1 + 63 * 4 + 1 + 63 * 4 + 1 + 63 * 4 + 1;