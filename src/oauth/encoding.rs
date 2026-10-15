//! Minimal `application/x-www-form-urlencoded` helpers.
//!
//! Used to build the query string of authorization redirects and to decode the
//! credentials of an HTTP Basic `Authorization` header (RFC 6749 section 2.3.1
//! requires them to be form-urlencoded before Base64). Keeping this local avoids
//! a dependency for two small functions.

/// Percent-encodes `value` with the unreserved set from RFC 3986
/// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`); spaces become `%20`.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0x0f));
            }
        }
    }
    out
}

/// Decodes a form-urlencoded component: `%XX` escapes and `+` as space.
///
/// Invalid escapes are left untouched so a malformed header never panics.
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match (from_hex(bytes[index + 1]), from_hex(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Builds `key=value&...` with every component percent-encoded.
pub fn encode_query<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(percent_encode("my app"), "my%20app");
        assert_eq!(
            percent_encode("http://localhost:3000/cb?a=b"),
            "http%3A%2F%2Flocalhost%3A3000%2Fcb%3Fa%3Db"
        );
        assert_eq!(percent_encode("aA0-._~"), "aA0-._~");
    }

    #[test]
    fn decodes_escapes_and_plus() {
        assert_eq!(percent_decode("my%20app"), "my app");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn roundtrip() {
        let original = "secret with spaces & symbols:/?=";
        assert_eq!(percent_decode(&percent_encode(original)), original);
    }

    #[test]
    fn query_is_joined_with_ampersands() {
        assert_eq!(
            encode_query([("code", "a b"), ("state", "x&y")]),
            "code=a%20b&state=x%26y"
        );
    }
}
