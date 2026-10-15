//! Human-friendly duration parsing for the YAML configuration.
//!
//! TTLs are written as a number with an optional unit suffix, e.g. `30s`,
//! `15m`, `8h`, `7d`. A bare number is interpreted as seconds.

use serde::{Deserialize, Deserializer, de::Error as _};
use std::time::Duration;

/// Error message reused for every invalid duration value.
pub(crate) fn duration_hint(value: &str) -> String {
    format!(
        "invalid duration '{value}': use a number with an optional unit suffix \
         (s = seconds, m = minutes, h = hours, d = days), for example 30s, 15m, 8h or 7d"
    )
}

/// Parses a duration string such as `15m` into [`Duration`].
pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(duration_hint(value));
    }

    let last = trimmed.chars().last().expect("trimmed is not empty");
    let (number, multiplier) = match last {
        's' | 'S' => (&trimmed[..trimmed.len() - 1], 1_u64),
        'm' | 'M' => (&trimmed[..trimmed.len() - 1], 60),
        'h' | 'H' => (&trimmed[..trimmed.len() - 1], 3_600),
        'd' | 'D' => (&trimmed[..trimmed.len() - 1], 86_400),
        c if c.is_ascii_digit() => (trimmed, 1_u64),
        _ => return Err(duration_hint(value)),
    };

    let number: u64 = number.trim().parse().map_err(|_| duration_hint(value))?;
    number
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| duration_hint(value))
}

/// Serde deserializer for duration fields written as strings.
pub(crate) fn de_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_duration(&value).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("8h").unwrap(), Duration::from_secs(28_800));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration(" 5s ").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("2H").unwrap(), Duration::from_secs(7_200));
    }

    #[test]
    fn rejects_garbage_with_hint() {
        for bad in ["", "abc", "15x", "1.5m", "-5s", "m"] {
            let err = parse_duration(bad).unwrap_err();
            assert!(err.contains("invalid duration"), "unexpected error: {err}");
            assert!(err.contains("30s"), "hint missing in: {err}");
        }
    }

    #[test]
    fn deserializes_from_yaml() {
        #[derive(serde::Deserialize)]
        struct Ttl {
            #[serde(default, deserialize_with = "de_duration")]
            ttl: Duration,
        }
        let parsed: Ttl = serde_yaml_ng::from_str("ttl: 10m").unwrap();
        assert_eq!(parsed.ttl, Duration::from_secs(600));
    }
}
