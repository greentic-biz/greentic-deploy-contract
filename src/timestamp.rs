//! Timestamp handling for the wire types.
//!
//! Every timestamp on this seam is `Option<DateTime<Utc>>` and every one of
//! them degrades a value it cannot parse to `None`. The admin stores these
//! columns as text, so a malformed row is possible; one bad row must not fail
//! the whole listing.

use chrono::{DateTime, Utc};

/// Parse an RFC-3339 timestamp, yielding `None` for absent or unparseable input.
pub fn parse_lenient(raw: Option<&str>) -> Option<DateTime<Utc>> {
    raw.and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

/// `#[serde(with = "crate::timestamp::opt_rfc3339")]` for `Option<DateTime<Utc>>`.
pub mod opt_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(dt) => s.serialize_str(&dt.to_rfc3339()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize to `Option<String>` first: an unparseable timestamp must
        // not be an error, so the parse happens after the value is safely in
        // hand rather than inside chrono's own Deserialize.
        let raw = Option::<String>::deserialize(d)?;
        Ok(super::parse_lenient(raw.as_deref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Holder {
        #[serde(with = "opt_rfc3339")]
        at: Option<DateTime<Utc>>,
    }

    #[test]
    fn parses_rfc3339() {
        let h: Holder = serde_json::from_str(r#"{"at":"2026-07-30T10:00:00+00:00"}"#).unwrap();
        assert_eq!(h.at.unwrap().to_rfc3339(), "2026-07-30T10:00:00+00:00");
    }

    #[test]
    fn null_is_none() {
        let h: Holder = serde_json::from_str(r#"{"at":null}"#).unwrap();
        assert_eq!(h.at, None);
    }

    /// One unparseable stored value must not turn the environment listing into
    /// a 500. This mirrors the designer's own `EnvSummaryDto.updated_at`, which
    /// is `Option` for exactly this reason and renders `None` as an em dash.
    #[test]
    fn garbage_degrades_to_none_rather_than_erroring() {
        let h: Holder = serde_json::from_str(r#"{"at":"not a timestamp"}"#).unwrap();
        assert_eq!(h.at, None);

        // A bare second-count is the specific bug this closes: it is a valid
        // JSON value and a plausible-looking timestamp, and it is not one.
        let h: Holder = serde_json::from_str(r#"{"at":"1785488794"}"#).unwrap();
        assert_eq!(h.at, None);
    }

    #[test]
    fn serializes_as_rfc3339() {
        let h = Holder {
            at: Some(
                DateTime::parse_from_rfc3339("2026-07-30T10:00:00+00:00")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        };
        assert_eq!(
            serde_json::to_string(&h).unwrap(),
            r#"{"at":"2026-07-30T10:00:00+00:00"}"#
        );
    }

    #[test]
    fn none_serializes_as_null() {
        assert_eq!(
            serde_json::to_string(&Holder { at: None }).unwrap(),
            r#"{"at":null}"#
        );
    }

    #[test]
    fn parse_lenient_matches_the_serde_behaviour() {
        assert!(parse_lenient(Some("2026-07-30T10:00:00+00:00")).is_some());
        assert!(parse_lenient(Some("nonsense")).is_none());
        assert!(parse_lenient(None).is_none());
    }
}
