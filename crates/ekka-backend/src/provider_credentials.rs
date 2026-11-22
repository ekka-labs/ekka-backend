//! Local-only provider secret transport. Never serialized or written to a record.
//! Parsing happens after the ordinary signed authorization was verified.
use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

use crate::answer::Code;

pub const HEADER: &str = "x-ekka-provider-credentials";

/// Its Debug intentionally reveals neither names nor values. No Serialize impl.
#[derive(Default)]
pub struct Material(BTreeMap<String, Zeroizing<String>>);

impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderCredentials([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for Material {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Material;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a provider credential object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Material, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    let value = Zeroizing::new(value);
                    if !key_name(&key)
                        || out.len() >= 8
                        || out.contains_key(&key)
                        || value.is_empty()
                        || !value.bytes().all(|b| b.is_ascii_graphic())
                    {
                        return Err(serde::de::Error::custom(
                            "invalid provider credential material",
                        ));
                    }
                    out.insert(key, value);
                }
                Ok(Material(out))
            }
        }
        d.deserialize_map(Fields)
    }
}

pub fn key_name(key: &str) -> bool {
    let mut b = key.bytes();
    (1..=128).contains(&key.len())
        && b.next()
            .is_some_and(|x| x.is_ascii_alphabetic() || x == b'_')
        && b.all(|x| x.is_ascii_alphanumeric() || x == b'_')
}

impl Material {
    pub fn parse(header: Option<&str>) -> Result<Self, Code> {
        let h = header
            .filter(|h| !h.is_empty() && h.len() <= 16_384)
            .ok_or(Code::CredentialMissing)?;
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(h)
                .map_err(|_| Code::RequestInvalid)?,
        );
        if bytes.len() > 8192 {
            return Err(Code::RequestInvalid);
        }
        serde_json::from_slice(&bytes).map_err(|_| Code::RequestInvalid)
    }

    /// The transport carries exactly the credentials pinned in the body.
    pub fn matches(&self, refs: &BTreeMap<String, String>) -> bool {
        self.0.keys().eq(refs.keys())
    }

    /// Only the gateway write may turn values into its required proto map.
    pub fn for_gateway(&self) -> std::collections::HashMap<String, String> {
        self.0
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encoded(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }
    #[test]
    fn material_has_redacted_debug_and_exact_keys() {
        let m = Material::parse(Some(&encoded(r#"{"api_key":"PLANTED_SECRET"}"#))).unwrap();
        assert!(!format!("{m:?}").contains("PLANTED_SECRET"));
        assert!(m.matches(&BTreeMap::from([("api_key".into(), "uuid".into())])));
        assert!(!m.matches(&BTreeMap::new()));
    }
    #[test]
    fn malformed_or_ambiguous_material_is_refused() {
        for s in [
            r#"{"api_key":"one","api_key":"two"}"#,
            r#"{"api_key":""}"#,
            r#"{"api_key":"two\nlines"}"#,
            r#"{"api_key":123}"#,
            r#"[]"#,
            r#"{"bad-key":"value"}"#,
            r#"{"api_key":"two words"}"#,
        ] {
            assert!(Material::parse(Some(&encoded(s))).is_err());
        }
        assert!(Material::parse(None).is_err());
        assert!(Material::parse(Some("!!!")).is_err());
        assert!(Material::parse(Some(&encoded(&"x".repeat(8193)))).is_err());
    }
    #[test]
    fn keyless_material_is_explicit() {
        let m = Material::parse(Some("e30=")).unwrap();
        assert!(m.matches(&BTreeMap::new()));
    }
}
