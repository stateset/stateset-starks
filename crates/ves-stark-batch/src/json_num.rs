use serde::de::{self, Deserializer};
use serde::ser::{SerializeSeq, Serializer};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrU64 {
    String(String),
    Number(u64),
}

fn parse_u64<E>(value: StringOrU64) -> Result<u64, E>
where
    E: de::Error,
{
    match value {
        StringOrU64::String(value) => value.parse::<u64>().map_err(E::custom),
        StringOrU64::Number(value) => Ok(value),
    }
}

fn serialize_u64_as_string<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_u64_from_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    parse_u64(StringOrU64::deserialize(deserializer)?)
}

fn serialize_u64_array_as_strings<S, const N: usize>(
    values: &[u64; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(N))?;
    for value in values {
        seq.serialize_element(&value.to_string())?;
    }
    seq.end()
}

fn deserialize_u64_array_from_strings<'de, D, const N: usize>(
    deserializer: D,
) -> Result<[u64; N], D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<StringOrU64>::deserialize(deserializer)?;
    if raw.len() != N {
        return Err(de::Error::custom(format!(
            "expected {N} elements, got {}",
            raw.len()
        )));
    }

    let mut values = [0u64; N];
    for (slot, value) in values.iter_mut().zip(raw) {
        *slot = parse_u64(value)?;
    }

    Ok(values)
}

pub mod u64_string {
    use super::{deserialize_u64_from_string, serialize_u64_as_string};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_u64_as_string(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_u64_from_string(deserializer)
    }
}

pub mod usize_string {
    use super::{deserialize_u64_from_string, serialize_u64_as_string};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &usize, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_u64_as_string(&(*value as u64), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<usize, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserialize_u64_from_string(deserializer)?;
        usize::try_from(value).map_err(serde::de::Error::custom)
    }
}

pub mod u64_array_4_strings {
    use super::{deserialize_u64_array_from_strings, serialize_u64_array_as_strings};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[u64; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_u64_array_as_strings(values, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u64; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_u64_array_from_strings(deserializer)
    }
}

pub mod u64_array_8_strings {
    use super::{deserialize_u64_array_from_strings, serialize_u64_array_as_strings};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[u64; 8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_u64_array_as_strings(values, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u64; 8], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_u64_array_from_strings(deserializer)
    }
}
