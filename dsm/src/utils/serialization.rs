use crate::utils::file::read_file;
use crate::utils::file::write_file;
/// Serialization utilities
///
///  Contains helper functions for serializing and deserializing data.
///
/// # Example
///
/// ```rust
/// use dsm::utils::serialization;
///
/// let data = vec![1, 2, 3, 4, 5];
///
/// // Serialize data to a file
/// serialization::serialize("data.bin", &data).unwrap();
///
/// // Deserialize data from a file
/// let deserialized_data: Vec<u8> = serialization::deserialize("data.bin").unwrap();
/// ```
use std::io;
/// Serializes data to a file.
pub fn serialize<T>(path: &str, data: &T) -> io::Result<()>
where
    T: serde::Serialize,
{
    let serialized = serde_json::to_string(data)?;
    write_file(path, serialized.as_bytes())
}

/// Deserializes data from a file.
pub fn deserialize<T>(path: &str) -> io::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let data = read_file(path)?;
    let deserialized: T = serde_json::from_slice(&data)?;
    Ok(deserialized)
}
