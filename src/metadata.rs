//! Shared framing and size limits for non-secret UI metadata.
use serde_json::Value;
use std::io::{self, Read, Write};

pub const MAX_METADATA: usize = 65536;

pub fn encode(value: &Value) -> io::Result<Vec<u8>> {
    let data = serde_json::to_vec(value)?;
    if data.len() > MAX_METADATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UI request too large",
        ));
    }
    Ok(data)
}

pub fn write(output: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_METADATA {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    output.write_all(&(data.len() as u32).to_be_bytes())?;
    output.write_all(data)
}

pub fn read(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    input.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_METADATA {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut data = vec![0; length];
    input.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_limit_round_trips_and_escaped_expansion_is_bounded() {
        let overhead = encode(&json!({"desc": ""})).unwrap().len();
        let data = encode(&json!({"desc": "x".repeat(MAX_METADATA - overhead)})).unwrap();
        assert_eq!(data.len(), MAX_METADATA);
        let mut frame = Vec::new();
        write(&mut frame, &data).unwrap();
        assert_eq!(read(&mut frame.as_slice()).unwrap(), data);
        assert!(encode(&json!({"desc": "x".repeat(MAX_METADATA - overhead + 1)})).is_err());
        assert!(encode(&json!({"desc": "\0".repeat(MAX_METADATA / 2)})).is_err());
    }

    #[test]
    fn incomplete_and_oversized_frames_are_rejected() {
        for frame in [
            vec![0, 0],
            vec![0, 0, 0, 3, b'{', b'}'],
            vec![0; 4],
            ((MAX_METADATA + 1) as u32).to_be_bytes().to_vec(),
        ] {
            assert!(read(&mut frame.as_slice()).is_err());
        }
    }
}
