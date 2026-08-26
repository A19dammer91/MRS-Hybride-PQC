```rust
use sha2::Sha256;
use zeroize::Zeroize;
use hmac::Mac;

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TimeCode {
    pub value: [u8; 32],
}

/// Generates a time-based HMAC-SHA256 authentication code.
///
/// `timestamp` is a Unix epoch in seconds (always u64, regardless of
/// the Diophantine integer width).
pub fn generate_timecode(secret_anchor: &[u8], timestamp: u64) -> Result<TimeCode, &'static str> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret_anchor)
        .map_err(|_| "HMAC key init error")?;
    mac.update(&timestamp.to_be_bytes());
    let result = mac.finalize();
    let mut code_bytes = [0u8; 32];
    code_bytes.copy_from_slice(&result.into_bytes());
    Ok(TimeCode { value: code_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timecode_deterministic() {
        let secret = b"test-anchor";
        let tc1 = generate_timecode(secret, 1_700_000_000).unwrap();
        let tc2 = generate_timecode(secret, 1_700_000_000).unwrap();
        assert_eq!(tc1.value, tc2.value);
    }

    #[test]
    fn timecode_different_timestamps() {
        let secret = b"test-anchor";
        let tc1 = generate_timecode(secret, 1_700_000_000).unwrap();
        let tc2 = generate_timecode(secret, 1_700_000_001).unwrap();
        assert_ne!(tc1.value, tc2.value);
    }
}
```
