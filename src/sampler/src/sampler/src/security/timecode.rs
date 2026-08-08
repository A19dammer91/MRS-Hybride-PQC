use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

// Definieer het HMAC type met SHA-256
type HmacSha256 = Hmac<Sha256>;

/// Struct die een veilige forward-secret tijdscode vasthoudt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TimeCode {
    pub value: [u8; 32],
}

/// Genereert een eenrichtings-tijdscode via code(t) = HMAC-SHA256(X_0, t)
/// Dit garandeert forward secrecy en voorkomt het terugrekenen van codes
pub fn generate_timecode(secret_anchor: &[u8], timestamp: u64) -> Result<TimeCode, &'static str> {
    let mut mac = HmacSha256::new_from_slice(secret_anchor)
        .map_err(|_| "Fout bij initialiseren van HMAC sleutel")?;
    
    // Zet de timestamp om naar bytes voor hashing
    mac.update(&timestamp.to_be_bytes());
    
    let result = mac.finalize();
    let mut code_bytes = [0u8; 32];
    code_bytes.copy_from_slice(&result.into_bytes());
    
    Ok(TimeCode { value: code_bytes })
}
