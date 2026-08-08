use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TimeCode {
    pub value: [u8; 32],
}

pub fn generate_timecode(secret_anchor: &[u8], timestamp: u64) -> Result<TimeCode, &'static str> {
    // Hier dwingen we expliciet hmac::Mac af om verwarring met aes-gcm te voorkomen
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret_anchor)
        .map_err(|_| "Fout bij initialiseren van HMAC sleutel")?;
    
    mac.update(&timestamp.to_be_bytes());
    
    let result = mac.finalize();
    let mut code_bytes = [0u8; 32];
    code_bytes.copy_from_slice(&result.into_bytes());
    
    Ok(TimeCode { value: code_bytes })
}

