use sha2::Sha256;
use zeroize::Zeroize;
use hmac::Mac;

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TimeCode {
    pub value: [u8; 32],
}

pub fn generate_timecode(secret_anchor: &[u8], timestamp: u64) -> Result<TimeCode, &'static str> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret_anchor)
        .map_err(|_| "Error initializing HMAC key")?;

    mac.update(&timestamp.to_be_bytes());

    let result = mac.finalize();
    let mut code_bytes = [0u8; 32];
    code_bytes.copy_from_slice(&result.into_bytes());

    Ok(TimeCode { value: code_bytes })
}
// ============================================================================
// Formal Security Games (EUF-CMA & Forward Secrecy Simulations)
// ============================================================================

use std::collections::HashSet;

/// Simulated Adversary for the EUF-CMA forgery game.
pub trait EufCmaAdversary {
    /// The attacker attempts to forge a timecode for a timestamp they haven't queried.
    fn attack(&self, sign_oracle: &dyn Fn(u64) -> [u8; 32]) -> (u64, [u8; 32]);
}

/// EUF-CMA Forgery Security Game (Deel III uit EasyCrypt).
pub fn run_euf_cma_game(adversary: &dyn EufCmaAdversary, secret_anchor: &[u8]) -> bool {
    let mut queried_timestamps = HashSet::new();

    let sign_oracle = |t: u64| -> [u8; 32] {
        queried_timestamps.insert(t);
        generate_timecode(secret_anchor, t).unwrap().value
    };

    let (t_star, sig_star) = adversary.attack(&sign_oracle);

    if queried_timestamps.contains(&t_star) {
        return false; 
    }

    if let Ok(real_code) = generate_timecode(secret_anchor, t_star) {
        sig_star == real_code.value
    } else {
        false
    }
}

/// Simulated Adversary for the Forward Secrecy challenge.
pub trait ForwardSecrecyAdversary {
    fn choose(&self, current_code: &[u8; 32], current_t: u64) -> u64;
    fn guess(&self, challenge: &[u8; 32]) -> bool;
}

/// Forward Secrecy Security Game (Deel IV uit EasyCrypt).
pub fn run_forward_secrecy_game(
    adversary: &dyn ForwardSecrecyAdversary, 
    secret_anchor: &[u8], 
    current_t: u64,
    rng: &mut impl rand::RngCore
) -> bool {
    let current_code = generate_timecode(secret_anchor, current_t).unwrap().value;
    let t_prime = adversary.choose(&current_code, current_t);
    
    if t_prime >= current_t {
        return false; 
    }

    let b_choice = (rng.next_u32() % 2) == 1; 
    let mut challenge = [0u8; 32];
    
    if b_choice {
        rng.fill_bytes(&mut challenge);
    } else {
        challenge = generate_timecode(secret_anchor, t_prime).unwrap().value;
    }

    let b_prime = adversary.guess(&challenge);
    b_prime == b_choice
}
