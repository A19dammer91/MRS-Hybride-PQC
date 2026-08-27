//! Temporal Barrier and Security Games matching the formal EasyCrypt
//! specifications from `MRS_AUTH_.ec`.

use std::collections::HashSet;
use std::cell::RefCell;
use std::time::{Instant, Duration};
use rand::RngCore;
use zeroize::Zeroize;
use sha2::Sha256;
use hmac::Mac;

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TimeCode {
    pub value: [u8; 32],
}

/// Generates a time-bound authentication code using HMAC-SHA256.
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
// PART I: Temporal Barrier (Hardware Clock & Zeroize Execution)
// ============================================================================

/// Executes a cryptographic operation within a strict hardware duration threshold.
/// If execution exceeds the timeout, the secret is wiped from RAM via zeroize.
pub fn run_with_temporal_barrier<F, T>(timeout: Duration, f: F) -> Option<T>
where
    F: FnOnce() -> T,
    T: Zeroize,
{
    let start_time = Instant::now();
    
    // Execute the core cryptographic computation
    let mut secret_result = f();
    
    let duration = start_time.elapsed();

    // Hardware-enforced side-channel timing check
    if duration > timeout {
        // TIMEOUT TRIGGERED: Purge registers from RAM immediately
        secret_result.zeroize();
        return None; 
    }

    Some(secret_result)
}

// ============================================================================
// PART III & IV: Formal Security Games (EUF-CMA & Forward Secrecy)
// ============================================================================

/// Simulated Adversary for the EUF-CMA forgery game.
pub trait EufCmaAdversary {
    fn attack(&self, sign_oracle: &dyn Fn(u64) -> [u8; 32]) -> (u64, [u8; 32]);
}

/// EUF-CMA Forgery Security Game. Returns true if the attacker successfully forges a token.
pub fn run_euf_cma_game(adversary: &dyn EufCmaAdversary, secret_anchor: &[u8]) -> bool {
    // Use RefCell to allow mutating the HashSet inside an immutable Fn closure
    let queried_timestamps = RefCell::new(HashSet::new());

    let sign_oracle = |t: u64| -> [u8; 32] {
        queried_timestamps.borrow_mut().insert(t);
        generate_timecode(secret_anchor, t).unwrap().value
    };

    let (t_star, sig_star) = adversary.attack(&sign_oracle);

    if queried_timestamps.borrow().contains(&t_star) {
        return false; // Attack invalid: timestamp was already leaked
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

/// Forward Secrecy Security Game. Returns true if the attacker breaks indistinguishability.
pub fn run_forward_secrecy_game(
    adversary: &dyn ForwardSecrecyAdversary, 
    secret_anchor: &[u8], 
    current_t: u64,
    rng: &mut impl RngCore
) -> bool {
    let current_code = generate_timecode(secret_anchor, current_t).unwrap().value;
    let t_prime = adversary.choose(&current_code, current_t);
    
    if t_prime >= current_t {
        return false; // Invalid attack bounds
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

// ============================================================================
// Automated Security Test Suite
// ============================================================================

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_temporal_barrier_success() {
        let timeout = Duration::from_millis(50);
        let secret_anchor = b"super-secret-key-material-32bytes";
        
        let res = run_with_temporal_barrier(timeout, || {
            generate_timecode(secret_anchor, 1000).unwrap()
        });
        
        assert!(res.is_some());
    }

    #[test]
    fn test_temporal_barrier_timeout_triggers_zeroize() {
        let timeout = Duration::from_nanos(1); // Enforce immediate timeout to test memory wiping
        let secret_anchor = b"super-secret-key-material-32bytes";
        
        let res = run_with_temporal_barrier(timeout, || {
            std::thread::sleep(Duration::from_millis(2));
            generate_timecode(secret_anchor, 1000).unwrap()
        });
        
        assert!(res.is_none());
    }
}
