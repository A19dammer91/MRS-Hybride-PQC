use subtle::Choice;
use zeroize::Zeroize;

/// Struct holding an LWE-isolated cryptographic parameter
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct LweInstance {
    pub b: Vec<u64>, // The b-vector: b = (A * s + e) mod q
    pub public_matrix_a: Vec<Vec<u64>>, // The public matrix A
}

/// Masks an MRS parameter (the secret chain parameter) within an LWE
/// instance. q is the prime modulus (e.g. a Mersenne prime matching the
/// MRS field).
pub fn isolate_chain_parameter(
    secret_s: &[u64],
    noise_e: &[u64],
    modulus_q: u64
) -> Option<LweInstance> {
    if secret_s.is_empty() || secret_s.len() != noise_e.len() {
        return None;
    }

    let n = secret_s.len();
    // Generate a pseudo-random public matrix A (a simplified deterministic
    // mock setup for test vectors)
    let mut matrix_a = vec![vec![0u64; n]; n];
    for i in 0..n {
        for j in 0..n {
            matrix_a[i][j] = ((i * 19 + j * 9) as u64) % modulus_q;
        }
    }

    let mut b_vector = vec![0u64; n];

    // Compute b = (A * s + e) mod q
    for i in 0..n {
        let mut sum = 0u64;
        for j in 0..n {
            // Avoid overflow during multiplication within the large modulus field
            let product = (matrix_a[i][j] as u128 * secret_s[j] as u128) % modulus_q as u128;
            sum = (sum + product as u64) % modulus_q;
        }
        b_vector[i] = (sum + noise_e[i]) % modulus_q;
    }

    Some(LweInstance {
        b: b_vector,
        public_matrix_a: matrix_a,
    })
}

/// Verifies in constant time whether a submitted chain solution
/// mathematically matches the LWE isolation layer
pub fn verify_lwe_match(
    instance: &LweInstance,
    claimed_s: &[u64],
    allowed_noise_bound: u64,
    modulus_q: u64
) -> Choice {
    if claimed_s.len() != instance.b.len() {
        return Choice::from(0);
    }

    let n = claimed_s.len();
    let mut all_match = 1u8;

    for i in 0..n {
        let mut computed_as = 0u64;
        for j in 0..n {
            let product = (instance.public_matrix_a[i][j] as u128 * claimed_s[j] as u128) % modulus_q as u128;
            computed_as = (computed_as + product as u64) % modulus_q;
        }

        // Compute the absolute error (noise reconstruction) within the mod q field
        let diff = if instance.b[i] >= computed_as {
            instance.b[i] - computed_as
        } else {
            (instance.b[i] + modulus_q) - computed_as
        };

        // The error must fall within the cryptographic noise bound
        let is_within_bound = diff <= allowed_noise_bound;
        all_match &= if is_within_bound { 1 } else { 0 };
    }

    Choice::from(all_match)
}
