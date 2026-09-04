# Research Note: 90/366 Witness Authentication, Draft Code

Status: draft, not compiled, not tested, not part of the crate.

This file preserves the witness and authentication code from the 90/366/2520 research idea (see 90-366-2520-transformation.md for the background, and sampler-90-366.md for the sampler this code calls into).

## What this code adds on top of the sampler

The sampler produces witness chains with a forced digital root. This file wraps that into a full authentication flow: deriving a master secret, generating a witness tied to an identity and a point in time, verifying it later, and generating an alibi.

The central addition here is a time window: a witness is only considered valid within 366 seconds of when it was created.

## The witness type

```rust
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    pub chain: MrsChain,
    pub binding_tag: [u8; 32],
    pub session_id: Vec<u8>,
    pub timestamp: u64,
    pub transform_level: TransformLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alibi(pub Witness);

#[derive(Debug, Clone)]
pub struct WitnessSpace {
    pub root_n: u64,
    pub depth: usize,
    pub temporal_window: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessStatus {
    ValidButUnbound,
    Authentic,
    Invalid,
    BindingMismatch,
    Expired,
}
```

WitnessStatus adds an Expired variant alongside the existing statuses, for witnesses presented outside their temporal window.

## Generating a witness tied to a point in time

```rust
impl MasterSecret {
    pub fn generate_temporal_witness(
        &self,
        space: &WitnessSpace,
        identity: &[u8],
        timestamp: u64,
    ) -> Option<Witness> {
        for attempt in 0u32..512 {
            let seed = Self::derive_seed(
                self.key_bytes(),
                identity,
                &timestamp.to_be_bytes(),
                attempt,
            );
            let mut rng = DeterministicRng::from_seed(seed);

            let chain = if let Some(window) = space.temporal_window {
                let root_n = (timestamp / MICRO_ANCHOR) * MICRO_ANCHOR;
                sample_three_layers_safe(root_n, &mut rng)?
            } else {
                sample_three_layers_safe(space.root_n, &mut rng)?
            };

            let chain_hash = hash_chain(&chain);
            let binding_tag = Self::compute_temporal_binding_tag(
                self.key_bytes(),
                identity,
                timestamp,
                &chain_hash,
            );

            if space.verify_membership_raw(&chain) == WitnessStatus::ValidButUnbound {
                return Some(Witness {
                    chain,
                    binding_tag,
                    session_id: timestamp.to_be_bytes().to_vec(),
                    timestamp,
                    transform_level: TransformLevel::TemporalAnchor,
                });
            }
        }
        None
    }
}
```

The root number is derived from which 366 second window the timestamp falls into, and the chain is bound to the identity and timestamp through an HMAC tag.

## Checking whether a witness has expired

```rust
impl MasterSecret {
    pub fn verify_temporal_authenticity(
        &self,
        witness: &Witness,
        identity: &[u8],
        current_timestamp: u64,
    ) -> WitnessStatus {
        if witness.timestamp > 0 {
            let max_window = witness.timestamp.saturating_add(MICRO_ANCHOR);
            if current_timestamp > max_window {
                return WitnessStatus::Expired;
            }
        }

        let chain_hash = hash_chain(&witness.chain);
        let expected_tag = Self::compute_temporal_binding_tag(
            self.key_bytes(),
            identity,
            witness.timestamp,
            &chain_hash,
        );
        let tags_match = expected_tag.ct_eq(&witness.binding_tag);
        if tags_match.unwrap_u8() == 1 {
            WitnessStatus::Authentic
        } else {
            WitnessStatus::BindingMismatch
        }
    }
}
```

## Generating an alibi for a temporal witness

```rust
impl WitnessSpace {
    pub fn generate_alternative_witness(
        &self,
        authentic: &Witness,
        rng: &mut impl RngCore,
    ) -> Option<Alibi> {
        for _attempt in 0..512 {
            let root_n = if authentic.timestamp > 0 {
                (authentic.timestamp / MICRO_ANCHOR) * MICRO_ANCHOR
            } else {
                self.root_n
            };

            if let Some(chain) = sample_three_layers_safe(root_n, rng) {
                let same = chains_equal_ct(&chain, &authentic.chain);
                if same.unwrap_u8() == 0
                    && self.verify_membership_raw(&chain) == WitnessStatus::ValidButUnbound
                {
                    let mut alibi_tag = [0u8; 32];
                    rng.fill_bytes(&mut alibi_tag);

                    return Some(Alibi(Witness {
                        chain,
                        binding_tag: alibi_tag,
                        session_id: authentic.session_id.clone(),
                        timestamp: authentic.timestamp,
                        transform_level: authentic.transform_level,
                    }));
                }
            }
            let _ = rng.next_u64();
        }
        None
    }
}
```

The alibi reuses the same time window as the authentic witness it is paired with, so it remains plausible for the same period.

## What the draft's tests establish

Generating a temporal witness succeeds and records the correct timestamp.

Verifying that same witness slightly later, within 366 seconds, reports Authentic.

Verifying it a full period later reports Expired.

An alibi generated for a temporal witness is valid in the witness space, and reports BindingMismatch under identity verification, distinguishing it from an authentic witness only to someone checking the binding tag.

Two witnesses generated for different 366 second periods produce different chains, and each verifies correctly within its own period.

## Relationship to the existing crate

This module defines Witness, MasterSecret, WitnessSpace, WitnessStatus, Alibi, SecretMode, SecretInput, KeyShare, and DeriveError, all of which already exist in security::witness with a different shape (no timestamp or transform_level fields, no Expired status). As a separate module path (security::witness_90 alongside security::witness) this compiles without conflict, distinguished by module location.

This module calls sample_three_layers_safe, MrsChain, and TransformLevel from the sampler draft described in sampler-90-366.md.

The generation functions retry up to 512 times before returning None, matching the retry pattern already used by the existing generate_authentic_witness in the crate.
