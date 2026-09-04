# Research Note: 90/366 Sampler, Draft Code

Status: draft, not compiled, not tested, not part of the crate.

This file preserves the sampler code from the 90/366/2520 research idea (see 90-366-2520-transformation.md for the background). It is kept here for reference.

## What this code does

Given a witness pair (a, b), it multiplies by 90 to force both numbers to become multiples of 9. This makes their digital root always equal to 9, removing that property as a distinguishing signal.

The code also implements the 2520 supergrid (a larger version of the same transform) and a 366 second time window, so a witness generated in one period is only valid within that period.

## The core constants

```rust
pub const MICRO_ANCHOR: u64 = 366;
pub const ROTATION_FACTOR: u64 = 90;
pub const MACRO_ANCHOR: u64 = 32940;
pub const SUPER_GRID: u64 = 2520;
pub const NINE_MODULUS: u64 = 9;
pub const PERFECT_SIX: u64 = 6;
pub const PERFECT_TWENTYEIGHT: u64 = 28;
```

## The chain type

```rust
#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
    pub transform_level: TransformLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TransformLevel {
    Raw,
    Rotated90,
    SuperGrid,
    TemporalAnchor,
}
```

This chain type carries a public transform_level field alongside the layers, recording which transformation produced it.

## The 90-rotation

```rust
pub fn rotate_90(pair: &DiophantinePair, delta_a: u64, delta_b: u64) -> DiophantinePair {
    let delta_a_9 = delta_a.wrapping_mul(NINE_MODULUS);
    let delta_b_9 = delta_b.wrapping_mul(NINE_MODULUS);

    let a_star = ROTATION_FACTOR
        .wrapping_mul(pair.a)
        .wrapping_add(delta_a_9);

    let b_star = ROTATION_FACTOR
        .wrapping_mul(pair.b)
        .wrapping_sub(19u64.wrapping_mul(delta_a_9))
        .wrapping_add(delta_b_9);

    DiophantinePair { a: a_star, b: b_star }
}

pub fn verify_90_rotation(
    original: &DiophantinePair,
    rotated: &DiophantinePair,
    original_n: u64,
    delta_b: u64,
) -> Choice {
    let expected_n = ROTATION_FACTOR.wrapping_mul(original_n)
        .wrapping_add(81u64.wrapping_mul(delta_b));

    let lhs = 19u64.wrapping_mul(rotated.a)
        .wrapping_add(9u64.wrapping_mul(rotated.b));

    let valid_eq = lhs.ct_eq(&expected_n);
    let valid_a = rotated.a.ct_gt(&0);
    let valid_b = rotated.b.ct_gt(&0);

    valid_eq & valid_a & valid_b
}

#[inline]
pub fn is_nine_homogeneous(n: u64) -> Choice {
    let dr = digital_root(n);
    dr.ct_eq(&9)
}

#[inline]
pub fn pair_is_nine_homogeneous(pair: &DiophantinePair) -> Choice {
    is_nine_homogeneous(pair.a) & is_nine_homogeneous(pair.b)
}
```

## The 366-temporal anchor

```rust
pub fn verify_temporal_anchor(n: u64) -> Choice {
    let is_multiple = n.ct_eq(&(n.wrapping_div(MICRO_ANCHOR).wrapping_mul(MICRO_ANCHOR)));
    let dr = digital_root(n);
    let dr_is_six = dr.ct_eq(&PERFECT_SIX);
    is_multiple & dr_is_six
}

pub fn temporal_root_from_timestamp(timestamp: u64) -> u64 {
    let k = timestamp.wrapping_div(MICRO_ANCHOR);
    MICRO_ANCHOR.wrapping_mul(k)
}
```

## The 2520-supergrid

```rust
pub fn supergrid_params(n: u64) -> Option<(u64, u64)> {
    if n % SUPER_GRID != 0 {
        return None;
    }
    let k = n / SUPER_GRID;
    let micro_n = 28 * k;
    Some((micro_n, k))
}

pub fn micro_to_supergrid(micro_pair: &DiophantinePair) -> DiophantinePair {
    DiophantinePair {
        a: ROTATION_FACTOR.wrapping_mul(micro_pair.a),
        b: ROTATION_FACTOR.wrapping_mul(micro_pair.b),
    }
}
```

## The public sampling functions

```rust
pub fn sample_three_layers_ct_90(
    root_n: u64,
    rng: &mut impl RngCore,
    use_90_transform: Choice,
) -> Option<MrsChain> {
    // Layer by layer sampling loop. Applies rotate_90 per layer when
    // use_90_transform is set, and checks 9-homogeneity afterward.
}

pub fn sample_three_layers_90(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    sample_three_layers_ct_90(root_n, rng, Choice::from(1))
}

pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    sample_three_layers_ct_90(root_n, rng, Choice::from(0))
}

pub fn sample_temporal_chain(
    timestamp: u64,
    rng: &mut impl RngCore,
) -> Option<MrsChain> {
    let root_n = temporal_root_from_timestamp(timestamp);
    let use_super = (root_n % SUPER_GRID == 0) as u8;
    let mut chain = sample_three_layers_90(root_n, rng)?;

    if use_super == 1 {
        chain.transform_level = TransformLevel::SuperGrid;
    } else {
        chain.transform_level = TransformLevel::TemporalAnchor;
    }
    Some(chain)
}
```

verify_temporal_chain checks that N = 19A + 9B holds for the first layer, and that 9-homogeneity holds for any transform_level other than Raw.

## What the draft's tests establish

366 = 6×19 + 28×9 holds exactly.

A 90-rotation preserves the underlying equation: 19A* + 9B* = 90N.

A 90-rotation produces numbers with digital root 9, confirmed for both A* and B*.

32940, the macro anchor, has digital root 9.

The supergrid transform for N = 2520 reduces correctly to the smaller problem 28 = 19×1 + 9×1.

A chain generated in 90-mode has digital root 9 on every layer.

A temporal chain is valid inside its 366-second window and reports as invalid for a timestamp one full period later.

## Relationship to the existing crate

This module defines its own MrsChain, with an added transform_level field not present in the existing security::witness::MrsChain. As a separate module path this compiles without conflict; the two types share a name but are distinguished by their module location.
