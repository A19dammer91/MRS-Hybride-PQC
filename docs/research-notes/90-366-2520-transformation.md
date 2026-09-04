# Research Note: The 90 / 366 / 2520 Transformation

Status: exploratory idea, not implemented, not formally verified, not part of the core framework.

This document explains a possible extension to MRS-AUTH.

## 1. The basic idea in one sentence

Take the existing witness (a set of numbers that satisfy N = 19A + 9B) and multiply every number in it by a fixed constant, 90, or a related constant, 2520, so that every number in the result ends in the same digital root (a simple checksum like property). If every number looks the same from that angle, an attacker who only checks that one property learns nothing.

## 2. What is a digital root

The digital root of a number is what you get by repeatedly adding its digits until only one digit is left. For example:

366 becomes 3+6+6 = 15, then 1+5 = 6.
32940 becomes 3+2+9+4+0 = 18, then 1+8 = 9.

There is a shortcut: for any positive whole number, the digital root only depends on the remainder after dividing by 9. This is the same digital root function already used throughout the core framework's sampler (the dr(N) function in the README).

Key fact used here: if a number is a multiple of 9, its digital root is always exactly 9. No exceptions.

## 3. Where 90, 366, and 2520 come from

366 equals 6 times 19 plus 28 times 9. The numbers 6 and 28 are chosen because they are perfect numbers (numbers equal to the sum of their own divisors, a well known concept in number theory: 6 = 1+2+3, 28 = 1+2+4+7+14). 366 also happens to be the number of days in a leap year, which is where the idea of using it as a time based anchor comes from (Section 5).

90 equals 9 times 10. Multiplying any number by 90 automatically makes it a multiple of 9. That is the whole trick: multiplying by 90 forces the digital root to become 9, every time, regardless of what the original number was.

2520 equals 90 times 28, and is the smallest number that all of 1, 2, 3, up to 10 divide into evenly (the least common multiple of 1 through 10). It is used here as a larger version of the same trick, combining multiple smaller cycles into one bigger structure.

## 4. What this achieves

The core framework already proves something narrower: that an attacker cannot tell an authentic witness from an alibi witness without knowing the secret key, based on a cryptographic argument (the binding tag behaves like random noise unless you have the key, as in the existing MRS_Deny.ec proof).

The 90/366/2520 idea targets a different, more specific kind of attacker: one who does not try to break the cryptography at all, but instead looks for shortcuts, simple patterns in the numbers themselves that might leak which witness is real. The Adaptive Attacker tab in the demo tests exactly this kind of attacker, and one of its strategies (A0 Bias) specifically checks the digital root.

When every number in every witness has a forced digital root of 9, that one specific shortcut stops working completely, because there is nothing left to observe on that axis: it is always the same value.

## 5. The time based idea

A separate idea layered on top uses 366 (seconds, in this proposal) as a time window. A witness generated in one 366 second window is only considered valid within that window, similar to how a rolling code expires after a short period. This idea is independent of the digital root idea above; a 366 second time window could be used without any of the 90 rotation math, or vice versa.

## 6. A preview of the code

The full draft code is kept in two dedicated files, split the same way an implementation would be split.

sampler-90-366.md holds the 90 rotation itself, the digital root checks, the 366 time window and 2520 supergrid helpers, and the sampling functions that produce a witness chain.

witness-90-366.md holds the authentication layer built on top: generating a witness tied to an identity and a point in time, checking whether it has expired, and generating an alibi.

Both files are excerpts from an early draft. The short version of what is in them: a function that multiplies a witness pair by 90, forcing its digital root to 9, and a wrapper around it that ties a witness to a 366 second time window.

## 7. What the formal proof shows

An EasyCrypt proof draft accompanies this idea. It formally establishes several things:

The 366 decomposition (366 = 6×19 + 28×9) holds exactly.

A 90 rotation of any valid (A, B) pair preserves the underlying MRS equation, scaled by 90.

A 90 rotation forces the digital root of every transformed number to 9.

There is a bijection between the micro space (witnesses for N=366) and the macro space (witnesses for N=32940), meaning every micro witness corresponds to exactly one macro witness and vice versa.

The supergrid transform preserves this same bijection at larger scales (multiples of 2520).

The proof also contains a lemma stating that a digital root observing adversary has identical success probability against an authentic witness and an alibi witness in the macro space, since the digital root is constant at 9 for every element of that space.

The adversary type used in that lemma is given the full (a, b, n) values, not just the digital root. The lemma's proof reasons from the digital root being constant, which shows that a digital root check specifically yields no information. It does not by itself establish that the complete numbers are equally distributed between authentic and alibi witnesses, which is a broader claim about the whole value rather than one derived property of it.

## 8. Summary of findings

Multiplying a witness by 90 provably forces every number in it to have digital root 9, confirmed both by direct calculation and by the EasyCrypt proof.

This construction provably defeats any attacker strategy based purely on checking digital roots, matching the behavior already observed empirically in the demo's Adaptive Attacker tab.

The bijection between the micro space (N=366) and the macro space (N=32940) is formally established, and generalizes to the 2520 supergrid.

The proof's strongest stated conclusion, that this defeats a digital root observing adversary, is narrower than the broader claim that a full witness (not just its digital root) is indistinguishable between authentic and alibi. The formal argument given supports the narrower claim.
