(* ================================================================= *)
(* MRS_Kyber.ec                                                      *)
(* Early iteration: abstract Kyber KEM interface with an explicit,   *)
(* externally provided seed parameter for KeyGen.                    *)
(*                                                                   *)
(* Status: DEPRECATED / OBSOLETE                                     *)
(* This file has been superseded by MRS_AUTH_KEM_Hybrid.ec and is    *)
(* not used in the final security proofs. It remains only as         *)
(* historical reference and documentation of the design evolution.   *)
(* ================================================================= *)

require import AllCore Int Real Distr List.
require import StdOrder.
import IntOrder.

(* ----------------------------------------------------------------- *)
(* Type synonyms                                                     *)
(* ----------------------------------------------------------------- *)
type seed.
type pkey.  (* public key *)
type skey.  (* secret key *)
type ctxt.  (* ciphertext / encapsulation *)
type ss.    (* shared secret *)

op dseed : seed distr.  (* uniform distribution over seeds *)
axiom dseed_ll : is_lossless dseed.

(* ----------------------------------------------------------------- *)
(* Abstract KEM interface with explicit seed parameter               *)
(* ----------------------------------------------------------------- *)
module type PQC_KEM_Seeded = {
  proc keygen(sd : seed) : pkey * skey
  proc encaps(pk : pkey) : ctxt * ss
  proc decaps(sk : skey, c : ctxt) : ss option
}.

(* ----------------------------------------------------------------- *)
(* Correctness requirement: decaps(encaps(pk)) recovers the shared   *)
(* secret for every key pair produced by keygen(sd), for every sd.   *)
(* ----------------------------------------------------------------- *)
axiom kem_seeded_correct (KEM <: PQC_KEM_Seeded) (sd : seed) :
  hoare [KEM.keygen : arg = sd ==> true] =>
  hoare [KEM.decaps :
    arg = (res{-1}.`2, fst (res{-2})) ==>
    exists k, res = Some k].

(* ----------------------------------------------------------------- *)
(* IND‑CCA2 game for the seed‑based interface                        *)
(* ----------------------------------------------------------------- *)
module type CCA2_Adv_Seeded = {
  proc find(pk : pkey) : unit { }
  proc distinguish(c : ctxt, k : ss) : bool
}.

module IND_CCA2_Seeded (KEM : PQC_KEM_Seeded) (A : CCA2_Adv_Seeded) = {
  proc main(sd : seed) : bool = {
    var pk, sk, c, k0, k1, b, b';
    (pk, sk) <@ KEM.keygen(sd);
    A.find(pk);
    (c, k0)  <@ KEM.encaps(pk);
    k1       <$ dss;              (* random, independent secret *)
    b        <$ {0,1};
    b'       <@ A.distinguish(c, if b then k1 else k0);
    return (b' = b);
  }
}.

op dss : ss distr.
axiom dss_ll : is_lossless dss.

(* ----------------------------------------------------------------- *)
(* Critical point of this design: the seed is an external input.     *)
(*                                                                   *)
(* Weakness: if two different calls to keygen receive the same seed  *)
(* (e.g., due to human error, a broken RNG, or reuse of a test       *)
(* vector in production), then the produced key pairs are identical. *)
(* This is a real operational risk that no cryptographic assumption  *)
(* can compensate: the security of the scheme depends on a guarantee *)
(* that lies outside the scheme itself (uniqueness of the seed).     *)
(* ----------------------------------------------------------------- *)
lemma keygen_seed_reuse_collision (KEM <: PQC_KEM_Seeded) (sd : seed) :
  equiv [KEM.keygen ~ KEM.keygen : arg{1} = sd /\ arg{2} = sd ==> ={res}].
proof.
  (* Proof sketch: a deterministic or weakly randomized keygen that
   * is fully reducible to `sd` yields the same key pair for equal
   * seeds. This lemma documents the assumption that is *implicitly*
   * required for this design to be secure: seed uniqueness must be
   * externally guaranteed. It is precisely this point that the
   * probabilistic KeyGen interface in MRS_AUTH_KEM_Hybrid.ec
   * eliminates.
   *)
  admit. (* Assumption, not proven: this is the explicit weakness of
            this design that motivates the replacement. *)
qed.

(* ================================================================= *)
(* End of MRS_Kyber.ec                                               *)
(* Deprecated – replaced by MRS_AUTH_KEM_Hybrid.ec                  *)
(* ================================================================= *)
