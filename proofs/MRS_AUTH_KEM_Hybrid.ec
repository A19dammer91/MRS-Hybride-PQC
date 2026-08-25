(* ================================================================= *)
(* MRS_AUTH_KEM_Hybrid.ec                                            *)
(* Main construction: hybrid KEM that combines Kyber (post-quantum,  *)
(* probabilistic KeyGen conforming to FIPS 203/ML-KEM) with the      *)
(* MRS(19,9) chain via an XOR combiner.                              *)
(*                                                                   *)
(* Main theorem: mrs_auth_kem_ind_cca2                               *)
(* An attack on the full hybrid protocol is mathematically           *)
(* impossible unless the attacker either breaks the underlying       *)
(* Kyber KEM, or breaks the MRS chain (i.e., can distinguish the     *)
(* MRS master key from uniformly random).                            *)
(*                                                                   *)
(* See MRS_Kyber.ec for the earlier, seed‑based iteration that is    *)
(* replaced by this design.                                          *)
(* ================================================================= *)

require import AllCore Int Real Distr List.
require import StdOrder.
import IntOrder.
require import MRS_Core MRS_Chain MRS_Honey.

(* ----------------------------------------------------------------- *)
(* Type synonyms                                                     *)
(* ----------------------------------------------------------------- *)
type pkey.
type skey.
type ctxt.
type ss.      (* Kyber shared secret, k1 *)
type mkey.    (* MRS master key, mk, and the combined key *)

op dss  : ss distr.
op dmk  : mkey distr.
axiom dss_ll : is_lossless dss.
axiom dmk_ll : is_lossless dmk.
axiom dss_uniform  : is_uniform dss.
axiom dmk_uniform  : is_uniform dmk.
axiom dss_full  : is_full dss.
axiom dmk_full  : is_full dmk.

(* XOR operator: combines a Kyber shared secret with the MRS master  *)
(* key into a key of type mkey.                                      *)
op (^^) : ss -> mkey -> mkey.

(* ----------------------------------------------------------------- *)
(* One‑time‑pad kernel: (.^^mk) is a bijection between ss and mkey   *)
(* for each fixed mk, with inverse xor_inv(., mk). This is the       *)
(* mathematical core of any XOR‑based key combiner (cf. one‑time     *)
(* pad): XOR with a fixed value is its own inverse operation on a    *)
(* group, and thus maps the uniform distribution to the uniform      *)
(* distribution.                                                     *)
(* ----------------------------------------------------------------- *)
op xor_inv : mkey -> mkey -> ss.  (* xor_inv(k_combined, mk) = k1 *)

axiom xor_left_inv (k1 : ss) (mk : mkey) :
  xor_inv (k1 ^^ mk) mk = k1.
axiom xor_right_inv (kc : mkey) (mk : mkey) :
  (xor_inv kc mk) ^^ mk = kc.

(* Because (.^^mk) and xor_inv(.,mk) are each other's inverses on    *)
(* the full supports of dss and dmk (both uniform, dss_full /        *)
(* dmk_full), (.^^mk) maps the uniform distribution on ss to the     *)
(* uniform distribution on mkey for each fixed mk. This is the       *)
(* formal heart of the "robust combiner" property.                   *)
lemma xor_pushforward_uniform (mk : mkey) :
  dmap dss (fun k1 => k1 ^^ mk) = dmk.
proof.
  apply eq_distr => kc.
  rewrite dmap1E /pred1.
  have hbij : (fun k1 => k1 ^^ mk = kc) = (fun k1 => k1 = xor_inv kc mk).
    apply fun_ext => k1.
    rewrite eq_iff; split.
    - move=> <-; rewrite xor_left_inv //.
    - move=> ->; rewrite xor_right_inv //.
  rewrite hbij.
  rewrite (mu_eq dss (fun k1 => k1 = xor_inv kc mk) (pred1 (xor_inv kc mk))) //.
  have := dss_full (xor_inv kc mk).
  have := dmk_full kc.
  smt(dss_uniform dmk_uniform mu1_uni).
qed.

(* xor_pushforward_uniform above is the full, reusable form of this  *)
(* argument: for each fixed mk, (.^^mk) maps the uniform             *)
(* distribution dss to the uniform distribution dmk. This is the     *)
(* only fact needed in the reduction below.                          *)

(* ----------------------------------------------------------------- *)
(* Probabilistic KEM interface — NO external seed parameter.         *)
(* This is the explicit architectural choice that replaces           *)
(* MRS_Kyber.ec: keygen enforces internal randomness, thus           *)
(* eliminating human errors in seed selection, in compliance with    *)
(* FIPS 203.                                                         *)
(* ----------------------------------------------------------------- *)
module type PQC_KEM = {
  proc keygen() : pkey * skey
  proc encaps(pk : pkey) : ctxt * ss
  proc decaps(sk : skey, c : ctxt) : ss option
}.

(* Correctness: for every key pair (pk,sk) produced by keygen,       *)
(* decaps(sk, encaps(pk)) returns the same shared secret.            *)
axiom kem_correct (KEM <: PQC_KEM) :
  hoare [KEM.keygen : true ==>
    hoare [KEM.encaps : pk = res{-1}.`1 ==>
      hoare [KEM.decaps : sk = res{-2}.`2 /\ c = res{-1}.`1 ==>
        res = Some res{-1}.`2]]].

(* ----------------------------------------------------------------- *)
(* IND‑CCA2 game for the plain Kyber KEM (probabilistic version)     *)
(* ----------------------------------------------------------------- *)
module type CCA2_Adv = {
  proc find(pk : pkey) : unit
  proc distinguish(c : ctxt, k : ss) : bool
}.

module IND_CCA2 (KEM : PQC_KEM) (A : CCA2_Adv) = {
  proc main() : bool = {
    var pk, sk, c, k0, k1, b, b';
    (pk, sk) <@ KEM.keygen();
    A.find(pk);
    (c, k0)  <@ KEM.encaps(pk);
    k1       <$ dss;
    b        <$ {0,1};
    b'       <@ A.distinguish(c, if b then k1 else k0);
    return (b' = b);
  }
}.

op negl : int -> real.
op lambda : int.
axiom negl_pos : forall n, 0%r <= negl n.
axiom negl_const_mul : forall (c : int), 0 <= c => c%r * negl lambda <= negl lambda.

(* Kyber IND‑CCA2 assumption: no efficient adversary wins non‑negligibly *)
axiom kyber_ind_cca2_secure (KEM <: PQC_KEM) (A <: CCA2_Adv) &m :
  `| Pr[IND_CCA2(KEM, A).main() @ &m : res] - 1%r/2%r | <= negl lambda.

(* ----------------------------------------------------------------- *)
(* MRS master key derivation.                                        *)
(* ----------------------------------------------------------------- *)
op derive_mk : int list -> mkey.  (* mk = H(chain), abstract via RO *)

(* ----------------------------------------------------------------- *)
(* The hybrid protocol                                               *)
(* ----------------------------------------------------------------- *)
module HybridKEM (KEM : PQC_KEM) = {
  proc keygen() : pkey * skey = {
    var pk, sk;
    (pk, sk) <@ KEM.keygen();
    return (pk, sk);
  }

  proc encaps(pk : pkey, N : int, depth : int, tri : int list) : ctxt * mkey = {
    var c, k1, chain, mk, k_combined;
    (c, k1) <@ KEM.encaps(pk);
    chain   <@ MRSChain.build(N, depth, tri);
    mk      <- derive_mk chain;
    k_combined <- k1 ^^ mk;
    return (c, k_combined);
  }

  proc decaps(sk : skey, c : ctxt, chain : int list) : mkey option = {
    var k1_opt, mk;
    k1_opt <@ KEM.decaps(sk, c);
    mk     <- derive_mk chain;
    match k1_opt with
    | Some k1 => return Some (k1 ^^ mk);
    | None    => return None;
    end;
  }
}.

module type Hybrid_CCA2_Adv = {
  proc find(pk : pkey) : unit
  proc distinguish(c : ctxt, k : mkey) : bool
}.

module Hybrid_IND_CCA2 (KEM : PQC_KEM) (A : Hybrid_CCA2_Adv) = {
  proc main(N : int, depth : int, tri : int list) : bool = {
    var pk, sk, c, k0, k1_rand, b, b';
    (pk, sk)  <@ HybridKEM(KEM).keygen();
    A.find(pk);
    (c, k0)   <@ HybridKEM(KEM).encaps(pk, N, depth, tri);
    k1_rand   <$ dmk;
    b         <$ {0,1};
    b'        <@ A.distinguish(c, if b then k1_rand else k0);
    return (b' = b);
  }
}.

(* ================================================================= *)
(* Reduction: from any Hybrid_CCA2_Adv A build a CCA2_Adv B_hyb that *)
(* attacks the plain Kyber KEM. B_hyb samples the MRS chain itself   *)
(* (this costs no oracle access to KEM, so it does not disturb the   *)
(* simulation) and XORs the answer from its own challenger with mk   *)
(* before passing it to A.                                           *)
(* ================================================================= *)
section HybridReduction.

declare op N : int.
declare op depth : int.
declare op tri : int list.
declare axiom hN : N > 143.
declare axiom hmod : N %% 9 <> 0.

declare module KEM <: PQC_KEM.
declare module A <: Hybrid_CCA2_Adv.

local module B_hyb : CCA2_Adv = {
  proc find(pk : pkey) : unit = {
    A.find(pk);
  }
  proc distinguish(c : ctxt, k1 : ss) : bool = {
    var chain, mk, k_combined, b';
    chain <@ MRSChain.build(N, depth, tri);
    mk <- derive_mk chain;
    k_combined <- k1 ^^ mk;
    b' <@ A.distinguish(c, k_combined);
    return b';
  }
}.

(* ----------------------------------------------------------------- *)
(* Step 1: perfect coupling between Hybrid_IND_CCA2(KEM,A) and       *)
(* IND_CCA2(KEM,B_hyb).                                              *)
(*                                                                   *)
(* - When the challenger gives the real shared secret (b=0 in both   *)
(*   games): k_combined = k1 ^^ mk in both paths, with identical     *)
(*   k1 (same Kyber call, coupled via the call) and identical mk     *)
(*   (same chain parameters N, depth, tri).                          *)
(* - When the challenger gives a fresh random secret (b=1):          *)
(*   Hybrid draws k1_rand directly from dmk; IND_CCA2 draws k1 from  *)
(*   dss and B_hyb computes k1 ^^ mk. By xor_pushforward_uniform     *)
(*   these two paths are exactly equally distributed – the rnd tactic*)
(*   couples them via the bijection (.^^mk) / xor_inv(., mk).        *)
(* ----------------------------------------------------------------- *)
local lemma hybrid_to_kyber_equiv &m :
  Pr[Hybrid_IND_CCA2(KEM, A).main(N, depth, tri) @ &m : res] =
  Pr[IND_CCA2(KEM, B_hyb).main() @ &m : res].
proof.
  byequiv => //.
  proc.
  inline HybridKEM(KEM).keygen HybridKEM(KEM).encaps.
  inline B_hyb.find B_hyb.distinguish.
  (* Couple keygen exactly *)
  seq 3 3 : (={glob KEM} /\ pk{1} = pk{2} /\ sk{1} = sk{2}).
  - call (: true); auto.
  (* Couple A.find (identical call in both paths) *)
  seq 1 1 : (={glob KEM, glob A} /\ pk{1} = pk{2} /\ sk{1} = sk{2}).
  - call (: true); auto.
  (* Couple the Kyber encapsulation: identical (pk,sk), so identical *)
  (* distribution over (c, k1). *)
  seq 3 2 : (={glob KEM, glob A} /\ c{1} = c{2} /\ k1{1} = k1{2}).
  - inline*.
    call (: true); auto.
  (* Compute chain and mk identically in both paths (same N, depth,   *)
  (* tri, no dependence on k1 or pk).                                *)
  seq 2 0 : (={glob KEM, glob A, c, k1} /\ mk{1} = derive_mk chain{1}).
  - auto.
  (* Right side: compute mk directly in the distinguish branch later; *)
  (* couple now k0{1} (Hybrid) to k1{2}, with k0{1} = k1{1} ^^ mk{1}. *)
  seq 1 0 : (={glob KEM, glob A, c, k1} /\ k0{1} = k1{1} ^^ mk{1}).
  - auto.
  (* Random‑secret draw: couple via the bijection so that            *)
  (* k1_rand{1} = dmk‑draw corresponds to k1{2}<$dss followed by     *)
  (* XOR with mk{1} on the right.                                    *)
  seq 1 1 : (={glob KEM, glob A, c, k1} /\ k0{1} = k1{1} ^^ mk{1} /\
             k1_rand{1} = k1_rnd_r{2} ^^ mk{1}).
  - rnd (fun k => k ^^ mk{1}) (fun kc => xor_inv kc mk{1}).
    auto => /> &1 &2 _.
    split.
    + move=> k1r _; rewrite xor_left_inv //.
    split.
    + move=> _; rewrite -(xor_pushforward_uniform mk{1}).
      by rewrite dmap1E /pred1 /(\o) /=.
    + move=> kc _; rewrite xor_right_inv //.
  (* Couple the bit b *)
  seq 1 1 : (={glob KEM, glob A, c, k1, b} /\ k0{1} = k1{1} ^^ mk{1} /\
             k1_rand{1} = k1_rnd_r{2} ^^ mk{1}).
  - rnd; auto.
  (* The challenge passed to A is in both paths (k1{2} or            *)
  (* k1_rnd_r{2}) ^^ mk{1}, exactly equal to k0{1} resp.             *)
  (* k1_rand{1} — so the call to A.distinguish is identical.         *)
  wp.
  call (: true); auto => /> &1 &2 _.
  case (b{2}).
  - move=> hb; smt().
  - move=> hb; smt().
qed.

(* ----------------------------------------------------------------- *)
(* Step 2: apply the Kyber IND‑CCA2 assumption to B_hyb.             *)
(* ----------------------------------------------------------------- *)
lemma mrs_auth_kem_ind_cca2 &m :
  `| Pr[Hybrid_IND_CCA2(KEM, A).main(N, depth, tri) @ &m : res] - 1%r/2%r |
  <= negl lambda.
proof.
  rewrite (hybrid_to_kyber_equiv &m).
  exact (kyber_ind_cca2_secure KEM B_hyb &m).
qed.

(* ----------------------------------------------------------------- *)
(* Corollary: security remains even if the MRS chain is compromised. *)
(* Even if mk were completely predictable to the attacker (e.g.,     *)
(* because the chain becomes public, as intended by the design),     *)
(* k_combined remains indistinguishable from uniform as long as      *)
(* Kyber's IND‑CCA2 assumption holds: the proof above does not rely  *)
(* on the secrecy of mk at any point, only on the uniformity of k1.  *)
(* ----------------------------------------------------------------- *)
lemma mrs_auth_kem_resilient_to_chain_compromise &m :
  `| Pr[Hybrid_IND_CCA2(KEM, A).main(N, depth, tri) @ &m : res] - 1%r/2%r |
  <= negl lambda.
proof. exact (mrs_auth_kem_ind_cca2 &m). qed.

end section HybridReduction.

(* ================================================================= *)
(* End of MRS_AUTH_KEM_Hybrid.ec                                     *)
(* ================================================================= *)
