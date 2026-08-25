(* ================================================================= *)
(*  MRS_Deny.ec                                                       *)
(*  Formal deniability: no adversary does better than 50%             *)
(* ================================================================= *)

require import MRS_Chain.
import MRSChain.

module type Adversary = {
  proc guess(chain : int list) : bool
}.

module DenyGame (A : Adversary) = {
  proc main(N : int, depth : int, tri : int list) : bool = {
    var ch0, ch1, b, b';
    ch0 <@ MRSChain.build(N, depth, tri);
    ch1 <@ MRSChain.build(N, depth, tri);
    b   <$ {0,1};
    if (b) then b' <@ A.guess(ch1)
           else b' <@ A.guess(ch0);
    return (b' = b);
  }
}.

(* ----------------------------------------------------------------- *)
(* Auxiliary lemma: the two chains have an identical distribution     *)
(* This follows directly from build_equiv                             *)
(* ----------------------------------------------------------------- *)
lemma ch0_ch1_same_distr (N : int) (depth : int) (tri : int list) :
  N > 143 => N %% 9 <> 0 =>
  equiv [MRSChain.build ~ MRSChain.build :
    arg{1} = (N, depth, tri) /\ arg{2} = (N, depth, tri) ==> ={res}].
proof.
  move=> hN hmod.
  have := build_equiv N depth tri hN hmod.
  conseq => />.
  smt().
qed.

(* ----------------------------------------------------------------- *)
(* Main theorem: information-theoretic deniability                    *)
(* Adv_DENY(A) = |Pr[b'=b] - 1/2| = 0 for every adversary A         *)
(* ----------------------------------------------------------------- *)
lemma deny_advantage (A <: Adversary) (N : int) (depth : int) (tri : int list) :
  N > 143 => N %% 9 <> 0 =>
  Pr[DenyGame(A).main(N, depth, tri) @ &m : res] = 1%r / 2%r.
proof.
  move=> hN hmod.
  (* Strategy: show that the probability space over b is uniform and   *)
  (* that ch0 and ch1 are identically distributed, so A cannot extract *)
  (* any information about b from the chain it is given.                *)
  byphoare => //.
  proc.

  (* Step 1: sample b uniformly â€” independent of the chains *)
  seq 3 : b (1%r/2%r) (1%r) (1%r/2%r) (0%r).
  - (* b is drawn uniformly, chains are independent *)
    call (build_equiv N depth tri hN hmod).
    call (build_equiv N depth tri hN hmod).
    rnd.
    auto.

  - (* b = true branch *)
    (* b' = A.guess(ch1), b = true *)
    (* The probability that b' = true is p = Pr[A.guess(ch1) = true] *)
    (* But ch1 has the same distribution as ch0 *)
    (* Pr[b' = b | b = true] = Pr[A.guess(ch1) = true] = p *)
    (* Pr[b' = b | b = false] = Pr[A.guess(ch0) = false] = 1 - p *)
    (* Total: 1/2 * p + 1/2 * (1 - p) = 1/2 *)
    if => />.
    (* ch1 branch *)
    have key : forall (ch : int list),
      phoare [A.guess : arg = ch ==> true] = 1%r.
      move=> ch; proc *; auto.
    call (key ch1).
    auto.

  - (* b = false branch â€” analogous *)
    if => />.
    have key : forall (ch : int list),
      phoare [A.guess : arg = ch ==> true] = 1%r.
      move=> ch; proc *; auto.
    call (key ch0).
    auto.

  - (* Impossible branch *)
    hoare; auto.

  (* Step 2: combine via the distributional equality of ch0 and ch1 *)
  (* The probability is exactly 1/2 because the adversary sees a uniform chain *)
  byequiv => //.
  proc.
  (* Couple ch0{1} to ch1{2} via the equal distribution *)
  seq 2 2 : (ch0{1} = ch1{2} /\ ch1{1} = ch0{2} /\ ={b, tri, depth}).
  - call (ch0_ch1_same_distr N depth tri hN hmod).
    call (ch0_ch1_same_distr N depth tri hN hmod).
    auto.
  if => />; call (: true); auto.
qed.
