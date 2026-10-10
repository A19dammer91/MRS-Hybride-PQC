(* ================================================================= *)
(*  MRS_Core.ec                                                       *)
(*  Mathematical core of MRS-AUTH: the 19A + 9B representation       *)
(*  system under the Positive Anchor Convention.                      *)
(*                                                                    *)
(*  The anchor A_0 is defined as the digital root of N:               *)
(*      A_0 = dr(N) = 1 + ((N - 1) mod 9)      for N > 0              *)
(*                                                                    *)
(*  Key structural fact:                                              *)
(*      N = 9 * (N %/ 9) + (N %% 9)                                   *)
(*  and the anchor satisfies:                                         *)
(*      a0 N = N %% 9      if N %% 9 <> 0                             *)
(*      a0 N = 9           if N %% 9 = 0                              *)
(*  so in all cases a0 N ≡ N (mod 9) and 1 <= a0 N <= 9.              *)
(*                                                                    *)
(*  Axiom baseline: 0.                                                *)
(*                                                                    *)
(*  Robustness principles (calibrated for EasyCrypt r2024.09):        *)
(*  - NO axioms, NO admits.                                           *)
(*  - `linarith`, `nlinarith`, `ltz_pmod`, `divz_ge0` are avoided.   *)
(*  - `ring_simplify` is avoided.                                     *)
(*  - `(by tactic)` is never used as a term argument.                 *)
(*  - `smt(/pred_name)` is NOT used (parse error in r2024.09).        *)
(*  - `rewrite /pred_name` in a goal is NOT used: in r2024.09 the     *)
(*    pred is expanded automatically by `move: h.` on a hypothesis.   *)
(*  - `mulzI` and `ltz_pmod` are NOT used (not available in r2024.09).*)
(*    Injectivity of multiplication by a nonzero constant is         *)
(*    delegated to `smt()` directly.                                  *)
(*  - `~` is NOT used for negation: `!` or an explicit implication   *)
(*    `P => false` is used instead, since `~` triggers a parse error  *)
(*    in r2024.09 in various positions.                               *)
(*  - Long `rewrite Heq` chains are fragile in r2024.09; modular      *)
(*    arithmetic is delegated to `smt(modzDl modzMl modz_mod)`.       *)
(*  - `case (cond).` without `=>` pattern is a parse error in         *)
(*    r2024.09; the robust form is `case (cond) => [hyp_true |        *)
(*    hyp_false].` everywhere.                                        *)
(*  - `set k := ...` is a parse error in r2024.09; concrete terms    *)
(*    are substituted directly instead.                               *)
(*  - Case-splits are avoided when `smt()` closes the goal directly.  *)
(*  - Concrete `dr` computations use `smt()` directly.                *)
(*  - Conjunctive lemmas are bound to a name before splitting:        *)
(*    `have hrange := L.` followed by `have [..] := hrange.` instead  *)
(*    of `have [..] := L.` directly.                                  *)
(*  - Module variable names carry no digits: digits inside identifiers*)
(*    trigger a parse error in `var` declarations in r2024.09.        *)
(*  - Module bodies contain no blank lines: blank lines inside a      *)
(*    procedure body disturb the parser in r2024.09.                  *)
(*  - A procedure returns exactly once, at the end: early `return`   *)
(*    inside an `if` block is a parse error in r2024.09. The return   *)
(*    value is accumulated in a local variable `res`.                 *)
(*  - The `%/` arithmetic for `tbn` is computed before the `if`       *)
(*    block, so that the `if` body contains only simple assignments   *)
(*    and a random sampling. This avoids a parser quirk in r2024.09   *)
(*    where `%/` inside an `if` body inside a procedure is fragile.   *)
(*  - Each procedure and each module appears exactly once: duplicate  *)
(*    definitions trigger a parse error in r2024.09.                  *)
(* ================================================================= *)

require import AllCore Int IntDiv Real Distr List.
require import StdOrder.
import IntOrder.

(* ----------------------------------------------------------------- *)
(* Digital root                                                       *)
(* ----------------------------------------------------------------- *)
op dr (n : int) : int = if n <= 0 then 0 else 1 + ((n - 1) %% 9).

lemma dr_range (n : int) : 0 < n => 1 <= dr n /\ dr n <= 9.
proof.
  move=> hn.
  rewrite /dr.
  have h : ! (n <= 0) by smt().
  rewrite h /=.
  split; first by smt(modz_ge0).
  by smt().
qed.

lemma dr_mod9 (n : int) : 0 < n => dr n = n - 9 * ((n - 1) %/ 9).
proof.
  move=> hn.
  rewrite /dr.
  have h : ! (n <= 0) by smt().
  rewrite h /=.
  have := divz_eq (n - 1) 9.
  smt().
qed.

lemma dr_cong9 (n : int) : 0 < n => (dr n - n) %% 9 = 0.
proof.
  move=> hn.
  rewrite /dr.
  have h : ! (n <= 0) by smt().
  rewrite h /=.
  have key : (1 + (n - 1) %% 9 - n) %% 9 = 0.
    have := modzDl (n - 1) 9.
    smt(modz_mod modzNm).
  exact key.
qed.

lemma dr_add9 (n : int) : 0 < n => dr (n + 9) = dr n.
proof.
  move=> hn.
  rewrite /dr.
  have h1 : ! (n + 9 <= 0) by smt().
  have h2 : ! (n <= 0) by smt().
  rewrite h1 h2 /=.
  have : (n + 9 - 1) %% 9 = (n - 1) %% 9.
    have ->: n + 9 - 1 = (n - 1) + 9 by ring.
    by rewrite modzDr.
  by move=> ->.
qed.

lemma dr_9k_r (k r : int) : 0 <= k => 0 < r => dr (9 * k + r) = dr r.
proof.
  move=> hk hr.
  rewrite /dr.
  have h1 : ! (9 * k + r <= 0) by smt().
  have h2 : ! (r <= 0) by smt().
  rewrite h1 h2 /=.
  have key : (9 * k + r - 1) %% 9 = (r - 1) %% 9 by smt().
  by rewrite key.
qed.

lemma dr_19 (n : int) : 0 < n => dr (19 * n) = dr n.
proof.
  move=> hn.
  have Heq : 19 * n = 9 * (2 * n) + n by ring.
  rewrite Heq.
  apply dr_9k_r; smt().
qed.

lemma dr_19A_9B (n m : int) : 0 < n => 0 <= m => dr (19 * n + 9 * m) = dr n.
proof.
  move=> hn hm.
  have Heq : 19 * n + 9 * m = 9 * (2 * n + m) + n by ring.
  rewrite Heq.
  have hk : 0 <= 2 * n + m by smt().
  exact (dr_9k_r (2 * n + m) n hk hn).
qed.

lemma dr_idempotent (n : int) : 1 <= n => n <= 9 => dr n = n.
proof.
  move=> h1 h9.
  rewrite /dr.
  have hpos : ! (n <= 0) by smt().
  rewrite hpos /=.
  have hmod : (n - 1) %% 9 = n - 1 by smt().
  rewrite hmod.
  ring.
qed.

(* ----------------------------------------------------------------- *)
(* Positive Anchor Convention                                        *)
(* ----------------------------------------------------------------- *)
op a0 (N : int) : int = dr N.
op B0 (N : int) : int = (N - 19 * a0 N) %/ 9.
op kmax (N : int) : int = (B0 N) %/ 19.

(* ----------------------------------------------------------------- *)
(* Auxiliary lemmas about a0 and B0                                   *)
(* ----------------------------------------------------------------- *)

lemma a0_range (N : int) : 0 < N => 1 <= a0 N /\ a0 N <= 9.
proof.
  move=> hN.
  rewrite /a0.
  by apply dr_range.
qed.

lemma a0_cong9 (N : int) : 0 < N => (a0 N - N) %% 9 = 0.
proof.
  move=> hN.
  rewrite /a0.
  by apply dr_cong9.
qed.

lemma a0_eq_mod9_or_9 (N : int) : 0 < N => a0 N = N %% 9 \/ a0 N = 9.
proof.
  move=> hNpos.
  have ha0 := a0_cong9 N hNpos.
  have hrange := a0_range N hNpos.
  have [hlo hhi] := hrange.
  have hmod_ge0 : 0 <= N %% 9 by smt(modz_ge0).
  case (N %% 9 = 0) => [hmod0 | hmod_ne].
  - right.
    smt().
  - left.
    smt().
qed.

lemma N_minus_19a0_mod9 (N : int) : 0 < N => (N - 19 * (a0 N)) %% 9 = 0.
proof.
  move=> hN.
  have ha0 := a0_cong9 N hN.
  have Heq : N - 19 * a0 N = N - a0 N - 18 * a0 N by ring.
  rewrite Heq.
  have h1 : (N - a0 N) %% 9 = 0 by smt(modzDl modzNm).
  have h2 : (18 * a0 N) %% 9 = 0 by smt().
  smt(modzDl).
qed.

lemma key_ineq (N : int) : 162 < N => 19 * (a0 N) <= N.
proof.
  move=> hN.
  have hNpos : 0 < N by smt().
  have hrange := a0_range N hNpos.
  have [hlo hhi] := hrange.
  case (a0 N = 9) => [heq | hne].
  - have hcong := a0_cong9 N hNpos.
    have hmod : N %% 9 = 0 by rewrite heq in hcong; smt(modzDl modzNm).
    have hdiv : N = 9 * (N %/ 9) by smt(divz_eq).
    have hq_ge : 18 < N %/ 9.
      have : 162 < 9 * (N %/ 9) by rewrite -hdiv.
      smt().
    have hge : 171 <= N.
      have : 9 * 19 <= 9 * (N %/ 9) by smt().
      smt().
    rewrite heq.
    smt().
  - have hle : a0 N <= 8 by smt().
    smt().
qed.

lemma B0_ge0 (N : int) : 162 < N => 0 <= B0 N.
proof.
  move=> hN.
  have hNpos : 0 < N by smt().
  have hrange := a0_range N hNpos.
  have [hlo hhi] := hrange.
  have hdiv := divz_eq N 9.
  case (N %% 9 = 0) => [hmod0 | hmod_ne].
  - have ha0_9 : a0 N = 9.
      have h := a0_eq_mod9_or_9 N hNpos.
      case h => [hleft | hright].
      + smt().
      + exact hright.
    rewrite /B0 ha0_9.
    have hN_eq : N = 9 * (N %/ 9) by smt().
    have hq_ge : 19 <= N %/ 9.
      have : 162 < 9 * (N %/ 9) by rewrite -hN_eq.
      smt().
    have hnn : 0 <= N - 19 * 9 by smt().
    have hdecomp : N - 19 * 9 =
                   9 * ((N - 19 * 9) %/ 9) + (N - 19 * 9) %% 9
      by smt(divz_eq).
    have hr_ge0 : 0 <= (N - 19 * 9) %% 9 by smt(modz_ge0).
    have hr_lt : (N - 19 * 9) %% 9 < 9 by smt(modz_ge0 divz_eq).
    smt().
  - have ha0_mod : a0 N = N %% 9.
      have h := a0_eq_mod9_or_9 N hNpos.
      case h => [hleft | hright].
      + exact hleft.
      + smt().
    rewrite /B0 ha0_mod.
    have hN_eq : N = 9 * (N %/ 9) + N %% 9 by smt().
    have hmod_ge0 : 0 <= N %% 9 by smt(modz_ge0).
    have hmod_lt : N %% 9 < 9 by smt(modz_ge0 divz_eq).
    have hq_ge : 18 <= N %/ 9.
      have : 162 < 9 * (N %/ 9) + N %% 9 by rewrite -hN_eq.
      smt().
    have hnn : 0 <= N - 19 * (N %% 9) by smt().
    have hdecomp : N - 19 * (N %% 9) =
                   9 * ((N - 19 * (N %% 9)) %/ 9) + (N - 19 * (N %% 9)) %% 9
      by smt(divz_eq).
    have hr_ge0 : 0 <= (N - 19 * (N %% 9)) %% 9 by smt(modz_ge0).
    have hr_lt : (N - 19 * (N %% 9)) %% 9 < 9 by smt(modz_ge0 divz_eq).
    smt().
qed.

lemma kmax_ge0 (N : int) : 162 < N => 0 <= kmax N.
proof.
  move=> hN.
  rewrite /kmax.
  have hB0 : 0 <= B0 N by apply B0_ge0.
  have hdecomp : B0 N = 19 * (B0 N %/ 19) + B0 N %% 19 by smt(divz_eq).
  have hmod_ge0 : 0 <= B0 N %% 19 by smt(modz_ge0).
  have hmod_lt : B0 N %% 19 < 19 by smt(modz_ge0 divz_eq).
  smt().
qed.

lemma a0_B0_eq (N : int) : 0 < N => 19 * a0 N + 9 * B0 N = N.
proof.
  move=> hN.
  rewrite /B0 /a0.
  have h := N_minus_19a0_mod9 N hN.
  have := divz_eq (N - 19 * a0 N) 9.
  smt().
qed.

lemma linear_invariant N k :
  162 < N =>
  0 <= k <= kmax N =>
  19 * (a0 N + 9 * k) + 9 * (B0 N - 19 * k) = N.
proof.
  move=> hN hk.
  have hNpos : 0 < N by smt().
  have base := a0_B0_eq N hNpos.
  have Heq : 19 * (a0 N + 9 * k) + 9 * (B0 N - 19 * k) =
             19 * a0 N + 9 * B0 N by ring.
  rewrite Heq.
  exact base.
qed.

lemma B_ge0 (N k : int) :
  162 < N =>
  0 <= k <= kmax N =>
  0 <= B0 N - 19 * k.
proof.
  move=> hN hk.
  rewrite /kmax in hk.
  have hB0 : 0 <= B0 N by apply B0_ge0.
  have hk2 : k <= B0 N %/ 19 by smt().
  have hdecomp : B0 N = 19 * (B0 N %/ 19) + B0 N %% 19 by smt(divz_eq).
  have hmod_ge0 : 0 <= B0 N %% 19 by smt(modz_ge0).
  have h19k_le : 19 * k <= 19 * (B0 N %/ 19) by smt().
  have h19k_le_B0 : 19 * k <= B0 N by smt().
  smt().
qed.

lemma A_pos (N k : int) :
  162 < N =>
  0 <= k <= kmax N =>
  1 <= a0 N + 9 * k.
proof.
  move=> hN hk.
  have hNpos : 0 < N by smt().
  have hrange := a0_range N hNpos.
  have [hlo _] := hrange.
  smt().
qed.

(* ----------------------------------------------------------------- *)
(* Predicate and uniqueness                                            *)
(* ----------------------------------------------------------------- *)

pred is_rep (N A B : int) = 1 <= A /\ 0 <= B /\ 19*A + 9*B = N.

lemma rep_uniq (N : int) (A B : int) :
  162 < N => is_rep N A B =>
  exists k, 0 <= k <= kmax N /\ A = a0 N + 9*k /\ B = B0 N - 19*k.
proof.
  move=> hN hrep.
  have Apos : 1 <= A.
    move: hrep.
    move=> [hA _].
    exact hA.
  have Bpos : 0 <= B.
    move: hrep.
    move=> [_ [hB _]].
    exact hB.
  have eq : 19*A + 9*B = N.
    move: hrep.
    move=> [_ [_ hEq]].
    exact hEq.
  have hNpos : 0 < N by smt().
  have A_mod : A %% 9 = N %% 9.
    have Heq : N = 19*A + 9*B by smt().
    rewrite Heq.
    smt(modzDl modzMl modz_mod).
  have ha0_eq_N : (a0 N - N) %% 9 = 0 by apply a0_cong9.
  have heq_mod : (A - a0 N) %% 9 = 0 by smt(modzDl modzNm).
  have hrange := a0_range N hNpos.
  have [hlo hhi] := hrange.
  have hA_ge_a0 : a0 N <= A by smt().
  have k_ge0 : 0 <= (A - a0 N) %/ 9 by smt().
  have A_eq : A = a0 N + 9 * ((A - a0 N) %/ 9).
    have := divz_eq (A - a0 N) 9.
    smt().
  have B_eq : B = B0 N - 19 * ((A - a0 N) %/ 9).
    have sum_eq : 19 * (a0 N + 9*((A - a0 N) %/ 9)) + 9*B = N
      by rewrite -A_eq; smt().
    have hNpos' : 0 < N by smt().
    have base_eq : 19 * a0 N + 9 * B0 N = N by apply a0_B0_eq.
    smt().
  have k_le_kmax : (A - a0 N) %/ 9 <= kmax N.
    rewrite /kmax.
    have hB : 0 <= B0 N - 19 * ((A - a0 N) %/ 9) by rewrite -B_eq; smt().
    have hdecomp : B0 N - 19 * ((A - a0 N) %/ 9) =
                   19 * ((B0 N - 19 * ((A - a0 N) %/ 9)) %/ 19) +
                   (B0 N - 19 * ((A - a0 N) %/ 9)) %% 19
      by smt(divz_eq).
    have hmod_ge0 : 0 <= (B0 N - 19 * ((A - a0 N) %/ 9)) %% 19 by smt(modz_ge0).
    have hmod_lt : (B0 N - 19 * ((A - a0 N) %/ 9)) %% 19 < 19 by smt(modz_ge0 divz_eq).
    smt().
  exists ((A - a0 N) %/ 9).
  split.
  - smt().
  - split; smt().
qed.

(* ----------------------------------------------------------------- *)
(* dr properties for representations                                   *)
(* ----------------------------------------------------------------- *)

lemma dr_a0 (N : int) : 0 < N => dr (a0 N) = dr N.
proof.
  move=> hN.
  rewrite /a0.
  have hrange := dr_range N hN.
  have [hlo hhi] := hrange.
  apply dr_idempotent => //.
qed.

lemma dr_rep_A (N k : int) : 0 < N => 0 <= k => dr (a0 N + 9 * k) = dr N.
proof.
  move=> hN hk.
  have ha0 : 0 < a0 N by smt(a0_range).
  have hpos : 0 < a0 N + 9 * k by smt().
  have Heq : a0 N + 9 * k = 9 * k + a0 N by ring.
  have Hdr : dr (a0 N + 9 * k) = dr (9 * k + a0 N).
    by rewrite Heq.
  rewrite Hdr.
  rewrite dr_9k_r; smt().
qed.

lemma dr_triangle_B (N k : int) :
  162 < N =>
  0 <= k <= kmax N =>
  (B0 N - 19 * k) %% 9 = dr (2 * dr N) %% 9 =>
  0 < B0 N - 19 * k =>
  dr (B0 N - 19 * k) = dr (2 * dr N).
proof.
  move=> hN hk hcong hpos.
  rewrite /dr.
  have h1 : ! (B0 N - 19 * k <= 0) by smt().
  rewrite h1 /=.
  have htgt : 0 < dr (2 * dr N).
    have hNpos : 0 < N by smt().
    have hrange := dr_range N hNpos.
    have [h1' h2] := hrange.
    have h2pos : 0 < 2 * (if N <= 0 then 0 else 1 + (N-1) %% 9) by smt().
    smt(dr_range modz_ge0).
  rewrite /dr.
  have h2 : ! (2 * dr N <= 0) by smt().
  rewrite h2 /=.
  have cong2 : (B0 N - 19 * k - 1) %% 9 = (dr (2 * dr N) - 1) %% 9.
    have := hcong.
    smt(modzDl modzNm).
  smt().
qed.

(* ----------------------------------------------------------------- *)
(* Frobenius boundary under Positive Anchor                          *)
(* ----------------------------------------------------------------- *)

lemma frobenius_162_not_rep (A B : int) : is_rep 162 A B => false.
proof.
  move=> hrep.
  have hA : 1 <= A.
    move: hrep.
    move=> [h _].
    exact h.
  have hB : 0 <= B.
    move: hrep.
    move=> [_ [h _]].
    exact h.
  have hEq : 19*A + 9*B = 162.
    move: hrep.
    move=> [_ [_ h]].
    exact h.
  have hmod : A %% 9 = 0.
    have : (19*A + 9*B) %% 9 = 162 %% 9 by rewrite hEq.
    have h162 : 162 %% 9 = 0 by done.
    smt(modzDl modzNm modzMml).
  have hAle : A <= 8 by smt().
  have hAge : 1 <= A by exact hA.
  smt(modz_ge0).
qed.

lemma dr_163 : dr 163 = 1.
proof.
  rewrite /dr.
  have h1 : ! (163 <= 0) by done.
  rewrite h1 /=.
  smt().
qed.

lemma a0_163 : a0 163 = 1.
proof. by rewrite /a0 dr_163. qed.

lemma B0_163 : B0 163 = 16.
proof.
  rewrite /B0 a0_163.
  have Heq : 163 - 19 * 1 = 144 by ring.
  rewrite Heq.
  have Heq2 : 144 %/ 9 = 16 by done.
  by rewrite Heq2.
qed.

lemma frobenius_163_explicit :
  is_rep 163 1 16.
proof.
  rewrite /is_rep.
  split; first by done.
  split; first by done.
  by [].
qed.

lemma frobenius_163_via_anchor :
  is_rep 163 (a0 163) (B0 163).
proof.
  rewrite a0_163 B0_163.
  exact frobenius_163_explicit.
qed.

lemma frobenius_boundary :
  (forall (A B : int), is_rep 162 A B => false) /\
  (exists (A B : int), is_rep 163 A B).
proof.
  split.
  - move=> A B.
    exact (frobenius_162_not_rep A B).
  - exists 1 16.
    exact frobenius_163_explicit.
qed.

lemma no_unrep_above_162 (N : int) : 162 < N => is_rep N (a0 N) (B0 N).
proof.
  move=> hN.
  have hB : 0 <= B0 N by apply B0_ge0.
  have hA : 1 <= a0 N by smt(a0_range).
  have hNpos : 0 < N by smt().
  have heq : 19 * a0 N + 9 * B0 N = N by apply a0_B0_eq.
  smt().
qed.

lemma all_above_frobenius_representable (N : int) :
  163 <= N => exists (A B : int), is_rep N A B.
proof.
  move=> hN.
  have hN' : 162 < N by smt().
  exists (a0 N) (B0 N).
  exact (no_unrep_above_162 N hN').
qed.

(* ----------------------------------------------------------------- *)
(* Module for representation sampling                                 *)
(*                                                                    *)
(* All module variable names are digit-free: digits inside           *)
(* identifiers trigger a parse error in `var` declarations in         *)
(* EasyCrypt r2024.09.                                                *)
(*                                                                    *)
(* Naming convention:                                                 *)
(*   anc   anchor         = a0 N                                      *)
(*   bcp   B-component    = B0 N                                      *)
(*   kbn   K-bound        = kmax N                                    *)
(*   ddr   double dr      = dr (2 * dr N)                             *)
(*   dmod  ddr mod 9      = ddr %% 9                                  *)
(*   kbs   K-base         = (bcp - dmod) %% 9                         *)
(*   tbn   T-bound        = (kbn - kbs) %/ 9                          *)
(*   ndx   Index          = sampled uniform in [0..tbn]               *)
(*   kvl   K-value        = kbs + 9 * ndx                             *)
(*   res   Result         = (0, 0) or (anc + 9*kvl, bcp - 19*kvl)     *)
(*                                                                    *)
(* The `var` declaration is split over two lines: a single line with  *)
(* 10 identifiers (~50 chars) triggers a parse error in r2024.09,     *)
(* while two lines of 5 identifiers each fit within the parser's      *)
(* per-line limit.                                                    *)
(*                                                                    *)
(* The procedure returns exactly once, at the end, via `res`. Early  *)
(* returns inside an `if` block are a parse error in EasyCrypt        *)
(* r2024.09, so the return value is accumulated in `res` and the      *)
(* single `return res;` sits at the end of the procedure.             *)
(*                                                                    *)
(* The `%/` arithmetic for `tbn` is computed before the `if` block,   *)
(* so that the `if` body contains only simple assignments and a       *)
(* random sampling. This avoids a parser quirk in r2024.09 where      *)
(* `%/` inside an `if` body inside a procedure is fragile.            *)
(* ----------------------------------------------------------------- *)
module MRSRep = {
  proc sample_basic(N : int) : int * int = {
    var kvl;
    kvl <$ [0..kmax N];
    return (a0 N + 9 * kvl, B0 N - 19 * kvl);
  }

  proc sample_triangle(N : int) : int * int = {
    var anc, bcp, kbn, ddr, dmod;
    var kbs, tbn, ndx, kvl, res;
    anc <- a0 N;
    bcp <- B0 N;
    kbn <- kmax N;
    ddr <- dr (2 * dr N);
    dmod <- ddr %% 9;
    kbs <- (bcp - dmod) %% 9;
    tbn <- (kbn - kbs) %/ 9;
    if (kbn < kbs) {
      res <- (0, 0);
    } else {
      ndx <$ [0..tbn];
      kvl <- kbs + 9 * ndx;
      res <- (anc + 9 * kvl, bcp - 19 * kvl);
    }
    return res;
  }
}.

lemma triangle_k0_le_kmax (N : int) :
  162 < N =>
  (B0 N - dr (2 * dr N) %% 9) %% 9 <= kmax N \/
  kmax N < (B0 N - dr (2 * dr N) %% 9) %% 9.
proof.
  move=> hN. smt().
qed.

lemma sample_basic_correct (N : int) :
  162 < N =>
  hoare [MRSRep.sample_basic :
    arg = N ==>
    19 * (fst res) + 9 * (snd res) = N /\
    dr (fst res) = dr N].
proof.
  move=> hN.
  proc.
  auto => />.
  move=> &m kvl hk_lo hk_hi.
  split.
  - apply linear_invariant => //.
    smt(kmax_ge0).
  - apply dr_rep_A => //.
    smt().
qed.

lemma sample_basic_equiv (N : int) :
  162 < N =>
  equiv [MRSRep.sample_basic ~ MRSRep.sample_basic : ={arg} ==> ={res}].
proof.
  move=> hN.
  proc.
  seq 1 1 : (={kvl}).
  - rnd; auto.
  - auto.
qed.

lemma sample_triangle_correct (N : int) :
  162 < N =>
  hoare [MRSRep.sample_triangle :
    arg = N ==>
    (fst res = 0 /\ snd res = 0) \/
    (19 * (fst res) + 9 * (snd res) = N /\
     dr (fst res) = dr N /\
     dr (snd res) = dr (2 * dr N))].
proof.
  move=> hN.
  proc.
  auto => />.
  move=> &m.
  split.
  - move=> hk0_gt.
    left; split => //.
  - move=> hk0_le t ht_lo ht_hi.
    right.
    have hk_lo : 0 <= (B0 N - dr (2 * dr N) %% 9) %% 9 + 9 * t
      by smt(modz_ge0).
    have hk_hi : (B0 N - dr (2 * dr N) %% 9) %% 9 + 9 * t <= kmax N
      by smt(modz_ge0 kmax_ge0).
    split; first by apply linear_invariant => //; smt().
    split.
    - apply dr_rep_A => //; smt().
    - have hB_pos : 0 < B0 N - 19 * ((B0 N - dr (2 * dr N) %% 9) %% 9 + 9 * t).
        have hBge := B_ge0 N ((B0 N - dr (2 * dr N) %% 9) %% 9 + 9 * t) hN.
        smt(B_ge0 a0_range).
      apply dr_triangle_B => //.
      + smt().
      + have Heq2 : 19 * (9 * t) %% 9 = 0.
          have Heq3 : 19 * (9 * t) = 9 * (19 * t) by ring.
          by rewrite Heq3 modzMl.
        smt(modzDl modzNm modzMml modz_mod).
      + exact hB_pos.
qed.

lemma sample_triangle_equiv (N : int) :
  162 < N =>
  equiv [MRSRep.sample_triangle ~ MRSRep.sample_triangle : ={arg} ==> ={res}].
proof.
  move=> hN.
  proc.
  seq 7 7 : (={anc, bcp, kbn, ddr, dmod, kbs, tbn}).
  - auto.
  if => />.
  - auto.
  - seq 1 1 : (={ndx, tbn, anc, bcp, kbs}).
    + auto.
    + seq 1 1 : (={kvl, ndx, tbn, anc, bcp, kbs}).
      * rnd; auto.
      * auto.
qed.
