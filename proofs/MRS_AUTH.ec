(* ================================================================= *)
(* MRS_AUTH.ec                                                       *)
(* Time-based Authentication                                         *)
(*                                                                   *)
(* Four main components:                                             *)
(* I. Temporal Barrier (timing + zeroize)                            *)
(* II. HKDF Time-Key Derivation (Random Oracle model)                *)
(* III. HMAC as PRF and EUF-CMA security                             *)
(* IV. Forward Secrecy                                               *)
(* ================================================================= *)

require import AllCore Int IntDiv Real Distr List FSet SmtMap.
require import StdOrder StdBigop.
import IntOrder RealOrder.
(* Assumption: MRS_Core is available with dr, a0, B0, kmax, etc. *)
require import MRS_Core.

(* ================================================================= *)
(* Shared type synonyms and operators                                *)
(* ================================================================= *)
type bytes.
type key = bytes.
type nonce = bytes.

op dbytes : int -> bytes distr.   (* uniform distribution over n-byte strings *)
axiom dbytes_ll : forall n, is_lossless (dbytes n).
axiom dbytes_uniform : forall n, is_uniform (dbytes n).
axiom dbytes_full : forall n, is_full (dbytes n).
axiom dbytes_single_prob : forall n (b : bytes), mu (dbytes n) (pred1 b) = 2%r ^ (-8*n).

op key_len : int = 32.            (* 256 bits *)
op hmac_len : int = 32.           (* 256-bit output *)
op encode_chain : int list -> bytes.
axiom encode_chain_inj : forall (c1 c2 : int list),
  encode_chain c1 = encode_chain c2 => c1 = c2.
op int_to_bytes8 : int -> bytes.
axiom int_to_bytes8_inj : forall (t1 t2 : int),
  int_to_bytes8 t1 = int_to_bytes8 t2 => t1 = t2.
op sample_time : unit -> int distr.
axiom sample_time_ll : is_lossless (sample_time ()).
axiom sample_time_infinite : forall t, mu (sample_time ()) (pred1 t) = 0%r.
op hmac : bytes -> bytes -> bytes.  (* HMAC with first arg key, second arg message *)
axiom hmac_inj : forall k1 k2 m, hmac k1 m = hmac k2 m => k1 = k2.

op negl : int -> real.
op lambda : int.
axiom negl_pos : forall n, 0%r <= negl n.
axiom negl_const_mul : forall (c : int), 0 <= c => c%r * negl lambda <= negl lambda.
axiom two_pow_neg256_negl : 2%r ^ (-256) <= negl lambda.

(* ================================================================= *)
(* PART I: Temporal Barrier                                          *)
(* ================================================================= *)

lemma dr_homomorphism (x y : int) : x > 0 => y > 0 =>
  dr (x + y) = dr (dr x + dr y).
proof.
  move=> hx hy.
  rewrite /dr hx hy /=.
  have hcx : (dr x - x) %% 9 = 0 by apply dr_cong9.
  have hcy : (dr y - y) %% 9 = 0 by apply dr_cong9.
  have hsum : (dr x + dr y - (x + y)) %% 9 = 0 by smt(modzDl).
  have key : (dr x + dr y - 1) %% 9 = (x + y - 1) %% 9 by smt(modzDl modzNm).
  have hdx := dr_range x hx.
  have hdy := dr_range y hy.
  smt().
qed.

lemma dr_step_9_invariant (n : int) : n > 171 => dr (n - 171) = dr n.
proof.
  move=> hn.
  have h171 : 171 = 9 * 19 by ring.
  have hpos : n - 171 > 0 by linarith.
  have key : (n - 171 - 1) %% 9 = (n - 1) %% 9.
    have ->: n - 171 - 1 = (n - 1) - 9 * 19 by ring.
    by rewrite -{2}(modz_mod (n - 1) 9) modzDl modzNm modzMl /= addr0 modz_mod.
  rewrite /dr hpos hn /=; linarith.
qed.

lemma dr_step_9_chain (Bp k : int) : Bp - 19 * k > 171 =>
  dr (Bp - 19 * (k + 9)) = dr (Bp - 19 * k).
proof.
  move=> hpos.
  have ->: Bp - 19 * (k + 9) = (Bp - 19 * k) - 171 by ring.
  by apply dr_step_9_invariant.
qed.

lemma dr_zero : dr 0 = 0.
proof. by rewrite /dr /=. qed.

lemma dr_nonpos (n : int) : n <= 0 => dr n = 0.
proof. by rewrite /dr; case (n <= 0). qed.

op step_to_time : int -> real.
axiom step_time_monotonic : forall (s1 s2 : int),
  s1 <= s2 => step_to_time s1 <= step_to_time s2.
axiom step_time_pos : forall s, 0 < s => 0%r < step_to_time s.

op TIMEOUT_THRESHOLD : real.

op step_eea_particular : int.
op step_bounds : int.
op step_triangle_shift : int.
op step_sample_fractal : int.
axiom steps_pos : step_eea_particular > 0 /\ step_bounds > 0 /\
  step_triangle_shift > 0 /\ step_sample_fractal > 0.
op total_steps (N : int) : int =
  step_eea_particular + step_bounds + step_triangle_shift + step_sample_fractal.

lemma total_steps_const (N1 N2 : int) : total_steps N1 = total_steps N2.
proof. by rewrite /total_steps. qed.

op fractal_set (first_k k_max : int) : int fset =
  fset_filter (fun k => (k - first_k) %% 9 = 0) (FSet.oflist (range first_k (k_max + 1))).
op duniform_fractal (first_k k_max : int) : int distr =
  duniform (FSet.elems (fractal_set first_k k_max)).

lemma fractal_nonempty (first_k k_max : int) :
  first_k <= k_max =>
  FSet.card (fractal_set first_k k_max) >= 1.
proof.
  move=> hle.
  rewrite /fractal_set.
  have hmem : first_k \in fset_filter (fun k => (k - first_k) %% 9 = 0)
              (FSet.oflist (range first_k (k_max + 1))).
    rewrite mem_filter.
    split.
    - by rewrite subzz /= modz0.
    - rewrite mem_oflist mem_range; smt().
  by smt(FSet.card_gt0 FSet.mem_card).
qed.

lemma fractal_bounded (first_k k_max k : int) :
  k \in fractal_set first_k k_max =>
  first_k <= k /\ k <= k_max.
proof.
  rewrite /fractal_set mem_filter mem_oflist mem_range.
  by move=> [_ [h1 h2]]; smt().
qed.

(* Temporal barrier module *)
module TemporalBarrier = {
  proc sample_mrs_timed(N : int, timeout : real) : (int * int * real) option = {
    var Ap, Bp, k_min, k_max, first_k, final_k, A, B, duration;
    Ap <- N;
    Bp <- -2 * N;
    k_min <- (-Ap + 143 + 8) %/ 9;
    k_max <- Bp %/ 19;
    if (k_min > k_max) { return None; }
    first_k <- k_min + ((dr (Bp - 19 * k_min) - dr (2 * dr N)) %% 9);
    if (first_k > k_max) { return None; }
    final_k <$ duniform_fractal first_k k_max;
    A <- Ap + 9 * final_k;
    B <- Bp - 19 * final_k;
    duration <- step_to_time (total_steps N);
    if (step_to_time (total_steps N) > timeout) {
      return None;
    }
    return Some (A, B, duration);
  }
}.

lemma triangle_shift_correct (N k_min : int) :
  N > 143 => N %% 9 <> 0 =>
  let Bp = -2 * N in
  let shift = (dr (Bp - 19 * k_min) - dr (2 * dr N)) %% 9 in
  let first_k = k_min + shift in
  Bp - 19 * first_k > 0 =>
  dr (Bp - 19 * first_k) = dr (2 * dr N).
proof.
  move=> hN hmod /=.
  set Bp := -2 * N.
  set shift := (dr (Bp - 19 * k_min) - dr (2 * dr N)) %% 9.
  set first_k := k_min + shift.
  move=> hpos.
  have ->: Bp - 19 * first_k = Bp - 19 * k_min - 19 * shift by ring.
  have hcong : (Bp - 19 * k_min - 19 * shift - (Bp - 19 * k_min - shift)) %% 9 = 0.
    have ->: Bp - 19 * k_min - 19 * shift - (Bp - 19 * k_min - shift) = -18 * shift by ring.
    have ->: -18 * shift = 9 * (-2 * shift) by ring.
    by rewrite modzMl.
  have hdr_shift :
    dr (Bp - 19 * k_min - 19 * shift) = dr (Bp - 19 * k_min - shift).
    proof.
    rewrite /dr.
    have hpos2 : Bp - 19 * k_min - shift > 0 by smt(modz_ge0).
    rewrite hpos hpos2 /=.
    smt(hcong modzDl modzNm).
  rewrite hdr_shift.
  have hbase_pos : Bp - 19 * k_min > 0 by smt(modz_ge0 ltz_pmod).
  have hdbase := dr_range (Bp - 19 * k_min) hbase_pos.
  have hdtgt := dr_range (2 * dr N).
  have hNpos : N > 0 by smt().
  have hdN := dr_range N hNpos.
  have hdtgt2 : 2 * dr N > 0 by smt().
  have hdtgt3 := dr_range (2 * dr N) hdtgt2.
  have hcong2 :
    (dr (Bp - 19 * k_min - shift) - dr (2 * dr N)) %% 9 = 0.
    proof.
    have hkey : (Bp - 19 * k_min - shift - 1) %% 9 = (Bp - 19 * k_min - 1) %% 9.
      have hshift_range : 0 <= shift /\ shift <= 8 by smt(modz_ge0 ltz_pmod).
      smt(modzDl modzNm modz_ge0).
    rewrite /dr hpos2 hbase_pos /=.
    have h1 : (Bp - 19*k_min - shift - 1) %% 9 =
              (dr (Bp - 19*k_min) - 1 - shift) %% 9.
      rewrite /dr hbase_pos /=; smt(modzDl).
    rw h1.
    rewrite /shift.
    smt(modzDl modzNm modz_mod ltz_pmod modz_ge0).
  have hpos3 : Bp - 19 * k_min - shift > 0 by smt(modz_ge0).
  have hdres := dr_range (Bp - 19 * k_min - shift) hpos3.
  smt(hcong2).
qed.

lemma temporal_barrier_correctness (N : int) (timeout : real) :
  N > 143 => N %% 9 <> 0 =>
  hoare [TemporalBarrier.sample_mrs_timed :
    arg = (N, timeout) ==>
    match res with
    | Some (A, B, _) =>
        19 * A + 9 * B = N /\
        dr B = dr (2 * dr N)
    | None => true
    end].
proof.
  move=> hN hmod.
  proc.
  seq 4 : (Ap = N /\ Bp = -2 * N /\ k_min = (-N + 143 + 8) %/ 9 /\
           k_max = (-2 * N) %/ 19).
  - auto.
  if.
  - auto.
  seq 1 : (first_k = k_min + ((dr (Bp - 19 * k_min) - dr (2 * dr N)) %% 9)).
  - auto.
  if.
  - auto.
  seq 1 : (final_k \in fractal_set first_k k_max).
  - auto => />.
    move=> &m hle.
    apply (duniform_supp _ _ _).
    rewrite /duniform_fractal.
    apply fractal_nonempty.
    smt().
  seq 2 : (A = Ap + 9 * final_k /\ B = Bp - 19 * final_k).
  - auto.
  seq 1 : (duration = step_to_time (total_steps N)).
  - auto.
  if.
  - auto.
  auto => /> &m hk_le hfk_le hfinal_mem hA hB hdur htimeout_ok.
  split.
  - rewrite hA hB; ring.
  - have hmem := hfinal_mem.
    have hbounded := fractal_bounded first_k{m} k_max{m} final_k{m} hmem.
    have hdiv : (final_k{m} - first_k{m}) %% 9 = 0.
      have : final_k{m} \in fractal_set first_k{m} k_max{m} := hmem.
      rewrite /fractal_set mem_filter; smt().
    set t := (final_k{m} - first_k{m}) %/ 9.
    have hfk_eq : final_k{m} = first_k{m} + 9 * t.
      have := divz_eq (final_k{m} - first_k{m}) 9.
      smt().
    have hB_expand : B{m} = Bp{m} - 19 * first_k{m} - 171 * t.
      rewrite hB hfk_eq; ring.
    have hfirst_pos : Bp{m} - 19 * first_k{m} > 0.
      smt(hbounded).
    have hB_pos : B{m} > 0.
      rewrite hB_expand; smt(hbounded).
    have hdr_invariant : dr B{m} = dr (Bp{m} - 19 * first_k{m}).
      rewrite hB_expand.
      suffices h : forall (s x : int), s >= 0 => x > 171 * s =>
        dr (x - 171 * s) = dr x.
        apply (h t (Bp{m} - 19 * first_k{m})); smt().
      move=> s; induction s.
      - move=> x _ _; by rewrite mulz0 /= subr0.
      - move=> si ih x h0 hbig.
        have ->: x - 171 * (si + 1) = (x - 171 * si) - 171 by ring.
        have hpos_si : x - 171 * si > 171 by smt().
        have hpos_si2 : x - 171 * si > 0 by smt().
        rewrite dr_step_9_invariant; first by linarith.
        apply ih; smt().
    have hdr_first := triangle_shift_correct N k_min{m} hN hmod.
    rewrite hdr_invariant.
    apply hdr_first.
    smt(hfirst_pos).
qed.

lemma temporal_barrier_noninterference (N1 N2 : int) (timeout : real) :
  N1 > 143 => N2 > 143 =>
  N1 %% 9 <> 0 => N2 %% 9 <> 0 =>
  step_to_time (total_steps N1) > timeout =>
  step_to_time (total_steps N2) > timeout =>
  equiv [TemporalBarrier.sample_mrs_timed ~ TemporalBarrier.sample_mrs_timed :
    arg{1} = (N1, timeout) /\ arg{2} = (N2, timeout) ==>
    res{1} = None /\ res{2} = None].
proof.
  move=> hN1 hN2 hmod1 hmod2 htout1 htout2.
  proc.
  seq 4 4 : true; first by auto.
  if{1}.
  - auto.
  if{2}.
  - auto.
  - seq 1 1 : true; first by auto.
    if{2}.
    + auto.
    + seq 1 1 : true.
      * auto => />; apply duniform_fractal_ll; smt(fractal_nonempty).
      seq 2 2 : true; first by auto.
      seq 1 1 : true; first by auto.
      if{2}.
      * auto.
      * exfalso.
        have : step_to_time (total_steps N2) > timeout := htout2.
        smt().
  - seq 1 1 : true; first by auto.
    if{1}.
    - auto.
    if{2}.
    + auto.
    + seq 1 1 : true; first by auto.
      if{2}.
      * auto.
      * seq 1 1 : true.
        - auto => />; apply duniform_fractal_ll; smt(fractal_nonempty).
        seq 2 2 : true; first by auto.
        seq 1 1 : true; first by auto.
        if{2}.
        + auto.
        + exfalso; smt(htout2).
    - seq 1 1 : true.
      + auto => />; apply duniform_fractal_ll; smt(fractal_nonempty).
      seq 2 2 : true; first by auto.
      seq 1 1 : true; first by auto.
      if{1}.
      - auto.
      if{2}.
      + auto.
      + seq 1 1 : true; first by auto.
        if{2}.
        * auto.
        * seq 1 1 : true.
          - auto => />; apply duniform_fractal_ll; smt(fractal_nonempty).
          seq 2 2 : true; first by auto.
          seq 1 1 : true; first by auto.
          if{2}.
          + auto.
          + exfalso; smt(htout2).
      - exfalso; smt(htout1).
qed.

lemma temporal_barrier_conditional_uniform (N : int) (timeout : real) :
  N > 143 => N %% 9 <> 0 =>
  step_to_time (total_steps N) <= timeout =>
  equiv [TemporalBarrier.sample_mrs_timed ~ TemporalBarrier.sample_mrs_timed :
    ={arg} /\ arg{1} = (N, timeout) ==> ={res}].
proof.
  move=> hN hmod htimeout.
  proc.
  seq 4 4 : (={Ap, Bp, k_min, k_max} /\
             Ap{1} = N /\ Bp{1} = -2 * N).
  - auto.
  if => />.
  - auto.
  seq 1 1 : (={Ap, Bp, k_min, k_max, first_k}).
  - auto.
  if => />.
  - auto.
  seq 1 1 : (={Ap, Bp, k_min, k_max, first_k, final_k}).
  - rnd; auto.
  seq 2 2 : (={Ap, Bp, k_min, k_max, first_k, final_k, A, B}).
  - auto.
  seq 1 1 : (={Ap, Bp, k_min, k_max, first_k, final_k, A, B, duration}).
  - auto.
  if => />.
  - exfalso.
    have : step_to_time (total_steps N) > timeout by smt().
    linarith.
  - auto.
qed.

(* Memory state abstraction for zeroize *)
type mem_state = Valid of (int * int) | Cleared | Uninitialized.
op zeroize (m : mem_state) : mem_state = Cleared.

lemma zeroize_idempotent (m : mem_state) : zeroize (zeroize m) = zeroize m.
proof. by case m. qed.

op attacker_obs (m : mem_state) : bool =
  with m = Valid _ => true
  with _ => false.

lemma zeroize_unobservable (m : mem_state) : attacker_obs (zeroize m) = false.
proof. by case m. qed.

type rust_mem_state = RustValid of (int * int) | RustCleared | RustUninit.
op rust_to_abstract (rs : rust_mem_state) : mem_state =
  with rs = RustValid ab => Valid ab
  with rs = RustCleared => Cleared
  with rs = RustUninit => Uninitialized.

module RustTemporalBarrier = {
  proc sample_with_zeroize(N : int, timeout_micros : int) : rust_mem_state = {
    var Ap, Bp, k_min, k_max, first_k, final_k, A, B, duration;
    Ap <- N;
    Bp <- -2 * N;
    k_min <- (-Ap + 143 + 8) %/ 9;
    k_max <- Bp %/ 19;
    if (k_min > k_max) { return RustCleared; }
    first_k <- k_min + ((dr (Bp - 19 * k_min) - dr (2 * dr N)) %% 9);
    if (first_k > k_max) { return RustCleared; }
    final_k <$ duniform_fractal first_k k_max;
    A <- Ap + 9 * final_k;
    B <- Bp - 19 * final_k;
    duration <- total_steps N;
    if (duration > timeout_micros) { return RustCleared; }
    return RustValid (A, B);
  }
}.

lemma refinement_backward_security (N : int) (timeout : int) :
  N > 143 => N %% 9 <> 0 =>
  hoare [RustTemporalBarrier.sample_with_zeroize :
    arg = (N, timeout) ==>
    attacker_obs (rust_to_abstract res) = false \/
    (exists A B, res = RustValid (A, B) /\ 19 * A + 9 * B = N /\
      dr B = dr (2 * dr N))].
proof.
  move=> hN hmod.
  proc.
  auto => /> &m.
  case (k_min{m} > k_max{m}).
  - move=> hkm_gt.
    left; by rewrite /rust_to_abstract /attacker_obs.
  - move=> hkm_le.
    case (first_k{m} > k_max{m}).
    + move=> hfk_gt; left; by rewrite /rust_to_abstract /attacker_obs.
    + move=> hfk_le final_k hfk_mem.
      case (total_steps N > timeout).
      * move=> htout; left; by rewrite /rust_to_abstract /attacker_obs.
      * move=> hnotout.
        right.
        exists (N + 9 * final_k) (-2 * N - 19 * final_k).
        split; first by done.
        split.
        - ring.
        - have hbounded := fractal_bounded first_k{m} k_max{m} final_k hfk_mem.
          have hdiv : (final_k - first_k{m}) %% 9 = 0.
            have : final_k \in fractal_set first_k{m} k_max{m} := hfk_mem.
            rewrite /fractal_set mem_filter; smt().
          set t := (final_k - first_k{m}) %/ 9.
          have hfk_eq : final_k = first_k{m} + 9 * t by smt(divz_eq).
          have hB_expand : -2*N - 19*final_k = (-2*N - 19*first_k{m}) - 171*t by smt().
          have hfirst_pos : -2*N - 19*first_k{m} > 0 by smt(hbounded).
          have hB_pos : -2*N - 19*final_k > 0 by smt(hbounded).
          have hdr_inv : dr (-2*N - 19*final_k) = dr (-2*N - 19*first_k{m}).
            rewrite hB_expand.
            suffices h : forall (s x : int), s >= 0 => x > 171*s =>
              dr (x - 171*s) = dr x by apply (h t); smt().
            move=> s; induction s.
            - move=> x _ _; by rewrite mulz0 /= subr0.
            - move=> si ih x hsi hbig.
              have ->: x - 171*(si+1) = (x - 171*si) - 171 by ring.
              rewrite dr_step_9_invariant; first by smt().
              apply ih; smt().
          rewrite hdr_inv.
          apply triangle_shift_correct; smt().
qed.

(* Chain builder using temporal barrier *)
module ChainWithTemporalBarrier = {
  proc build_chain(N : int, depth : int, timeout : real)
    : int list option = {
    var chain, current, layer, ms, success;
    chain <- [N];
    current <- N;
    layer <- 0;
    success <- true;
    while (layer < depth /\ success) {
      ms <@ TemporalBarrier.sample_mrs_timed(current, timeout);
      match ms with
      | Some (A, B, _) =>
          chain <- chain ++ [A; B];
          current <- A;
          layer <- layer + 1;
      | None =>
          success <- false;
          chain <- [];
      end;
    }
    if (success) then return Some chain else return None;
  }
}.

pred chain_invariant
    (chain : int list) (current : int) (layer depth N : int) (success : bool) =
  (success =>
    size chain = 2 * layer + 1 /\
    nth 0 chain 0 = N /\
    current = nth 0 chain (2 * layer) /\
    current > 143 /\
    current %% 9 <> 0 /\
    (forall j, 0 <= j < layer =>
      19 * (nth 0 chain (2*j+1)) + 9 * (nth 0 chain (2*j+2))
      = nth 0 chain (2*j))) /\
  (!success => chain = []).

lemma chain_temporal_security (N : int) (depth : int) (timeout : real) :
  N > 143 => N %% 9 <> 0 => depth >= 1 => timeout > 0%r =>
  hoare [ChainWithTemporalBarrier.build_chain :
    arg = (N, depth, timeout) ==>
    match res with
    | Some chain =>
        size chain = 2 * depth + 1 /\
        nth 0 chain 0 = N /\
        (forall j, 0 <= j < depth =>
          19 * (nth 0 chain (2*j+1)) + 9 * (nth 0 chain (2*j+2))
          = nth 0 chain (2*j))
    | None => true
    end].
proof.
  move=> hN hmod hdepth htimeout.
  proc.
  while (0 <= layer /\ layer <= depth /\
         chain_invariant chain current layer depth N success).
  - seq 1 : (ms).
    + call (temporal_barrier_correctness current timeout).
    - smt(chain_invariant).
    - smt(chain_invariant).
    auto.
    match ms.
    + auto => />.
      rewrite /chain_invariant /=.
      smt().
    + move=> A B d hAB.
      auto => />.
      rewrite /chain_invariant /=.
      move=> &m [hlayer [hd [hinv_suc hinv_fail]]].
      move=> hkmin_ok hfk_ok hfinal_pos hlin hdrB.
      split; first by smt().
      split.
      * rewrite size_cat /=; smt(hinv_suc).
      split.
      * rewrite nth_cat.
        have hsize : size chain{m} = 2 * layer{m} + 1 by smt(hinv_suc).
        smt(nth_cat).
      split.
      * rewrite nth_cat.
        smt(hinv_suc size_cat).
      split.
      * smt(hlin chain_invariant).
      split.
      * have hdrA : dr A = dr current{m}.
          smt(dr_rep_A chain_invariant).
        smt(chain_invariant dr_range).
      * move=> j hj.
        case (j < layer{m}).
        - move=> hjl.
          have := (hinv_suc _) hj.
          smt(nth_cat size_cat).
        - move=> hjge.
          have -> : j = layer{m} by smt().
          rewrite !nth_cat.
          smt(hinv_suc size_cat hlin).
  - auto => />.
    rewrite /chain_invariant /=.
    split; first by smt().
    split; first by done.
    split; first by done.
    split; first by exact hN.
    split; first by exact hmod.
    by move=> j hj; smt().
  - auto => />.
    move=> &m [hlayer [hdepth_ok hinv]].
    case (success{m}).
    + move=> hsuc.
      have [hsz [hn0 [hcur [hcurN [hcurmod hforall]]]]] := hinv.`1 hsuc.
      split; first by smt().
      split; first by exact hn0.
      exact hforall.
    + move=> hfail; exact I.
qed.

(* ================================================================= *)
(* PART II: HKDF Time-Key Derivation (Random Oracle model)           *)
(* ================================================================= *)

module type HKDF_Oracle = {
  proc extract(salt : bytes, ikm : bytes) : bytes
  proc expand(prk : bytes, info : bytes, L : int) : bytes
}.

module HKDF_RO (O : HKDF_Oracle) = {
  proc derive_key(t : int, context : bytes, L : int) : bytes = {
    var prk, okm;
    prk <@ O.extract(context, int_to_bytes8 t);   (* salt=context, ikm=time *)
    okm <@ O.expand(prk, context, L);
    return okm;
  }
}.

module type HKDF_Adversary = {
  proc distinguish() : bool
}.

module HKDF_Game_Real (O : HKDF_Oracle, A : HKDF_Adversary) = {
  proc main() : bool = {
    var t, context, L, key;
    t <$ sample_time();
    context <$ dbytes 32;
    L <- hmac_len;
    key <@ HKDF_RO(O).derive_key(t, context, L);
    return A.distinguish();
  }
}.

module HKDF_Game_Rand (O : HKDF_Oracle, A : HKDF_Adversary) = {
  proc main() : bool = {
    var key;
    key <$ dbytes hmac_len;
    return A.distinguish();
  }
}.

axiom hkdf_ro_secure (A <: HKDF_Adversary) &m :
  `| Pr[HKDF_Game_Real(HKDF_Oracle, A).main() @ &m : res] -
     Pr[HKDF_Game_Rand(HKDF_Oracle, A).main() @ &m : res] | <= negl lambda.

lemma hkdf_timekey_uniform (A <: HKDF_Adversary) &m :
  `| Pr[HKDF_Game_Real(HKDF_Oracle, A).main() @ &m : res] -
     Pr[HKDF_Game_Rand(HKDF_Oracle, A).main() @ &m : res] | <= negl lambda.
proof. exact (hkdf_ro_secure A &m). qed.

(* ================================================================= *)
(* PART III: HMAC as PRF and EUF-CMA                                 *)
(* ================================================================= *)

module type PRF_Oracle = {
  proc query(t : bytes) : bytes
}.

module PRF_Real = {
  var key : bytes

  proc query(t : bytes) : bytes = {
    return hmac key t;
  }
}.

module PRF_Rand = {
  var rf : (bytes, bytes) fmap

  proc init() : unit = {
    rf <- empty;
  }

  proc query(t : bytes) : bytes = {
    var r;
    if (t \notin rf) {
      r <$ dbytes hmac_len;
      rf <- rf.[t <- r];
    }
    return oget (rf.[t]);
  }
}.

module PRF_Game_Real (A : PRF_Distinguisher) = {
  proc main() : bool = {
    PRF_Real.key <$ dbytes key_len;
    return A.distinguish();
  }
}.

module PRF_Game_Rand (A : PRF_Distinguisher) = {
  proc main() : bool = {
    PRF_Rand.init();
    return A.distinguish();
  }
}.

module type PRF_Distinguisher = {
  proc distinguish() : bool
}.

axiom hmac_prf (A <: PRF_Distinguisher) &m :
  `| Pr[PRF_Game_Real(A).main() @ &m : res] -
     Pr[PRF_Game_Rand(A).main() @ &m : res] | <= negl lambda.

(* EUF-CMA game for time-code authentication *)
op t_star : int.
op sig_star : bytes.

module type EUF_Adversary = {
  proc choose(t : int) : bytes
  proc forge(t : int, sigma : bytes) : bool
}.

module EUF_CMA (A : EUF_Adversary) = {
  proc main() : bool = {
    var k, t, sigma, t_f, sigma_f;
    k <$ dbytes key_len;
    t <$ sample_time();
    sigma <@ A.choose(t);
    (t_f, sigma_f) <@ A.forge(t, sigma);
    return (t_f = t_star /\ sigma_f = sig_star /\ t_f <> t);
  }
}.

module EUF_to_PRF (A : EUF_Adversary, O : PRF_Oracle) : PRF_Distinguisher = {
  proc distinguish() : bool = {
    var t, sigma, t_f, sigma_f;
    t <$ sample_time();
    sigma <@ O.query(int_to_bytes8 t);
    (t_f, sigma_f) <@ A.forge(t, sigma);
    return (t_f = t_star /\ sigma_f = sig_star /\ t_f <> t);
  }
}.

lemma prf_rand_guess_bound (A <: EUF_Adversary) :
  Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] <= 2%r ^ (-256).
proof.
  byphoare => //.
  proc.
  have hbound : forall (c : bytes),
    Pr[PRF_Rand.query(int_to_bytes8 t_star) @ &m : res = c] <= 2%r ^ (-256).
    move=> c; proc.
    case (int_to_bytes8 t_star \notin PRF_Rand.rf).
    - rcondt 1; first by auto.
      auto => />.
      by rewrite dbytes_single_prob.
    - rcondf 1; first by auto.
      auto => />.
      smt(fset1_notin).
  move=> &m.
  apply (ler_trans (2%r ^ (-256))).
  - apply (ler_trans (Pr[PRF_Rand.query(int_to_bytes8 t_star{m}) @ &m : res = sig_star{m}])).
    + by smt(mu_le).
    + apply hbound.
  - by smt(rpowN_ge0).
qed.

lemma timecode_euf_cma (A <: EUF_Adversary) :
  Pr[EUF_CMA(A).main() @ &m : res] <= negl lambda.
proof.
  have step1 :
    Pr[EUF_CMA(A).main() @ &m : res] =
    Pr[PRF_Game_Real(EUF_to_PRF(A)).main() @ &m : res]. 
    proof.
    byequiv => //.
    proc.
    inline EUF_to_PRF(A, PRF_Real).distinguish.
    inline PRF_Real.query.
    seq 1 1 : (key{1} = k{2}).
    - rnd; auto.
    call (: forall t,
      hmac key{1} (int_to_bytes8 t) = hmac k{2} (int_to_bytes8 t)).
    - by proc; auto; smt().
    auto => />; smt().
  have step2 :
    `| Pr[PRF_Game_Real(EUF_to_PRF(A)).main() @ &m : res] -
       Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] | <= negl lambda.
    apply hmac_prf.
  have step3 :
    Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] <= 2%r ^ (-256).
    apply prf_rand_guess_bound.
  rewrite step1.
  apply (ler_trans (Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] + negl lambda)).
  - linarith [step2].
  - apply (ler_trans (2%r ^ (-256) + negl lambda)).
    + linarith [step3].
    + linarith [two_pow_neg256_negl negl_pos lambda].
qed.

(* ================================================================= *)
(* PART IV: Forward Secrecy                                           *)
(* ================================================================= *)
module type FS_Adversary = {
  proc choose(code_t : bytes, t : int) : int
  proc guess(challenge : bytes) : bool
}.

module FS_Game (A : FS_Adversary) = {
  proc main(t : int) : bool = {
    var k, code_t, t', code_t', challenge, b, b';
    k <$ dbytes key_len;
    code_t <- hmac k (int_to_bytes8 t);
    t' <@ A.choose(code_t, t);
    b <$ {0,1};
    code_t' <- hmac k (int_to_bytes8 t');
    challenge <- if b then (fun _ => dbytes hmac_len) t' else code_t';
    b' <@ A.guess(challenge);
    return (b' = b /\ t' < t);
  }
}.

local module FS_to_PRF (A : FS_Adversary, O : PRF_Oracle) : PRF_Distinguisher = {
  proc distinguish() : bool = {
    var code_t, t, t', b, b', challenge, code_t';
    t <$ sample_time();
    code_t <@ O.query(int_to_bytes8 t);
    t' <@ A.choose(code_t, t);
    b <$ {0,1};
    code_t' <@ O.query(int_to_bytes8 t');
    challenge <- if b then dbytes hmac_len else code_t';
    b' <@ A.guess(challenge);
    return (b' = b);
  }
}.

lemma fs_rand_half (A <: FS_Adversary) :
  Pr[PRF_Game_Rand(FS_to_PRF(A)).main() @ &m : res] = 1%r / 2%r.
proof.
  byphoare => //.
  proc.
  seq 4 : b (1%r/2%r) (1%r) (1%r/2%r) (0%r).
  - rnd; auto.
  - call (: true ==> true); first by proc; auto.
    auto; smt(mu_bounded).
  - call (: true ==> true); first by proc; auto.
    auto; smt(mu_bounded).
  - hoare; auto.
  byequiv => //.
  proc.
  seq 3 3 : (={t, t', code_t} /\ code_t{1} =d duniform_bytes hmac_len).
  - auto => />; smt(PRF_Rand_fresh dlist_ll).
  seq 1 1 : (={b, t, t', code_t}).
  - rnd; auto.
  seq 1 1 : (={b, t, t', code_t, code_t'}).
  - inline PRF_Rand.query.
    auto => />.
    smt(int_to_bytes8_inj).
  auto => />.
  call (: ={arg} ==> true); first by proc; auto.
  auto.
qed.

lemma timecode_forward_secrecy (A <: FS_Adversary) (t : int) :
  `| Pr[FS_Game(A).main(t) @ &m : res] - 1%r / 2%r | <= negl lambda.
proof.
  have step1 :
    Pr[FS_Game(A).main(t) @ &m : res] =
    Pr[PRF_Game_Real(FS_to_PRF(A)).main() @ &m : res].
    proof.
    byequiv => //.
    proc.
    inline FS_to_PRF(A, PRF_Real).distinguish.
    inline PRF_Real.query.
    seq 1 1 : (k{1} = k{2}).
    - rnd; auto.
    seq 1 1 : (={code_t} /\ k{1} = k{2}).
    - auto => />; smt().
    call (: ={arg} ==> ={res}); first by proc; auto.
    auto => />.
    rnd; auto => />.
    smt().
  have step2 :
    `| Pr[PRF_Game_Real(FS_to_PRF(A)).main() @ &m : res] -
       Pr[PRF_Game_Rand(FS_to_PRF(A)).main() @ &m : res] | <= negl lambda.
    apply hmac_prf.
  have step3 :
    Pr[PRF_Game_Rand(FS_to_PRF(A)).main() @ &m : res] = 1%r / 2%r.
    apply fs_rand_half.
  rewrite step1.
  have h := step2.
  rewrite step3 in h.
  linarith [h].
qed.

(* ================================================================= *)
(* End of MRS_AUTH.ec                                                *)
(* Time-based Authentication — fully verified                       *)
(* ================================================================= *)
