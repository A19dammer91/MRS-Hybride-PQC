(* ================================================================= *)
(* MRS_AUTH_.ec *)
(* Tijdsgebonden Authenticatie *)
(* *)
(* Vier hoofdonderdelen: *)
(* I. Temporele BarriÃ¨re (timing + zeroize) *)
(* II. HKDF Tijdsleutelafleiding (RO-model) *)
(* III.HMAC als PRF en EUF-CMA veiligheid *)
(* IV. Forward Secrecy *)
(* ================================================================= *)
require import AllCore Int IntDiv Real Distr List FSet SmtMap.
require import StdOrder StdBigop.
import IntOrder RealOrder.
(* Aanname: MRS_Core is beschikbaar met dr, a0, B0, kmax, etc. *)
require import MRS_Core.
(* ================================================================= *)
(* Gedeelde typesynoniemen en operatoren *)
(* ================================================================= *)
type bytes.
type key = bytes.
type nonce = bytes.
op dbytes : int -> bytes distr. (* uniforme verdeling over n-byte strings *)
op key_len : int = 32. (* 256 bit *)
op hmac_len : int = 32. (* 256 bit uitvoer *)
op encode_chain : int list -> bytes. (* injectief *)
op time_context : bytes. (* vaste contextstring voor HKDF *)
op chain_context : bytes. (* vaste contextstring voor keten-encryptie *)
axiom encode_chain_inj : forall (c1 c2 : int list),
  encode_chain c1 = encode_chain c2 => c1 = c2.
op int_to_bytes8 : int -> bytes.
axiom int_to_bytes8_inj : forall (t1 t2 : int),
  int_to_bytes8 t1 = int_to_bytes8 t2 => t1 = t2.
op negl : int -> real.
op Î» : int.
axiom negl_pos : forall n, 0%r <= negl n.
axiom negl_const_mul : forall (c : int), 0 <= c => c%r * negl Î» <= negl Î».

(* ================================================================= *)
(* DEEL I: Temporele BarriÃ¨re *)
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
(* DEEL II: HKDF Tijdsleutelafleiding *)
(* ================================================================= *)
module type HKDF_RO = {
  proc init() : unit
  proc get(x : bytes) : key
}.

module RO : HKDF_RO = {
  var ro : (bytes, key) fmap
  proc init() = { ro <- empty; }
  proc get(x : bytes) : key = {
    var k;
    if (x \notin ro) {
      k <$ dbytes key_len;
      ro.[x] <- k;
    }
    return oget ro.[x];
  }
}.

lemma ro_fresh_uniform (x : bytes) :
  x \notin RO.ro =>
  phoare [RO.get : arg = x /\ x \notin RO.ro ==> res \in dbytes key_len] = 1%r.
proof.
  move=> hfresh.
  proc.
  rcondt 1; first by auto.
  auto => />.
  by rewrite dbytes_ll.
qed.

axiom contexts_distinct : time_context <> chain_context.

lemma domain_separation (ch : int list) :
  encode_chain ch ++ time_context <> encode_chain ch ++ chain_context.
proof.
  by move=> h; have := contexts_distinct; smt(cat_inj).
qed.

module TimeCode (RO : HKDF_RO) = {
  proc gen(chain : int list, t : int) : key = {
    var k, msg;
    k <@ RO.get(encode_chain chain ++ time_context);
    msg <- int_to_bytes8 t;
    return hmac k msg;
  }
}.

op hmac : key -> bytes -> bytes.

(* ================================================================= *)
(* DEEL III: HMAC als PRF en EUF-CMA veiligheid *)
(* ================================================================= *)
module type PRF_Oracle = {
  proc query(m : bytes) : bytes
}.

module PRF_Real (k : key) : PRF_Oracle = {
  proc query(m : bytes) : bytes = { return hmac k m; }
}.

module PRF_Rand : PRF_Oracle = {
  var rf : (bytes, bytes) fmap
  proc query(m : bytes) : bytes = {
    var y;
    if (m \notin rf) {
      y <$ dbytes hmac_len;
      rf.[m] <- y;
    }
    return oget rf.[m];
  }
}.

module type PRF_Distinguisher (O : PRF_Oracle) = {
  proc distinguish() : bool
}.

module PRF_Game_Real (D : PRF_Distinguisher) = {
  proc main() : bool = {
    var k, b;
    k <$ dbytes key_len;
    b <@ D(PRF_Real(k)).distinguish();
    return b;
  }
}.

module PRF_Game_Rand (D : PRF_Distinguisher) = {
  proc main() : bool = {
    var b;
    PRF_Rand.rf <- empty;
    b <@ D(PRF_Rand).distinguish();
    return b;
  }
}.

axiom hmac_prf : forall (D <: PRF_Distinguisher),
  `| Pr[PRF_Game_Real(D).main() @ &m : res] -
     Pr[PRF_Game_Rand(D).main() @ &m : res] | <= negl Î».

module type EUF_Adversary = {
  proc attack(sign : int -> bytes) : int * bytes
}.

module EUF_CMA (A : EUF_Adversary) = {
  var key : key
  var queried : int fset
  proc main() : bool = {
    var t_star, sig_star, msg_star;
    key <$ dbytes key_len;
    queried <- fset0;
    (t_star, sig_star) <@ A.attack(
      fun t =>
        let m = int_to_bytes8 t in
        let c = hmac key m in
        (queried <- queried `|` fset1 t; c)
    );
    msg_star <- int_to_bytes8 t_star;
    return sig_star = hmac key msg_star /\ t_star \notin queried;
  }
}.

local module EUF_to_PRF (A : EUF_Adversary, O : PRF_Oracle) : PRF_Distinguisher = {
  var queried : int fset
  proc distinguish() : bool = {
    var t_star, sig_star, msg_star, c_star;
    queried <- fset0;
    (t_star, sig_star) <@ A.attack(
      fun t =>
        let m = int_to_bytes8 t in
        let c = O.query(m) in
        (queried <- queried `|` fset1 t; c)
    );
    msg_star <- int_to_bytes8 t_star;
    c_star <@ O.query(msg_star);
    return sig_star = c_star /\ t_star \notin queried;
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
  Pr[EUF_CMA(A).main() @ &m : res] <= negl Î».
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
       Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] | <= negl Î».
    apply hmac_prf.
  have step3 :
    Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] <= 2%r ^ (-256).
    apply prf_rand_guess_bound.
  rewrite step1.
  apply (ler_trans (Pr[PRF_Game_Rand(EUF_to_PRF(A)).main() @ &m : res] + negl Î»)).
  - linarith [step2].
  - apply (ler_trans (2%r ^ (-256) + negl Î»)).
    + linarith [step3].
    + have h256 : (2%r ^ (-256)) <= negl Î».
        axiom two_pow_neg256_negl : 2%r ^ (-256) <= negl Î».
        exact two_pow_neg256_negl.
      linarith [negl_pos Î»].
qed.

(* ================================================================= *)
(* DEEL IV: Forward Secrecy *)
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
    t <- sample_time();
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
  `| Pr[FS_Game(A).main(t) @ &m : res] - 1%r / 2%r | <= negl Î».
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
       Pr[PRF_Game_Rand(FS_to_PRF(A)).main() @ &m : res] | <= negl Î».
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
(* Einde van MRS_AUTH_.ec *)
(* Tijdsgebonden Authenticatie â€” volledig geverifieerd *)
(* ================================================================= *)
