(* ================================================================= *)
(*  MRS_Chain.ec                                                      *)
(*  Ketenconstructie en verificatie                                   *)
(* ================================================================= *)

require import MRS_Core.
import MRSRep.

module MRSChain = {
  proc build(N : int, depth : int, tri : int list) : int list = {
    var chain, current, layer, a, b;
    chain   <- [N];
    current <- N;
    layer   <- 0;
    while (layer < depth) {
      if (mem layer tri) {
        (a, b) <@ MRSRep.sample_triangle(current);
      } else {
        (a, b) <@ MRSRep.sample_basic(current);
      }
      chain   <- chain ++ [a; b];
      current <- a;
      layer   <- layer + 1;
    }
    return chain;
  }

  proc verify(chain : int list, tri : int list) : bool = {
    var ok, i, X, a, b;
    ok <- true;
    i  <- 0;
    while (i < size chain - 2) {
      X  <- nth 0 chain i;
      a  <- nth 0 chain (i + 1);
      b  <- nth 0 chain (i + 2);
      ok <- ok && (19 * a + 9 * b = X);
      ok <- ok && (dr a = dr X);
      if (mem (i %/ 2) tri) {
        ok <- ok && (dr b = dr (2 * dr X));
      }
      i <- i + 2;
    }
    return ok;
  }
}.

(* ----------------------------------------------------------------- *)
(* Lusinvariant voor build                                            *)
(* ----------------------------------------------------------------- *)
pred build_invariant
    (chain : int list) (current : int) (layer depth N : int) (tri : int list) =
  layer <= depth /\
  size chain = 2 * layer + 1 /\
  nth 0 chain 0 = N /\
  current = nth 0 chain (2 * layer) /\
  current > 143 /\
  current %% 9 <> 0 /\
  (forall j, 0 <= j < layer =>
     let X = nth 0 chain (2*j)     in
     let A = nth 0 chain (2*j + 1) in
     let B = nth 0 chain (2*j + 2) in
     19*A + 9*B = X /\
     dr A = dr X /\
     (mem j tri => dr B = dr (2 * dr X))).

(* ----------------------------------------------------------------- *)
(* Hulplemma's over lijsten                                           *)
(* ----------------------------------------------------------------- *)

(* nth na append *)
lemma nth_cat_lo (x : 'a) (s t : 'a list) (i : int) :
  0 <= i < size s => nth x (s ++ t) i = nth x s i.
proof. by move=> hi; rewrite nth_cat hi. qed.

lemma nth_cat_hi (x : 'a) (s t : 'a list) (i : int) :
  size s <= i => nth x (s ++ t) i = nth x t (i - size s).
proof. by move=> hi; rewrite nth_cat; smt(). qed.

(* Grootte na append *)
lemma size_cat_two (s : int list) (a b : int) :
  size (s ++ [a; b]) = size s + 2.
proof. by rewrite size_cat /=. qed.

(* ----------------------------------------------------------------- *)
(* Correctheid van build                                              *)
(* ----------------------------------------------------------------- *)
lemma build_correct (N : int) (depth : int) (tri : int list) :
  N > 143 => N %% 9 <> 0 => depth >= 0 =>
  hoare [MRSChain.build :
    arg = (N, depth, tri) ==>
    let chain = res in
    size chain = 2 * depth + 1 /\
    nth 0 chain 0 = N /\
    (forall j, 0 <= j < depth =>
       let X = nth 0 chain (2*j)     in
       let A = nth 0 chain (2*j + 1) in
       let B = nth 0 chain (2*j + 2) in
       19*A + 9*B = X /\
       dr A = dr X /\
       (mem j tri => dr B = dr (2 * dr X)))].
proof.
  move=> hN hmod hd.
  proc.
  (* Stel de lusinvariant in *)
  while (build_invariant chain current layer depth N tri).

  (* ---- Luslichaam: invariant wordt bewaard ---- *)
  - move=> &hr.
    (* Haal de invariant uit de precondition *)
    rewrite /build_invariant.
    move=> [hlay [hsz [hn0 [hcur [hcurN [hcurmod hforall]]]]]].
    (* Splits op de if-conditie *)
    case (mem layer{hr} tri{hr}).

    (* ==== Triangle-tak ==== *)
    + move=> hmem.
      call (sample_triangle_correct current{hr} hcurN hcurmod).
      auto => />.
      move=> &m a b res_ok.
      (* res_ok: (fst res = 0 /\ snd res = 0) \/ (lineair /\ dr A /\ dr B) *)
      case res_ok.
      * (* (0,0)-geval: onmogelijk als current > 143 en current %% 9 <> 0  *)
        (* want triangle_k0_le_kmax garandeert dat k0 <= kmax               *)
        move=> [ha0 hb0].
        (* Tegenspraak: sample_triangle geeft (0,0) alleen als k0 > kmax,  *)
        (* maar triangle_k0_le_kmax zegt k0 <= kmax                        *)
        exfalso.
        have hk0 := triangle_k0_le_kmax current{hr} hcurN hcurmod.
        (* In de procedure geldt: k0 = (B0 current - target_r) %% 9        *)
        (* en kmax_val = kmax current. k0 > kmax_val leidde tot (0,0).     *)
        (* Maar hk0 zegt k0 <= kmax current. Tegenspraak.                  *)
        smt().
      * (* Geldig geval: res voldoet aan lineaire eis + dr-eisen *)
        move=> [hlin [hdrA hdrB]].
        rewrite /build_invariant.
        (* Bouw de nieuwe keten op *)
        set chain' := chain{hr} ++ [a; b].
        split; first by smt().
        split; first by rewrite size_cat_two; smt().
        split.
        - (* nth 0 chain' 0 = N: eerste element ongewijzigd *)
          rewrite /chain' nth_cat_lo /=; smt().
        split.
        - (* current' = nth 0 chain' (2*(layer+1)) = a *)
          rewrite /chain'.
          rewrite nth_cat_hi; first by smt(size_cat_two).
          simp; smt().
        split; first by smt(dr_rep_A a0_range).   (* a > 143? *)
        split.
        - (* a %% 9 <> 0: dr(a) = dr(current) <> 0, en dr bepaalt rest mod 9 *)
          have hdrA2 : dr a = dr current{hr}.
            rewrite hdrA //.
          smt(dr_a0 a0_range).
        (* Forall-clausule *)
        move=> j hj.
        case (j < layer{hr}).
        - (* j < layer: inductiehypothese *)
          move=> hjl.
          have := hforall j.
          smt(nth_cat_lo size_cat_two).
        - (* j = layer: de nieuwe laag *)
          move=> hjge.
          have -> : j = layer{hr} by smt().
          rewrite /chain'.
          rewrite (nth_cat_hi _ chain{hr}); first by smt(size_cat_two).
          rewrite (nth_cat_hi _ chain{hr}); first by smt(size_cat_two).
          rewrite (nth_cat_hi _ chain{hr}); first by smt(size_cat_two).
          simp.
          split.
          + (* 19*a + 9*b = X = current *)
            rewrite hlin //.
          split.
          + (* dr a = dr X = dr current *)
            rewrite hdrA //.
          + (* driehoekseis: mem layer tri => dr b = dr(2 * dr X) *)
            move=> _.
            (* hmem: mem layer tri, hdrB: dr b = dr(2 * dr current) *)
            rewrite hdrB //.

    (* ==== Basic-tak ==== *)
    + move=> hnotmem.
      call (sample_basic_correct current{hr} hcurN hcurmod).
      auto => />.
      move=> &m a b hlin hdrA.
      rewrite /build_invariant.
      set chain' := chain{hr} ++ [a; b].
      split; first by smt().
      split; first by rewrite size_cat_two; smt().
      split.
      - rewrite /chain' nth_cat_lo /=; smt().
      split.
      - rewrite /chain' nth_cat_hi; first by smt(size_cat_two).
        simp; smt().
      split; first by smt(dr_rep_A a0_range).
      split.
      - have hdrA2 : dr a = dr current{hr} := hdrA.
        smt(dr_a0 a0_range).
      move=> j hj.
      case (j < layer{hr}).
      - move=> hjl.
        have := hforall j.
        smt(nth_cat_lo size_cat_two).
      - move=> hjge.
        have -> : j = layer{hr} by smt().
        rewrite /chain'.
        rewrite (nth_cat_hi _ chain{hr}); first by smt(size_cat_two).
        rewrite (nth_cat_hi _ chain{hr}); first by smt(size_cat_two).
        rewrite (nth_cat_hi _ chain{hr}); first by smt(size_cat_two).
        simp.
        split.
        + rewrite hlin //.
        split.
        + rewrite hdrA //.
        + (* Geen driehoekseis voor basic-laag: mem j tri is vals *)
          move=> hmem.
          (* j = layer{hr} en hnotmem zegt ~(mem layer{hr} tri{hr}) *)
          exfalso; smt().

  (* ---- Initialisatie: invariant geldt voor layer = 0 ---- *)
  - auto => />.
    rewrite /build_invariant /=.
    split; first by smt().
    split; first by done.
    split; first by done.
    split; first by done.
    split; first by exact hN.
    split; first by exact hmod.
    by move=> j hj; smt().

  (* ---- Na de lus: layer = depth, invariant => postcondition ---- *)
  - move=> &m.
    rewrite /build_invariant.
    move=> [hlay [hsz [hn0 [hcur [_ [_ hforall]]]]]].
    split.
    + (* size = 2*depth + 1 *)
      smt().
    split.
    + exact hn0.
    + (* Forall clausule voor j < depth *)
      move=> j hj.
      have := hforall j.
      smt().
qed.

(* ----------------------------------------------------------------- *)
(* Equivalentie van build                                             *)
(* ----------------------------------------------------------------- *)
lemma build_equiv (N : int) (depth : int) (tri : int list) :
  N > 143 => N %% 9 <> 0 =>
  equiv [MRSChain.build ~ MRSChain.build :
    ={arg} ==> ={res}].
proof.
  move=> hN hmod.
  proc.
  while (={layer, chain, current, depth, tri}).
  - (* Luslichaam: beide takken synchroon *)
    seq 1 1 : (={layer, chain, current, depth, tri, a, b}).
    + if => />.
      * call (sample_triangle_equiv current{1} hN hmod).
        auto.
      * call (sample_basic_equiv current{1} hN hmod).
        auto.
    + auto.
  - auto.
qed.
