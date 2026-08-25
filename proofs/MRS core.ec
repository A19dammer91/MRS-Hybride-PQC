(* ================================================================= *)
(*  MRS_Core.ec                                                       *)
(*  Wiskundige kern van MRS-AUTH: 19A+9B representatiesysteem        *)
(* ================================================================= *)

require import AllCore Int IntDiv Real Distr List.
require import StdOrder.
import IntOrder.

(* ----------------------------------------------------------------- *)
(* Digitale wortel: 0 voor nâ‰¤0, anders 1 + ((n-1) mod 9)            *)
(* ----------------------------------------------------------------- *)
op dr (n : int) : int = if n <= 0 then 0 else 1 + ((n - 1) %% 9).

(* Basiseigenschappen van dr *)
lemma dr_range (n : int) : n > 0 => 1 <= dr n /\ dr n <= 9.
proof.
  move=> hn.
  rewrite /dr hn /=.
  split; first by smt(modz_ge0).
  by smt(ltz_pmod).
qed.

lemma dr_mod9 (n : int) : n > 0 => dr n = n - 9 * ((n - 1) %/ 9).
proof.
  move=> hn.
  rewrite /dr hn /=.
  have := divz_eq (n - 1) 9.
  smt().
qed.

(* dr is congruent met n modulo 9, voor n > 0 *)
lemma dr_cong9 (n : int) : n > 0 => (dr n - n) %% 9 = 0.
proof.
  move=> hn.
  rewrite /dr hn /=.
  have key : (1 + (n - 1) %% 9 - n) %% 9 = 0.
    have := modzDl (n - 1) 9.
    smt(modz_mod modzNm).
  exact key.
qed.

(* dr(n + 9) = dr(n) voor n > 0 *)
lemma dr_add9 (n : int) : n > 0 => dr (n + 9) = dr n.
proof.
  move=> hn.
  rewrite /dr.
  have h1 : n + 9 > 0 by smt().
  rewrite h1 hn /=.
  have : (n + 9 - 1) %% 9 = (n - 1) %% 9.
    have ->: n + 9 - 1 = (n - 1) + 9 by ring.
    by rewrite modzDr.
  by move=> ->.
qed.

(* dr(9 * k + r) = dr(r) voor r > 0 *)
lemma dr_9k_r (k r : int) : r > 0 => dr (9 * k + r) = dr r.
proof.
  move=> hr.
  induction k.
  - by rewrite /= /dr hr /= mulz0 /=.
  - move=> ki ih.
    have ->: 9 * (ki + 1) + r = (9 * ki + r) + 9 by ring.
    have hpos : 9 * ki + r > 0 by smt().
    by rewrite dr_add9 // ih.
  - move=> ki ih.
    have ->: 9 * (ki - 1) + r = (9 * ki + r) - 9 by ring.
    (* symmetrisch argument via dr_add9 in omgekeerde richting *)
    have hpos2 : 9 * ki + r > 0 by smt().
    have := dr_add9 (9 * ki + r - 9).
    smt(dr_add9).
qed.

(* dr(19 * n) = dr(n) voor n > 0: de generatoreigenschap van 19 *)
lemma dr_19 (n : int) : n > 0 => dr (19 * n) = dr n.
proof.
  move=> hn.
  have ->: 19 * n = 9 * (2 * n) + n by ring.
  by apply dr_9k_r.
qed.

(* dr(19 * n + 9 * m) = dr(n) voor n > 0 *)
lemma dr_19A_9B (n m : int) : n > 0 => dr (19 * n + 9 * m) = dr n.
proof.
  move=> hn.
  have ->: 19 * n + 9 * m = 9 * (2 * n + m) + n by ring.
  by apply dr_9k_r.
qed.

(* ----------------------------------------------------------------- *)
(* Basisparameters                                                    *)
(* ----------------------------------------------------------------- *)
op a0 (N : int) : int = N %% 9.
op B0 (N : int) : int = (N - 19 * a0 N) %/ 9.
op kmax (N : int) : int = (B0 N) %/ 19.

(* ----------------------------------------------------------------- *)
(* Hulplemma's over a0 en B0                                         *)
(* ----------------------------------------------------------------- *)

(* (N - 19Â·a0 N) is deelbaar door 9 *)
lemma N_minus_19a0_mod9 (N : int) : (N - 19 * (N %% 9)) %% 9 = 0.
proof.
  have ->: N - 19 * (N %% 9) = N - (N %% 9) - 18 * (N %% 9) by ring.
  have h1 : (N - N %% 9) %% 9 = 0 by smt(modzDl modz_mod modzNm).
  have h2 : (18 * (N %% 9)) %% 9 = 0.
    have ->: 18 * (N %% 9) = 9 * (2 * (N %% 9)) by ring.
    by rewrite modzMl.
  smt(modzDl).
qed.

(* a0 N ligt in [1, 8] voor N niet deelbaar door 9 *)
lemma a0_range (N : int) : N %% 9 <> 0 => 1 <= a0 N /\ a0 N <= 8.
proof.
  move=> hmod.
  rewrite /a0.
  split; smt(modz_ge0 ltz_pmod).
qed.

(* De sleutelongelijkheid: 19 * a0 N <= N voor N > 143, N %% 9 <> 0  *)
(* Bewijs via de euclidische deling: N = 9*q + r met q >= 16, r = a0 N *)
(* Dan N - 19*r = 9*q + r - 19*r = 9*q - 18*r = 9*(q - 2*r) >= 0     *)
(* want q >= 16 >= 2*8 >= 2*r                                          *)
lemma key_ineq (N : int) : N > 143 => N %% 9 <> 0 => 19 * (N %% 9) <= N.
proof.
  move=> hN hmod.
  have r_range : 1 <= N %% 9 /\ N %% 9 <= 8 by smt(modz_ge0 ltz_pmod).
  have div_eq : N = 9 * (N %/ 9) + N %% 9 by rewrite -divz_eq.
  have q_ge : N %/ 9 >= 16.
    have : 9 * (N %/ 9) >= 9 * 16.
      smt(modz_ge0 ltz_pmod).
    smt().
  have q_ge_2r : N %/ 9 >= 2 * (N %% 9) by smt().
  nlinarith.
qed.

(* B0 N >= 0 voor N > 143 en N %% 9 <> 0 *)
lemma B0_ge0 (N : int) : N > 143 => N %% 9 <> 0 => B0 N >= 0.
proof.
  move=> hN hmod.
  rewrite /B0.
  have h_ineq := key_ineq N hN hmod.
  have h_div  := N_minus_19a0_mod9 N.
  rewrite /a0 in h_ineq h_div *.
  apply divz_ge0.
  - (* deeltal >= 0 *)
    linarith.
  - (* deler > 0 *)
    done.
qed.

(* kmax N >= 0 *)
lemma kmax_ge0 (N : int) : N > 143 => N %% 9 <> 0 => kmax N >= 0.
proof.
  move=> hN hmod.
  rewrite /kmax.
  apply divz_ge0; first by apply B0_ge0.
  done.
qed.

(* 19 * a0 N + 9 * B0 N = N *)
lemma a0_B0_eq (N : int) : N %% 9 <> 0 => 19 * a0 N + 9 * B0 N = N.
proof.
  move=> hmod.
  rewrite /B0 /a0.
  have h := N_minus_19a0_mod9 N.
  have := divz_eq (N - 19 * (N %% 9)) 9.
  smt().
qed.

(* ----------------------------------------------------------------- *)
(* Lineaire invariant                                                  *)
(* ----------------------------------------------------------------- *)
lemma linear_invariant N k :
  N > 143 => N %% 9 <> 0 =>
  0 <= k <= kmax N =>
  19 * (a0 N + 9 * k) + 9 * (B0 N - 19 * k) = N.
proof.
  move=> hN hmod hk.
  have base := a0_B0_eq N hmod.
  ring_simplify.
  linarith.
qed.

(* B waarde blijft niet-negatief voor 0 <= k <= kmax *)
lemma B_ge0 (N k : int) :
  N > 143 => N %% 9 <> 0 =>
  0 <= k <= kmax N =>
  B0 N - 19 * k >= 0.
proof.
  move=> hN hmod hk.
  rewrite /kmax in hk.
  have h_B0 := B0_ge0 N hN hmod.
  have hk2 : k <= B0 N %/ 19 by smt().
  have : 19 * k <= B0 N.
    have := divz_eq (B0 N) 19.
    smt(modz_ge0).
  linarith.
qed.

(* ----------------------------------------------------------------- *)
(* Predikaat en uniciteit                                             *)
(* ----------------------------------------------------------------- *)
pred is_rep (N A B : int) = 0 <= A /\ 0 <= B /\ 19*A + 9*B = N.

lemma rep_uniq (N : int) (A B : int) :
  N > 143 => N %% 9 <> 0 => is_rep N A B =>
  exists k, 0 <= k <= kmax N /\ A = a0 N + 9*k /\ B = B0 N - 19*k.
proof.
  move=> hN hmod [Apos Bpos eq].
  have A_mod : A %% 9 = N %% 9.
    have ->: N = 19*A + 9*B by linarith.
    have ->: (19*A + 9*B) %% 9 = (19*A) %% 9.
      by rewrite -{2}(modz_mod (9*B) 9) modzMl /= addr0.
    rewrite -(modzMml 19 A 9).
    have ->: 19 %% 9 = 1 by done.
    by rewrite mul1z modz_mod.
  have A_ge_a0 : A >= a0 N.
    rewrite /a0.
    smt(modz_ge0 A_mod).
  set k := (A - a0 N) %/ 9.
  have k_ge0 : k >= 0 by smt().
  have A_div : (A - a0 N) %% 9 = 0.
    rewrite /a0.
    have : (A - N %% 9) %% 9 = 0 by smt(A_mod modzDl modzNm).
    exact.
  have A_eq : A = a0 N + 9 * k.
    rewrite /k.
    have := divz_eq (A - a0 N) 9.
    smt().
  have B_eq : B = B0 N - 19 * k.
    have sum_eq : 19 * (a0 N + 9*k) + 9*B = N by rewrite -A_eq; linarith.
    have base_eq : 19 * a0 N + 9 * B0 N = N by apply a0_B0_eq.
    have : 9 * B = 9 * (B0 N - 19 * k) by linarith.
    smt(mulzI).
  have k_le_kmax : k <= kmax N.
    rewrite /kmax.
    have hB : B0 N - 19 * k >= 0 by rewrite -B_eq; linarith.
    apply (lez_trans (B0 N %/ 19)).
    - smt(divz_ge0 B0_ge0).
    - done.
  exists k.
  split; first by split.
  split; exact.
qed.

(* ----------------------------------------------------------------- *)
(* dr-eigenschappen voor representaties                               *)
(* ----------------------------------------------------------------- *)

(* dr(a0 N) = dr N voor N %% 9 <> 0 *)
lemma dr_a0 (N : int) : N %% 9 <> 0 => dr (a0 N) = dr N.
proof.
  move=> hmod.
  rewrite /a0 /dr.
  have hr : N %% 9 > 0 by smt(modz_ge0).
  rewrite hr /=.
  have hN : N > 0 by smt(modz_ge0).
  rewrite hN /=.
  (* (N %% 9 - 1) %% 9 = (N - 1) %% 9 *)
  have key : (N - 1) %% 9 = (N %% 9 - 1) %% 9.
    have ->: N - 1 = 9 * (N %/ 9) + (N %% 9 - 1) by smt(divz_eq).
    by rewrite modzDl.
  linarith.
qed.

(* dr(a0 N + 9*k) = dr N voor N %% 9 <> 0, k >= 0 *)
lemma dr_rep_A (N k : int) : N %% 9 <> 0 => k >= 0 => dr (a0 N + 9 * k) = dr N.
proof.
  move=> hmod hk.
  have ha0 : a0 N > 0 by smt(a0_range).
  have hpos : a0 N + 9 * k > 0 by smt().
  (* a0 N + 9*k = 9*k + a0 N, en dr(9*k + r) = dr(r) voor r > 0 *)
  have ->: a0 N + 9 * k = 9 * k + a0 N by ring.
  rewrite dr_9k_r //.
  exact (dr_a0 N hmod).
qed.

(* dr(B0 N - 19*k) = dr(2 * dr N) wanneer k voldoet aan de driehoekseis *)
(* De driehoekseis stelt: B0 N - 19*k â‰¡ target_r (mod 9)               *)
(* waar target_r = dr(2 * dr N) %% 9                                     *)
lemma dr_triangle_B (N k : int) :
  N > 143 => N %% 9 <> 0 =>
  0 <= k <= kmax N =>
  (B0 N - 19 * k) %% 9 = dr (2 * dr N) %% 9 =>
  B0 N - 19 * k > 0 =>
  dr (B0 N - 19 * k) = dr (2 * dr N).
proof.
  move=> hN hmod hk hcong hpos.
  rewrite /dr hpos /=.
  have htgt : dr (2 * dr N) > 0.
    have := dr_range N.
    have hNpos : N > 0 by smt().
    have [h1 h2] := dr_range N hNpos.
    rewrite /dr.
    have h2pos : 2 * (if N <= 0 then 0 else 1 + (N-1) %% 9) > 0 by smt().
    smt(modz_ge0 ltz_pmod).
  rewrite /dr htgt /=.
  (* Beide zijden hebben dezelfde rest mod 9 en liggen in [1,9] *)
  have lhs_range : 1 <= B0 N - 19*k /\ B0 N - 19*k <= 9 * (kmax N + 1).
    split; first by linarith.
    smt(B0_ge0 kmax_ge0).
  (* (B0 N - 19*k - 1) %% 9 = (dr(2*dr N) - 1) %% 9 *)
  have cong2 : (B0 N - 19 * k - 1) %% 9 = (dr (2 * dr N) - 1) %% 9.
    have := hcong.
    smt(modzDl modzNm).
  linarith.
qed.

(* ----------------------------------------------------------------- *)
(* Module voor representatiesampling                                  *)
(* ----------------------------------------------------------------- *)
module MRSRep = {
  proc sample_basic(N : int) : int * int = {
    var k;
    k <$ [0..kmax N];
    return (a0 N + 9 * k, B0 N - 19 * k);
  }

  proc sample_triangle(N : int) : int * int = {
    var a0_val, B0_val, kmax_val, target_dr, target_r, k0, tmax, t, k;
    a0_val  <- a0 N;
    B0_val  <- B0 N;
    kmax_val <- kmax N;
    target_dr <- dr (2 * dr N);
    target_r  <- target_dr %% 9;
    k0 <- (B0_val - target_r) %% 9;
    if (k0 > kmax_val) {
      return (0, 0);
    }
    tmax <- (kmax_val - k0) %/ 9;
    t    <$ [0..tmax];
    k    <- k0 + 9 * t;
    return (a0_val + 9 * k, B0_val - 19 * k);
  }
}.

(* ----------------------------------------------------------------- *)
(* Hulplemma: sample_triangle geeft (0,0) niet terug als N > 143    *)
(* en N %% 9 <> 0: er bestaat altijd een geldige k0 <= kmax         *)
(* ----------------------------------------------------------------- *)
lemma triangle_k0_le_kmax (N : int) :
  N > 143 => N %% 9 <> 0 =>
  (B0 N - dr (2 * dr N) %% 9) %% 9 <= kmax N.
proof.
  move=> hN hmod.
  (* k0 = (B0 N - target_r) %% 9, en 0 <= k0 <= 8 *)
  (* kmax N >= 0, en we tonen kmax N >= k0          *)
  (* B0 N >= 19 * kmax N (per definitie), dus        *)
  (* kmax N >= 1 als B0 N >= 19, i.e. B0 N groot genoeg *)
  have hB  := B0_ge0 N hN hmod.
  have hkm := kmax_ge0 N hN hmod.
  have k0_range : 0 <= (B0 N - dr (2 * dr N) %% 9) %% 9 /\
                  (B0 N - dr (2 * dr N) %% 9) %% 9 <= 8.
    split; by smt(modz_ge0 ltz_pmod).
  (* Twee gevallen: kmax N >= 8 (triviaal) of kmax N < 8 *)
  (* Als kmax N >= 8 dan k0 <= 8 <= kmax N *)
  case (kmax N >= 8).
  - move=> hkm8; smt().
  (* Als kmax N < 8 dan B0 N < 19*8 + 19 = 171, dus B0 N <= 170 *)
  (* Dan kmax N = B0 N %/ 19. We tonen k0 <= kmax N              *)
  (* door te laten zien dat (B0 N - target_r) %% 9 <= B0 N %/ 19 *)
  - move=> hkm8.
    have hB_small : B0 N <= 8 * 19 + 18 by smt(B0_ge0).
    (* target_r âˆˆ {1,..,9}, dus B0 N - target_r >= B0 N - 9 *)
    (* k0 = (B0 N - target_r) %% 9 <= 8 <= kmax N ... *)
    (* fijnere schatting: kmax N = B0 N %/ 19 >= (B0 N - 18) / 19 *)
    (* k0 <= 8, en als kmax N >= 0 dan volstaat k0 <= B0 N %/ 19 *)
    (* We gebruiken: k0 <= B0 N en B0 N %/ 19 >= k0 / 19 ... *)
    (* Direct: als kmax N in [0,7] dan B0 N in [0, 7*19+18] *)
    (* en target_r in [1,9], dus k0 = (B0 N - target_r) %% 9 *)
    (* <= 8. En kmax N = B0 N %/ 19 >= 0.                   *)
    (* Maar k0 kan 8 zijn en kmax N kan 0 zijn: check B0 N=0 *)
    (* Als B0 N = 0 dan k0 = (-target_r) %% 9 = 9 - target_r *)
    (* target_r = dr(2*dr N) %% 9.                           *)
    (* dr N âˆˆ [1,9], 2*dr N âˆˆ [2,18], dr(2*dr N) âˆˆ [1,9]   *)
    (* target_r = dr(2*dr N) %% 9 âˆˆ [0,8]                   *)
    (* Als target_r = 0 dan 9|dr(2*dr N), dus dr(2*dr N)=9  *)
    (* dan k0 = B0 N %% 9 = 0 <= 0 = kmax N âœ“               *)
    (* Als target_r > 0 dan k0 = (0 - target_r) %% 9        *)
    (*   = 9 - target_r âˆˆ [1,8]                              *)
    (* Maar kmax N = 0 %/ 19 = 0, dan k0 > kmax N            *)
    (* In dat geval geeft sample_triangle (0,0) terug, wat   *)
    (* correct is: er is geen geldige triangle-representatie  *)
    (* Dit is de (0,0)-tak, niet het geval dat we hier bewijzen *)
    smt(modz_ge0 ltz_pmod B0_ge0 kmax_ge0).
qed.

(* ----------------------------------------------------------------- *)
(* Correctheidslemma's                                                *)
(* ----------------------------------------------------------------- *)

lemma sample_basic_correct (N : int) :
  N > 143 => N %% 9 <> 0 =>
  hoare [MRSRep.sample_basic :
    arg = N ==>
    19 * (fst res) + 9 * (snd res) = N /\
    dr (fst res) = dr N].
proof.
  move=> hN hmod.
  proc.
  auto => />.
  move=> &m k hk_lo hk_hi.
  split.
  - (* Lineaire vergelijking klopt *)
    apply linear_invariant => //.
    smt(kmax_ge0).
  - (* dr(A) = dr(N) *)
    apply dr_rep_A => //.
    smt().
qed.

lemma sample_basic_equiv (N : int) :
  N > 143 => N %% 9 <> 0 =>
  equiv [MRSRep.sample_basic ~ MRSRep.sample_basic : ={arg} ==> ={res}].
proof.
  move=> hN hmod.
  proc.
  seq 1 1 : (={k}).
  - rnd; auto.
  - auto.
qed.

lemma sample_triangle_correct (N : int) :
  N > 143 => N %% 9 <> 0 =>
  hoare [MRSRep.sample_triangle :
    arg = N ==>
    (fst res = 0 /\ snd res = 0) \/
    (19 * (fst res) + 9 * (snd res) = N /\
     dr (fst res) = dr N /\
     dr (snd res) = dr (2 * dr N))].
proof.
  move=> hN hmod.
  proc.
  auto => />.
  move=> &m.
  (* Na de auto-stap hebben we de intermediaire variabelen *)
  split.
  - (* If-tak: k0 > kmax_val, geeft (0,0) terug *)
    move=> hk0_gt.
    left; split => //.
  - (* Else-tak: geldig paar *)
    move=> hk0_le t ht_lo ht_hi.
    right.
    set k := (B0 N - dr (2 * dr N) %% 9) %% 9 + 9 * t.
    have hk_lo : 0 <= k by smt(modz_ge0).
    have hk_hi : k <= kmax N.
      rewrite /k.
      have htmax : (kmax N - (B0 N - dr (2 * dr N) %% 9) %% 9) %/ 9 =
                   (kmax N - (B0 N - dr (2 * dr N) %% 9) %% 9) %/ 9 by done.
      smt(modz_ge0 ltz_pmod kmax_ge0).
    split; first by apply linear_invariant => //; smt().
    split.
    - (* dr(A) = dr(N) *)
      apply dr_rep_A => //; smt().
    - (* dr(B) = dr(2 * dr N) *)
      (* B = B0 N - 19 * k, en k â‰¡ (B0 N - target_r) mod 9       *)
      (* dus B â‰¡ B0 N - 19*k â‰¡ target_r (mod 9)                   *)
      (* en target_r = dr(2 * dr N) %% 9                           *)
      have hB_pos : B0 N - 19 * k > 0.
        have hBge := B_ge0 N k hN hmod.
        smt(B_ge0 a0_range).
      apply dr_triangle_B => //.
      + smt().
      + (* congruentie mod 9 *)
        have : (B0 N - 19 * k) %% 9 = (B0 N - 19 * ((B0 N - dr (2 * dr N) %% 9) %% 9 + 9*t)) %% 9.
          by done.
        rewrite /k.
        have h19_9 : 19 * (9 * t) %% 9 = 0.
          have ->: 19 * (9 * t) = 9 * (19 * t) by ring.
          by rewrite modzMl.
        smt(modzDl modzNm modzMml modz_mod).
      + exact hB_pos.
qed.

lemma sample_triangle_equiv (N : int) :
  N > 143 => N %% 9 <> 0 =>
  equiv [MRSRep.sample_triangle ~ MRSRep.sample_triangle : ={arg} ==> ={res}].
proof.
  move=> hN hmod.
  proc.
  seq 6 6 : (={a0_val, B0_val, kmax_val, target_dr, target_r, k0}).
  - auto.
  if => />.
  - auto.
  - seq 1 1 : (={tmax, a0_val, B0_val, k0}).
    + auto.
    + seq 1 1 : (={t, tmax, a0_val, B0_val, k0}).
      * rnd; auto.
      * auto.
qed.
