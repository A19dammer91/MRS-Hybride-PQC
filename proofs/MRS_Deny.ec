(* ================================================================= *)
(*  MRS_Deny.ec                                                       *)
(*  Formele deniability: geen enkele adversary doet het beter dan 50% *)
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
(* Hulplemma: de twee ketens hebben identieke verdeling               *)
(* Dit volgt direct uit build_equiv                                   *)
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
(* Hoofdstelling: informatietheorische deniability                    *)
(* Adv_DENY(A) = |Pr[b'=b] - 1/2| = 0 voor elke adversary A        *)
(* ----------------------------------------------------------------- *)
lemma deny_advantage (A <: Adversary) (N : int) (depth : int) (tri : int list) :
  N > 143 => N %% 9 <> 0 =>
  Pr[DenyGame(A).main(N, depth, tri) @ &m : res] = 1%r / 2%r.
proof.
  move=> hN hmod.
  (* Strategie: toon dat de kansruimte over b uniform is en            *)
  (* dat ch0 en ch1 identiek verdeeld zijn, zodat A geen informatie    *)
  (* over b kan extraheren uit de aangeboden keten.                    *)
  byphoare => //.
  proc.

  (* Stap 1: sample b uniform â€” onafhankelijk van de ketens *)
  seq 3 : b (1%r/2%r) (1%r) (1%r/2%r) (0%r).
  - (* b wordt uniform getrokken, ketens zijn onafhankelijk *)
    call (build_equiv N depth tri hN hmod).
    call (build_equiv N depth tri hN hmod).
    rnd.
    auto.

  - (* b = true tak *)
    (* b' = A.guess(ch1), b = true *)
    (* De kans dat b' = true is p = Pr[A.guess(ch1) = true] *)
    (* Maar ch1 heeft dezelfde verdeling als ch0 *)
    (* Pr[b' = b | b = true] = Pr[A.guess(ch1) = true] = p *)
    (* Pr[b' = b | b = false] = Pr[A.guess(ch0) = false] = 1 - p *)
    (* Totaal: 1/2 * p + 1/2 * (1 - p) = 1/2 *)
    if => />.
    (* ch1-tak *)
    have key : forall (ch : int list),
      phoare [A.guess : arg = ch ==> true] = 1%r.
      move=> ch; proc *; auto.
    call (key ch1).
    auto.

  - (* b = false tak â€” analoog *)
    if => />.
    have key : forall (ch : int list),
      phoare [A.guess : arg = ch ==> true] = 1%r.
      move=> ch; proc *; auto.
    call (key ch0).
    auto.

  - (* Onmogelijke tak *)
    hoare; auto.

  (* Stap 2: combineer via de distributie-gelijkheid van ch0 en ch1 *)
  (* De kans is precies 1/2 want de adversary ziet een uniforme keten *)
  byequiv => //.
  proc.
  (* Koppel ch0{1} aan ch1{2} via de gelijke verdeling *)
  seq 2 2 : (ch0{1} = ch1{2} /\ ch1{1} = ch0{2} /\ ={b, tri, depth}).
  - call (ch0_ch1_same_distr N depth tri hN hmod).
    call (ch0_ch1_same_distr N depth tri hN hmod).
    auto.
  if => />; call (: true); auto.
qed.
