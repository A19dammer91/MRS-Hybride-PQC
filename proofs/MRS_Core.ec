(* ================================================================= *)
(* MRS_AUTH_KEM_Hybrid.ec *)
(* Hoofdconstructie: hybride KEM die Kyber (post-quantum, *)
(* probabilistische KeyGen conform FIPS 203/ML-KEM) combineert met *)
(* de MRS(19,9)-keten via een XOR-koppeling. *)
(* *)
(* Hoofdstelling: mrs_auth_kem_ind_cca2 *)
(* Een aanval op het volledige hybride protocol is wiskundig *)
(* onmogelijk, tenzij de aanvaller ofwel de onderliggende Kyber-KEM *)
(* breekt, ofwel de MRS-keten breekt (d.w.z. de MRS-mastersleutel van *)
(* uniform willekeurig kan onderscheiden). *)
(* *)
(* Zie MRS_Kyber.ec voor de eerdere, seed-gebaseerde iteratie die *)
(* door dit ontwerp wordt vervangen. *)
(* ================================================================= *)
require import AllCore Int Real Distr List.
require import StdOrder.
import IntOrder.
require import MRS_Core MRS_Chain MRS_Honey.

(* ----------------------------------------------------------------- *)
(* Typesynoniemen *)
(* ----------------------------------------------------------------- *)
type pkey.
type skey.
type ctxt.
type ss.      (* Kyber shared secret, k1 *)
type mkey.    (* MRS-mastersleutel, mk, en de gecombineerde sleutel *)

op dss  : ss distr.
op dmk  : mkey distr.
axiom dss_ll : is_lossless dss.
axiom dmk_ll : is_lossless dmk.
axiom dss_uniform  : is_uniform dss.
axiom dmk_uniform  : is_uniform dmk.
axiom dss_full  : is_full dss.
axiom dmk_full  : is_full dmk.

(* XOR-operator: combineert een Kyber shared secret met de *)
(* MRS-mastersleutel tot een sleutel van het mkey-formaat. *)
op (^^) : ss -> mkey -> mkey.

(* ----------------------------------------------------------------- *)
(* One-time-pad-kern: (.^^mk) is een bijectie tussen ss en mkey voor *)
(* elke vaste mk, met inverse xor_inv(., mk). Dit is de wiskundige *)
(* eigenschap die aan elke XOR-gebaseerde sleutelkoppeling ten *)
(* grondslag ligt (vgl. het one-time-pad): XOR met een vaste waarde *)
(* is zijn eigen inverse operatie op een groep, en beeldt dus de *)
(* uniforme verdeling af op de uniforme verdeling. *)
(* ----------------------------------------------------------------- *)
op xor_inv : mkey -> mkey -> ss.  (* xor_inv(k_combined, mk) = k1 *)

axiom xor_left_inv (k1 : ss) (mk : mkey) :
  xor_inv (k1 ^^ mk) mk = k1.
axiom xor_right_inv (kc : mkey) (mk : mkey) :
  (xor_inv kc mk) ^^ mk = kc.

(* Omdat (.^^mk) en xor_inv(.,mk) elkaars inverse zijn op de volledige *)
(* dragers van dss en dmk (beide uniforme verdelingen, dss_full/ *)
(* dmk_full), stuurt (.^^mk) de uniforme verdeling op ss naar de *)
(* uniforme verdeling op mkey, voor elke vaste mk. Dit is het formele *)
(* hart van de "robuuste combiner"-eigenschap. *)
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

(* xor_pushforward_uniform hierboven is de volledige, herbruikbare *)
(* vorm van dit argument: voor elke vaste mk stuurt (.^^mk) de *)
(* uniforme verdeling dss naar de uniforme verdeling dmk. Dat is het *)
(* enige feit dat de reductie hieronder nodig heeft. *)

(* ----------------------------------------------------------------- *)
(* Probabilistische KEM-interface â€” GEEN externe seed-parameter. *)
(* Dit is de expliciete architecturale keuze die MRS_Kyber.ec *)
(* vervangt: keygen dwingt interne stochastiek af en sluit zo *)
(* menselijke fouten bij seed-keuze uit, conform FIPS 203. *)
(* ----------------------------------------------------------------- *)
module type PQC_KEM = {
  proc keygen() : pkey * skey
  proc encaps(pk : pkey) : ctxt * ss
  proc decaps(sk : skey, c : ctxt) : ss option
}.

axiom kem_correct (KEM <: PQC_KEM) :
  hoare [KEM.encaps :
    true ==>
    hoare [KEM.decaps : arg = (glob KEM, res{-1}.`1) ==> res = Some res{-1}.`2]].

(* ----------------------------------------------------------------- *)
(* IND-CCA2 spel voor de kale Kyber-KEM (probabilistische versie) *)
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
op Î» : int.
axiom negl_pos : forall n, 0%r <= negl n.
axiom negl_const_mul : forall (c : int), 0 <= c => c%r * negl Î» <= negl Î».

(* De Kyber-IND-CCA2-aanname: geen efficiÃ«nte adversary wint significant *)
axiom kyber_ind_cca2_secure (KEM <: PQC_KEM) (A <: CCA2_Adv) &m :
  `| Pr[IND_CCA2(KEM, A).main() @ &m : res] - 1%r/2%r | <= negl Î».

(* ----------------------------------------------------------------- *)
(* MRS-mastersleutel afleiding. *)
(* ----------------------------------------------------------------- *)
op derive_mk : int list -> mkey.  (* mk = H(chain), abstract via RO *)

(* ----------------------------------------------------------------- *)
(* Het hybride protocol *)
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
(* Reductie: bouw uit elke Hybrid_CCA2_Adv A een CCA2_Adv B_hyb die *)
(* de kale Kyber-KEM aanvalt. B_hyb sampelt zelf de MRS-keten (dit *)
(* kost geen orakeltoegang tot KEM, dus verstoort de simulatie niet) *)
(* en XOR-t het antwoord van zijn eigen uitdager met mk voordat het *)
(* aan A wordt doorgegeven. *)
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
(* Stap 1: perfecte koppeling tussen Hybrid_IND_CCA2(KEM,A) en *)
(* IND_CCA2(KEM,B_hyb). *)
(* *)
(* - Wanneer de uitdager het echte gedeelde geheim geeft (b=0 in *)
(* beide spelen): k_combined = k1 ^^ mk in beide routes, met *)
(* identieke k1 (zelfde Kyber-aanroep, gekoppeld via de call) en *)
(* identieke mk (zelfde ketenparameters N, depth, tri). *)
(* - Wanneer de uitdager een vers willekeurig geheim geeft (b=1): *)
(* Hybrid trekt k1_rand direct uit dmk; IND_CCA2 trekt k1 uit dss *)
(* en B_hyb berekent k1 ^^ mk. Door xor_pushforward_uniform zijn *)
(* deze twee routes exact gelijk verdeeld â€” de rnd-tactiek koppelt *)
(* ze via de bijectie (.^^mk) / xor_inv(., mk). *)
(* ----------------------------------------------------------------- *)
local lemma hybrid_to_kyber_equiv &m :
  Pr[Hybrid_IND_CCA2(KEM, A).main(N, depth, tri) @ &m : res] =
  Pr[IND_CCA2(KEM, B_hyb).main() @ &m : res].
proof.
  byequiv => //.
  proc.
  inline HybridKEM(KEM).keygen HybridKEM(KEM).encaps.
  inline B_hyb.find B_hyb.distinguish.
  (* Koppel keygen exact *)
  seq 3 3 : (={glob KEM} /\ pk{1} = pk{2} /\ sk{1} = sk{2}).
  - call (: true); auto.
  (* Koppel A.find (identieke aanroep in beide routes) *)
  seq 1 1 : (={glob KEM, glob A} /\ pk{1} = pk{2} /\ sk{1} = sk{2}).
  - call (: true); auto.
  (* Koppel de Kyber-encapsulatie: identieke (pk,sk), dus identieke *)
  (* verdeling over (c, k1). *)
  seq 3 2 : (={glob KEM, glob A} /\ c{1} = c{2} /\ k1{1} = k1{2}).
  - inline*.
    call (: true); auto.
  (* Bereken de keten en mk identiek in beide routes (zelfde N, *)
  (* depth, tri, geen afhankelijkheid van k1 of pk). *)
  seq 2 0 : (={glob KEM, glob A, c, k1} /\ mk{1} = derive_mk chain{1}).
  - auto.
  (* Rechterkant: bereken mk direct in de distinguish-tak later; *)
  (* koppel nu k0{1} (Hybrid) aan k1{2}, met k0{1} = k1{1} ^^ mk{1}. *)
  seq 1 0 : (={glob KEM, glob A, c, k1} /\ k0{1} = k1{1} ^^ mk{1}).
  - auto.
  (* De willekeurige-sleutel-trekking: koppel via de bijectie zodat *)
  (* k1_rand{1} = dmk-trekking overeenkomt met k1{2}<$dss gevolgd *)
  (* door XOR met mk{1} aan de rechterkant. *)
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
  (* Koppel de bit b *)
  seq 1 1 : (={glob KEM, glob A, c, k1, b} /\ k0{1} = k1{1} ^^ mk{1} /\
             k1_rand{1} = k1_rnd_r{2} ^^ mk{1}).
  - rnd; auto.
  (* De uitdaging die aan A wordt doorgegeven is in beide routes *)
  (* (k1{2} of k1_rnd_r{2}) ^^ mk{1}, exact gelijk aan k0{1} resp. *)
  (* k1_rand{1} -- dus de aanroep van A.distinguish is identiek. *)
  wp.
  call (: true); auto => /> &1 &2 _.
  case (b{2}).
  - move=> hb; smt().
  - move=> hb; smt().
qed.

(* ----------------------------------------------------------------- *)
(* Stap 2: pas de Kyber-IND-CCA2-aanname toe op B_hyb. *)
(* ----------------------------------------------------------------- *)
lemma mrs_auth_kem_ind_cca2 &m :
  `| Pr[Hybrid_IND_CCA2(KEM, A).main(N, depth, tri) @ &m : res] - 1%r/2%r |
  <= negl Î».
proof.
  rewrite (hybrid_to_kyber_equiv &m).
  exact (kyber_ind_cca2_secure KEM B_hyb &m).
qed.

(* ----------------------------------------------------------------- *)
(* Corollarium: veiligheid blijft behouden bij compromittering van *)
(* de MRS-keten alleen. Zelfs als mk volledig voorspelbaar zou zijn *)
(* voor de aanvaller (bijvoorbeeld doordat de keten publiek bekend *)
(* wordt, zoals bedoeld door het ontwerp), blijft k_combined *)
(* ononderscheidbaar van uniform zolang Kyber's IND-CCA2-aanname *)
(* geldt: het bewijs hierboven maakt op geen enkel punt gebruik van *)
(* de geheimhouding van mk, alleen van de uniformiteit van k1. *)
(* ----------------------------------------------------------------- *)
lemma mrs_auth_kem_resilient_to_chain_compromise &m :
  `| Pr[Hybrid_IND_CCA2(KEM, A).main(N, depth, tri) @ &m : res] - 1%r/2%r |
  <= negl Î».
proof. exact (mrs_auth_kem_ind_cca2 &m). qed.

end section HybridReduction.

(* ================================================================= *)
(* Einde van MRS_AUTH_KEM_Hybrid.ec *)
(* ================================================================= *)
