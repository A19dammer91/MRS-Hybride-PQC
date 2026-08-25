(* ================================================================= *)
(* MRS_Kyber.ec *)
(* Vroege iteratie: abstracte Kyber-KEM-interface met een expliciete, *)
(* extern aangeleverde seed-parameter voor KeyGen. *)
(* *)
(* Status: SUPERSEDED. Deze module is de eerdere ontwerpkeuze die is *)
(* vervangen door de probabilistische KeyGen-interface (zonder *)
(* externe seed) in MRS_AUTH_KEM_Hybrid.ec, om directe conformiteit *)
(* met FIPS 203 (ML-KEM) te garanderen en menselijke fouten bij het *)
(* kiezen van seeds uit te sluiten. Dit bestand blijft behouden als *)
(* referentie en om de vergelijking tussen beide ontwerpen te *)
(* documenteren. *)
(* ================================================================= *)
require import AllCore Int Real Distr List.
require import StdOrder.
import IntOrder.

(* ----------------------------------------------------------------- *)
(* Typesynoniemen *)
(* ----------------------------------------------------------------- *)
type seed.
type pkey.  (* publieke sleutel *)
type skey.  (* geheime sleutel *)
type ctxt.  (* ciphertext / encapsulatie *)
type ss.    (* gedeeld geheim (shared secret) *)

op dseed : seed distr.  (* uniforme verdeling over seeds *)
axiom dseed_ll : is_lossless dseed.

(* ----------------------------------------------------------------- *)
(* Abstracte KEM-interface met expliciete seed-parameter *)
(* ----------------------------------------------------------------- *)
module type PQC_KEM_Seeded = {
  proc keygen(sd : seed) : pkey * skey
  proc encaps(pk : pkey) : ctxt * ss
  proc decaps(sk : skey, c : ctxt) : ss option
}.

(* ----------------------------------------------------------------- *)
(* Correctheidseis: decaps(encaps(pk)) herstelt het gedeelde geheim *)
(* voor elk sleutelpaar geproduceerd door keygen(sd), voor elke sd. *)
(* ----------------------------------------------------------------- *)
axiom kem_seeded_correct (KEM <: PQC_KEM_Seeded) (sd : seed) :
  hoare [KEM.keygen : arg = sd ==> true] =>
  hoare [KEM.decaps :
    arg = (res{-1}.`2, fst (res{-2})) ==>
    exists k, res = Some k].

(* ----------------------------------------------------------------- *)
(* IND-CCA2 spel voor de seed-gebaseerde interface *)
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
    k1       <$ dss;              (* willekeurig, onafhankelijk geheim *)
    b        <$ {0,1};
    b'       <@ A.distinguish(c, if b then k1 else k0);
    return (b' = b);
  }
}.

op dss : ss distr.
axiom dss_ll : is_lossless dss.

(* ----------------------------------------------------------------- *)
(* Kritiek punt van dit ontwerp: de seed is een externe invoer. *)
(* *)
(* Zwakte: als twee verschillende aanroepen van keygen dezelfde seed *)
(* ontvangen (bijvoorbeeld door een menselijke fout, een kapotte *)
(* RNG, of hergebruik van een testvector in productie), dan zijn de *)
(* geproduceerde sleutelparen identiek. Dit is een reÃ«el operationeel *)
(* risico dat geen enkele cryptografische aanname kan compenseren: *)
(* de veiligheid van het schema hangt af van een garantie die *)
(* buiten het schema zelf ligt (uniciteit van de seed). *)
(* ----------------------------------------------------------------- *)
lemma keygen_seed_reuse_collision (KEM <: PQC_KEM_Seeded) (sd : seed) :
  equiv [KEM.keygen ~ KEM.keygen : arg{1} = sd /\ arg{2} = sd ==> ={res}].
proof.
  (* Bewijsschema: een deterministische of zwak-gerandomiseerde keygen
   * die volledig herleidbaar is tot `sd` geeft bij gelijke seed
   * hetzelfde sleutelpaar. Dit lemma documenteert de aanname die
   * *impliciet* nodig is opdat dit ontwerp veilig zou zijn: seed-
   * uniciteit moet extern gegarandeerd worden. Het is precies dit
   * punt dat de probabilistische KeyGen-interface in
   * MRS_AUTH_KEM_Hybrid.ec elimineert.
   *)
  admit. (* Aanname, niet bewezen: dit is de expliciete zwakte van
            dit ontwerp die de motivatie vormt voor de vervanging. *)
qed.

(* ================================================================= *)
(* Einde van MRS_Kyber.ec *)
(* Vroege iteratie â€” vervangen door MRS_AUTH_KEM_Hybrid.ec *)
(* ================================================================= *)
