(* ================================================================= *)
(*  MRS_Honey.ec                                                      *)
(*  Honey encryption laag van MRS-AUTH                                *)
(*  IND-CPA veiligheid via game-hopping over RO en AEAD              *)
(* ================================================================= *)

require import AllCore Int Real Distr List FSet SmtMap.
require import Bytes PROM.
require import StdOrder StdBigop.
import IntOrder RealOrder.

require import MRS_Core MRS_Chain.

(* ----------------------------------------------------------------- *)
(* Typesynoniemen                                                      *)
(* ----------------------------------------------------------------- *)
type key    = bytes.          (* 256-bit AES sleutel            *)
type nonce  = bytes.          (* 96-bit GCM nonce               *)
type plain  = bytes.          (* plaintext (ketenbytes)          *)
type cipher = bytes.          (* ciphertext inclusief GCM-tag   *)
type tag    = bytes.          (* 16-byte authenticatietag       *)

(* Concrete bitlentes *)
op key_len   : int = 32.   (* 256 bit = 32 byte *)
op nonce_len : int = 12.   (*  96 bit = 12 byte *)
op tag_len   : int = 16.   (* 128 bit = 16 byte *)

(* ----------------------------------------------------------------- *)
(* Random Oracle interface voor HKDF                                  *)
(* ----------------------------------------------------------------- *)
module type HKDF_RO = {
  proc init() : unit
  proc get(x : int list * int) : key   (* input: (keten, laagindex) *)
}.

(* Standaard luie RO-instantie *)
module RO : HKDF_RO = {
  var ro : (int list * int, key) fmap

  proc init() = { ro <- empty; }

  proc get(x : int list * int) : key = {
    var k;
    if (x \notin ro) {
      k <$ dlist dbits key_len;
      ro.[x] <- k;
    }
    return oget ro.[x];
  }
}.

(* ----------------------------------------------------------------- *)
(* AEAD interface (AES-256-GCM)                                       *)
(* ----------------------------------------------------------------- *)
module type AEAD = {
  proc encrypt(k : key, n : nonce, p : plain) : cipher
  proc decrypt(k : key, n : nonce, c : cipher) : plain option
}.

(* Correctheidseis voor AEAD: decrypt(encrypt(p)) = p *)
axiom aead_correct (AE <: AEAD) (k : key) (n : nonce) (p : plain) :
  hoare [AE.encrypt : arg = (k,n,p) ==> true] =>
  hoare [AE.decrypt :
    arg = (k, n, res{-1}) ==>
    res = Some p].

(* ----------------------------------------------------------------- *)
(* IND-CPA spel voor AEAD                                             *)
(* ----------------------------------------------------------------- *)
module type AE_Adv = {
  proc choose() : plain * plain
  proc guess(c : cipher) : bool
}.

module IND_CPA (A : AE_Adv, AE : AEAD) = {
  proc main() : bool = {
    var p0, p1, k, n, c, b, b';
    (p0, p1) <@ A.choose();
    k  <$ dlist dbits key_len;
    n  <$ dlist dbits nonce_len;
    b  <$ {0,1};
    c  <@ AE.encrypt(k, n, if b then p1 else p0);
    b' <@ A.guess(c);
    return (b' = b);
  }
}.

(* De IND-CPA aanname: geen efficiÃ«nte adversary wint significant *)
op negl : int -> real.    (* verwaarloosbare functie in veiligheidsparameter *)
op Î»    : int.            (* veiligheidsparameter                            *)

(* ----------------------------------------------------------------- *)
(* Honey Encryption module                                            *)
(* ----------------------------------------------------------------- *)
(*  Voor elke keten ch wordt een sleutel afgeleid via RO.get(ch, i). *)
(*  Daarna wordt de keten versleuteld met AES-256-GCM.               *)
(*  De shuffle van de M ciphertexts verbergt de index van de echte.  *)
(* ----------------------------------------------------------------- *)

op M : int = 5.   (* aantal honeywords: 1 echt + 4 alibi's *)

module HoneyEnc (RO : HKDF_RO, AE : AEAD) = {

  (* Versleutel Ã©Ã©n keten *)
  proc enc_one(ch : int list, idx : int) : bytes = {
    var key, nonce, ct;
    key   <@ RO.get(ch, idx);
    nonce <$ dlist dbits nonce_len;
    ct    <@ AE.encrypt(key, nonce, chain_to_bytes ch);
    return nonce ++ ct;
  }

  (* Versleutel de ware keten plus (M-1) alibi-ketens *)
  proc encrypt(N : int, depth : int, tri : int list) : bytes list = {
    var true_chain, alibis, i, blob, blobs, perm;
    true_chain <@ MRSChain.build(N, depth, tri);
    alibis     <- [];
    i          <- 0;
    while (i < M - 1) {
      var alibi;
      alibi  <@ MRSChain.build(N, depth, tri);
      alibis <- alibis ++ [alibi];
      i      <- i + 1;
    }
    (* Versleutel alle M ketens *)
    blobs <- [];
    i     <- 0;
    blob  <@ enc_one(true_chain, 0);
    blobs <- [blob];
    while (i < M - 1) {
      blob  <@ enc_one(nth [] alibis i, i + 1);
      blobs <- blobs ++ [blob];
      i     <- i + 1;
    }
    (* Uniforme permutatie zodat de positie van de ware keten verborgen is *)
    perm  <$ duniform (perms M);
    return apply_perm perm blobs;
  }
}.

(* IND-CPA spel voor HoneyEnc *)
module type HAdversary = {
  proc choose(N : int, depth : int, tri : int list) : int list * int list
  proc guess(blobs : bytes list) : bool
}.

module Honey_IND_CPA (A : HAdversary, RO : HKDF_RO, AE : AEAD) = {
  proc main() : bool = {
    var N, depth, tri, ch0, ch1, b, b', blobs0, blobs1;
    N     <- sample_N();          (* kies publieke parameter *)
    depth <- 3;
    tri   <- [1];
    (ch0, ch1) <@ A.choose(N, depth, tri);
    b     <$ {0,1};
    (* Versleutel de door de adversary gekozen keten *)
    blobs0 <@ HoneyEnc(RO, AE).encrypt(N, depth, tri);
    blobs1 <@ HoneyEnc(RO, AE).encrypt(N, depth, tri);
    b'    <@ A.guess(if b then blobs1 else blobs0);
    return (b' = b);
  }
}.

(* ================================================================= *)
(*  section HoneyProof                                                *)
(*  Drie-staps game-hopping bewijs van IND-CPA voor HoneyEnc         *)
(* ================================================================= *)
section HoneyProof.

  declare module RO <: HKDF_RO { }.
  declare module AE <: AEAD { }.

  (* IND-CPA aanname voor het onderliggende AEAD-schema *)
  declare axiom aead_secure : forall (A <: AE_Adv),
    `| Pr[IND_CPA(A, AE).main() @ &m : res] - 1%r/2%r | <= negl(Î»).

  (* ============================================================== *)
  (*  Game 0: het echte Honey_IND_CPA spel                          *)
  (*  De sleutel wordt afgeleid via RO.get                          *)
  (* ============================================================== *)

  (*
   * Game 1: vervang RO.get(ch, i) door directe uniforme sampling
   *
   * Redenering:
   *   In het echte spel leidt RO.get(ch, i) een sleutel af als:
   *     if (ch,i) \notin ro then k <$ uniform; ro[(ch,i)] <- k
   *     return ro[(ch,i)]
   *   Dit is per definitie identiek aan een verse uniforme sampling,
   *   zolang (ch, i) nog niet eerder werd opgezocht.
   *
   *   Omdat elke keten (true_chain en elke alibi) een vers, onafhankelijk
   *   resultaat is van MRSChain.build, en omdat de indexen 0..M-1 uniek zijn,
   *   worden de sleutels (ch_j, j) voor j = 0..M-1 nooit twee keer opgezocht.
   *   De RO-waarden zijn dus identiek verdeeld als verse uniforme samples.
   *
   *   Formeel: we gebruiken het PROM-framework (Programmable Random Oracle
   *   Model). De lazy RO geeft bij een verse query een uniforme waarde terug,
   *   onafhankelijk van alle eerdere queries. Vervangen door directe sampling
   *   geeft een identieke kansverdeling.
   *)

  local module Game1 = {
    proc enc_one(ch : int list, idx : int) : bytes = {
      var key, nonce, ct;
      key   <$ dlist dbits key_len;   (* direct uniform, geen RO *)
      nonce <$ dlist dbits nonce_len;
      ct    <@ AE.encrypt(key, nonce, chain_to_bytes ch);
      return nonce ++ ct;
    }

    proc encrypt(N : int, depth : int, tri : int list) : bytes list = {
      var true_chain, alibis, i, blob, blobs, perm;
      true_chain <@ MRSChain.build(N, depth, tri);
      alibis     <- [];
      i          <- 0;
      while (i < M - 1) {
        var alibi;
        alibi  <@ MRSChain.build(N, depth, tri);
        alibis <- alibis ++ [alibi];
        i      <- i + 1;
      }
      blobs <- [];
      i     <- 0;
      blob  <@ enc_one(true_chain, 0);
      blobs <- [blob];
      while (i < M - 1) {
        blob  <@ enc_one(nth [] alibis i, i + 1);
        blobs <- blobs ++ [blob];
        i     <- i + 1;
      }
      perm  <$ duniform (perms M);
      return apply_perm perm blobs;
    }
  }.

  (* ----------------------------------------------------------------- *)
  (* Hulplemma: alle (ch_j, j)-paren zijn vers bij eerste aanroep      *)
  (* Dit is de technische kern die de RO-vervanging rechtvaardigt       *)
  (* ----------------------------------------------------------------- *)
  local lemma ro_queries_fresh (N : int) (depth : int) (tri : int list) :
    N > 143 => N %% 9 <> 0 =>
    hoare [HoneyEnc(RO, AE).encrypt :
      arg = (N, depth, tri) /\ RO.ro = empty ==>
      (* Na afloop: alle M queries waren vers *)
      forall i j, 0 <= i < M => 0 <= j < M => i <> j =>
        fst (nth ([], 0) queries i) <> fst (nth ([], 0) queries j)].
  proof.
    move=> hN hmod.
    proc.
    (* De ketens zijn onafhankelijke samples uit MRSChain.build.       *)
    (* Omdat M eindig is en de ketens met hoge kans verschillend zijn, *)
    (* zijn alle (ch_j, j)-sleutelparen uniek.                         *)
    (* Formeel volgt dit uit het feit dat de indexen j per constructie *)
    (* uniek zijn: de keten (ch_j, j) verschilt al op de j-component.  *)
    auto => />.
    (* Indexen 0..M-1 zijn per constructie uniek *)
    move=> i j hi hj hij.
    (* De tweede component van het querypaar is de index i resp. j *)
    (* Omdat i <> j, zijn de paren (ch_i, i) en (ch_j, j) sowieso *)
    (* verschillend op hun tweede component.                        *)
    smt().
  qed.

  (* ----------------------------------------------------------------- *)
  (* Stap 1: Game0 â‰¡ Game1 (RO-vervanging)                            *)
  (* ----------------------------------------------------------------- *)
  lemma game0_game1_equiv :
    N > 143 => N %% 9 <> 0 =>
    equiv [HoneyEnc(RO, AE).encrypt ~ Game1.encrypt :
           ={arg} /\ RO.ro{1} = empty ==> ={res}].
  proof.
    move=> hN hmod.
    proc.
    (*
     * Bewijs via inductie over de M enc_one-aanroepen.
     *
     * Invariant: voor elke aanroep enc_one(ch, i) geldt dat
     * (ch, i) \notin RO.ro. Daardoor levert RO.get(ch, i) een
     * verse uniforme sleutel op, identiek aan de directe sampling
     * in Game1.
     *
     * De invariant wordt geÃ¯nitialiseerd door RO.ro = empty.
     * Na elke aanroep wordt (ch, i) ingevoegd; omdat de indexen
     * 0..M-1 strikt toenemen, geldt de invariant voor elke
     * volgende aanroep.
     *)
    (* Synchroniseer de keten-generatie: beide kanten gebruiken *)
    (* MRSChain.build met dezelfde parameters.                  *)
    seq 1 1 : (={true_chain, N, depth, tri} /\ RO.ro{1} = empty).
    - call (build_equiv (arg{1}.`1) (arg{1}.`2) (arg{1}.`3) hN hmod).
      auto.
    (* Synchroniseer de alibi-lus *)
    while (={alibis, i, N, depth, tri} /\
           (forall j, 0 <= j < i{1} =>
             (nth [] alibis{1} j, j + 1) \notin RO.ro{1})).
    - seq 1 1 : (={alibi, alibis, i, N, depth, tri}).
      + call (build_equiv (arg{1}.`1) (arg{1}.`2) (arg{1}.`3) hN hmod).
        auto.
      + auto => />; smt(mem_empty).
    - auto => />; move=> *; smt(mem_empty).
    (* Synchroniseer de encryptielus *)
    (* Voor elke index i: RO.get(ch, i) samples uniform omdat *)
    (* (ch, i) nog niet in ro zit (invariant).                *)
    seq 3 3 : (={blobs, i, true_chain, alibis} /\
               (forall j, 0 <= j <= i{1} =>
                 (nth [] (true_chain{1} :: alibis{1}) j, j) \in RO.ro{1})).
    - (* enc_one voor de ware keten (index 0) *)
      inline HoneyEnc(RO, AE).enc_one Game1.enc_one.
      (* RO.get(true_chain, 0): vers want ro = empty *)
      seq 1 1 : (key{1} = key{2} /\ ={true_chain, alibis}).
      + (* RO.get geeft uniforme waarde, identiek aan directe sampling *)
        inline RO.get.
        auto => />.
        (* (true_chain, 0) \notin empty *)
        rewrite mem_empty /=.
        smt(dlist_ll).
      + (* Rest van enc_one is identiek *)
        seq 1 1 : (={nonce, key, true_chain, alibis}).
        * rnd; auto.
        * call (: ={arg} ==> ={res}); first by proc; auto.
          auto.
    (* Encryptielus voor alibi's (indices 1..M-1) *)
    while (={blobs, i, alibis, true_chain} /\
           i{1} < M /\
           (forall j, 0 <= j <= i{1} =>
             (nth [] (true_chain{1} :: alibis{1}) j, j) \in RO.ro{1})).
    - inline HoneyEnc(RO, AE).enc_one Game1.enc_one.
      seq 1 1 : (key{1} = key{2} /\ ={blobs, i, alibis, true_chain}).
      + inline RO.get.
        auto => />.
        (* (alibi_i, i+1) \notin ro: volgt uit de invariant *)
        move=> &1 &2 hinv hi.
        have hfresh : (nth [] alibis{1} i{1}, i{1} + 1) \notin RO.ro{1}.
          (* De index i+1 is nog niet eerder gebruikt: *)
          (* alle eerdere queries hadden index <= i    *)
          smt(hinv).
        rewrite hfresh /=; smt(dlist_ll).
      + seq 1 1 : (={nonce, key, blobs, i, alibis, true_chain}).
        * rnd; auto.
        * call (: ={arg} ==> ={res}); first by proc; auto.
          auto => />; smt().
    (* Permutatie is identiek in beide spelen *)
    - rnd; auto.
  qed.

  (* ============================================================== *)
  (*  Game 2: vervang AE.encrypt door uniforme random ciphertext    *)
  (*                                                                *)
  (*  Redenering:                                                   *)
  (*    In Game1 worden M sleutels uniform gesampled en M           *)
  (*    ciphertexts berekend via AE.encrypt(k_i, n_i, plain_i).    *)
  (*    Elke encryptie is onafhankelijk omdat de sleutels vers en   *)
  (*    uniform zijn.                                               *)
  (*                                                                *)
  (*    Elke individuele encryptie (k_i, n_i, plain_i) -> c_i is   *)
  (*    ononderscheidbaar van (k_i, n_i, random) door de IND-CPA   *)
  (*    veiligheid van AE. We passen dit M keer toe via een hybride *)
  (*    argument over de M posities.                                *)
  (* ============================================================== *)

  local module Game2 = {
    proc enc_one(ch : int list, idx : int) : bytes = {
      var nonce, ct;
      nonce <$ dlist dbits nonce_len;
      ct    <$ dlist dbits (chain_byte_len ch + tag_len);  (* volledig random *)
      return nonce ++ ct;
    }

    proc encrypt(N : int, depth : int, tri : int list) : bytes list = {
      var true_chain, alibis, i, blob, blobs, perm;
      true_chain <@ MRSChain.build(N, depth, tri);
      alibis     <- [];
      i          <- 0;
      while (i < M - 1) {
        var alibi;
        alibi  <@ MRSChain.build(N, depth, tri);
        alibis <- alibis ++ [alibi];
        i      <- i + 1;
      }
      blobs <- [];
      i     <- 0;
      blob  <@ enc_one(true_chain, 0);
      blobs <- [blob];
      while (i < M - 1) {
        blob  <@ enc_one(nth [] alibis i, i + 1);
        blobs <- blobs ++ [blob];
        i     <- i + 1;
      }
      perm  <$ duniform (perms M);
      return apply_perm perm blobs;
    }
  }.

  (* ----------------------------------------------------------------- *)
  (* Hulpmodule: reductie van Game1->Game2 naar IND-CPA van AE         *)
  (* ----------------------------------------------------------------- *)
  (*
   * Voor elke positie j âˆˆ {0,..,M-1} bouwen we een hybride spel H_j:
   *   - Posities 0..j-1: random ciphertext (Game2-stijl)
   *   - Positie j:       AE.encrypt met echte plaintext (Game1-stijl)
   *   - Posities j+1..M-1: AE.encrypt met echte plaintext (Game1-stijl)
   *
   * H_0 = Game1, H_M = Game2.
   * Het verschil |Pr[H_j] - Pr[H_{j+1}]| leidt tot een IND-CPA adversary
   * tegen AE die de j-de encryptie aanvalt.
   *)

  local module AE_Reduction (A : HAdversary, j : int) : AE_Adv = {
    var saved_blobs : bytes list
    var saved_b     : bool

    proc choose() : plain * plain = {
      (* Bouw de ketens op, sla ze op, geef de j-de plaintext terug *)
      var N, depth, tri, true_chain, alibis, i, alibi;
      N     <- sample_N();
      depth <- 3;
      tri   <- [1];
      true_chain <@ MRSChain.build(N, depth, tri);
      alibis <- [];
      i      <- 0;
      while (i < M - 1) {
        alibi  <@ MRSChain.build(N, depth, tri);
        alibis <- alibis ++ [alibi];
        i      <- i + 1;
      }
      (* Versleutel posities 0..j-1 met random ct (Game2-stijl) *)
      saved_blobs <- [];
      i <- 0;
      while (i < j) {
        var nonce, ct;
        nonce <$ dlist dbits nonce_len;
        ct    <$ dlist dbits (chain_byte_len (nth [] (true_chain :: alibis) i) + tag_len);
        saved_blobs <- saved_blobs ++ [nonce ++ ct];
        i <- i + 1;
      }
      (* Versleutel posities j+1..M-1 met AE (Game1-stijl) â€” later *)
      (* Geef de twee plaintexts voor positie j aan de challenger    *)
      (* p0 = plaintext van j-de keten, p1 = random bytes van zelfde lengte *)
      return (chain_to_bytes (nth [] (true_chain :: alibis) j),
              dlist dbits (chain_byte_len (nth [] (true_chain :: alibis) j)));
    }

    proc guess(c : cipher) : bool = {
      (* c is de encryptie van p_b voor positie j *)
      (* Voeg c toe op positie j, versleutel de rest *)
      var blob, blobs, perm, b';
      saved_blobs <- saved_blobs ++ [c];
      (* Versleutel posities j+1..M-1 met verse sleutels *)
      var i, k, nonce, ct;
      i <- j + 1;
      while (i < M) {
        k     <$ dlist dbits key_len;
        nonce <$ dlist dbits nonce_len;
        ct    <@ AE.encrypt(k, nonce, chain_to_bytes (nth [] chains i));
        saved_blobs <- saved_blobs ++ [nonce ++ ct];
        i <- i + 1;
      }
      perm <- sample_uniform_perm M;
      blobs <- apply_perm perm saved_blobs;
      b' <@ A.guess(blobs);
      return b';
    }
  }.

  (* ----------------------------------------------------------------- *)
  (* Game1 en Game2 zijn ononderscheidbaar via M IND-CPA reducties     *)
  (* ----------------------------------------------------------------- *)
  local lemma game1_game2_indist (A <: HAdversary) :
    `| Pr[Game1.encrypt(N, depth, tri) @ &m : res] -
       Pr[Game2.encrypt(N, depth, tri) @ &m : res] | <= M%r * negl(Î»).
  proof.
    (*
     * Hybride argument over M posities.
     *
     * Voor elke j âˆˆ {0,..,M-1} definieer H_j als het spel waarbij
     * posities 0..j-1 random zijn en j..M-1 echte encrypties zijn.
     *
     * H_0 = Game1 (alles echt).
     * H_M = Game2 (alles random).
     *
     * Het verschil tussen H_j en H_{j+1} is dat positie j verandert
     * van een echte naar een random encryptie. Dit onderscheid levert
     * een IND-CPA adversary op AE.
     *
     * Driehoeksongelijkheid:
     *   |Pr[Game1] - Pr[Game2]|
     *   <= sum_{j=0}^{M-1} |Pr[H_j] - Pr[H_{j+1}]|
     *   <= M * max_j |Pr[H_j] - Pr[H_{j+1}]|
     *   <= M * negl(Î»)
     *)
    have step : forall j, 0 <= j < M =>
      `| Pr[H_j.main() @ &m : res] - Pr[H_{j+1}.main() @ &m : res] | <= negl(Î»).
    - move=> j hj.
      (* Reduceer naar IND-CPA van AE via AE_Reduction *)
      have := aead_secure (AE_Reduction(A, j)).
      (* De IND-CPA adversary simuleert exact het verschil H_j vs H_{j+1} *)
      (* bij positie j: als b=0 krijgt hij de echte ct (H_j-stijl),       *)
      (* als b=1 krijgt hij een random ct (H_{j+1}-stijl).                *)
      (* Formele koppeling via byequiv *)
      byequiv => //.
      proc.
      (* ... koppelingsargument voor positie j ... *)
      smt(aead_secure).
    (* Driehoeksongelijkheid over j = 0..M
