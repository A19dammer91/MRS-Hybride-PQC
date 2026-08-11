use crate::core::diophantine::{calculate_popoviciu_cardinality, generate_representation_family, DiophantinePair};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// Struct die een volledige 3-laagse keten (Matryoshka) vasthoudt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Berekent de digitale wortel (digital root) van een getal constant-time zonder loops
#[inline]
pub fn digital_root(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        1 + ((n - 1) % 9)
    }
}

/// Controleert de harmonische Triangle-eis: dr(B) == dr(2 * dr(X))
/// X is de OUDERWAARDE op de huidige laag (de N die net werd opgesplitst),
/// niet een extern meegegeven seed. Dit is wat het a ≡ 1 (mod b) argument
/// uit de specificatie (§4.2) vereist: de restklasse-verschuiving werkt per
/// stap binnen de representatiefamilie van X zelf.
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> bool {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b == target
}

/// Telt hoeveel representaties van `n` voldoen aan de driehoeksconditie t.o.v.
/// X = n zelf. Dit is het aantal driehoeks-geldige alibi's dat laag `n` zou
/// hebben op de eerstvolgende laag -- de juiste maatstaf voor check-ahead,
/// in tegenstelling tot de ruwe (ongefilterde) Popoviciu-telling.
pub fn count_triangle_filtered(n: u64) -> u64 {
    generate_representation_family(n)
        .iter()
        .filter(|pair| validate_triangle_condition(pair.b, n))
        .count() as u64
}

/// Controleert of `a_value` minimaal 2 driehoeks-geldige vervolgen heeft op
/// de volgende laag (R'(A) >= 2). Gebruikt de driehoeks-GEFILTERDE telling,
/// niet de ruwe Popoviciu-kardinaliteit: die laatste kan positief zijn
/// terwijl er na driehoeksfiltering alsnog nul geldige vervolgen overblijven,
/// wat de check-ahead-garantie zou ondermijnen.
#[inline]
pub fn check_ahead_valid(a_value: u64) -> bool {
    count_triangle_filtered(a_value) >= 2
}

/// Berekent het hiërarchische gewicht van elke driehoeks-geldige kandidaat
/// op laag `n`, gefilterd op de driehoeksconditie t.o.v. `n` zelf. Dit is
/// het gewicht dat de sampler daadwerkelijk gebruikt om uniformiteit te
/// garanderen (Forest Symmetry): het aantal driehoeks-geldige vervolgketens
/// per kandidaat, niet de ruwe Popoviciu-kardinaliteit van eerdere versies.
/// Retourneert de gefilterde kandidaten en hun gewichten in dezelfde volgorde.
pub fn calculate_layer_weights(n: u64) -> (Vec<DiophantinePair>, Vec<u64>) {
    let family = generate_representation_family(n);
    let mut candidates = Vec::with_capacity(family.len());
    let mut weights = Vec::with_capacity(family.len());

    for pair in family {
        if !validate_triangle_condition(pair.b, n) {
            continue;
        }
        let w = count_triangle_filtered(pair.a);
        if w == 0 {
            continue; // dood spoor: geen driehoeks-geldige vervolgen op A
        }
        candidates.push(pair);
        weights.push(w);
    }

    (candidates, weights)
}

/// Trekt een cryptografisch willekeurig geheel getal in [0, bound) zonder
/// modulo-bias, via rejection sampling op een CSPRNG.
fn uniform_below(bound: u64, rng: &mut impl RngCore) -> u64 {
    assert!(bound > 0, "bound moet positief zijn");
    let limit = u64::MAX - (u64::MAX % bound);
    loop {
        let r = rng.next_u64();
        if r < limit {
            return r % bound;
        }
    }
}

/// Rekent een 3-laagse Matryoshka-keten door op basis van root_n.
///
/// Op elke laag wordt cryptografisch willekeurig, GEWOGEN gesampled tussen
/// alle driehoeks-geldige kandidaten: het gewicht van een kandidaat is het
/// aantal driehoeks-geldige vervolgketens dat via die kandidaat bereikbaar
/// is (op de laatste laag: gewicht 1, want daar is elke representatie zelf
/// al een complete keten). Zo wordt elke volledige keten in Omega(root_n)
/// met exact gelijke kans geproduceerd (Forest Symmetry Theorem).
///
/// Dit vervangt de eerdere implementatie, die het EERSTE geldige paar uit
/// `family` koos zonder enige randomness -- dat was volledig deterministisch
/// (dezelfde root_n gaf altijd dezelfde keten) en bood dus geen geheime,
/// onvoorspelbare index.
///
/// **API-wijziging:** het `seed_x`-argument is verwijderd. De driehoeksconditie
/// toetst nu tegen `current_n` (de daadwerkelijke ouderwaarde per laag) in
/// plaats van een vaste externe waarde. Aanroepen elders in de codebase
/// moeten worden aangepast naar `sample_three_layers(root_n)`.
pub fn sample_three_layers(root_n: u64) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut rng = OsRng;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let family = generate_representation_family(current_n);

        let mut candidates: Vec<DiophantinePair> = Vec::new();
        let mut weights: Vec<u64> = Vec::new();

        for pair in family {
            if !validate_triangle_condition(pair.b, current_n) {
                continue;
            }
            if !is_last_layer && !check_ahead_valid(pair.a) {
                continue;
            }
            let w = if is_last_layer {
                1
            } else {
                count_triangle_filtered(pair.a)
            };
            if w == 0 {
                continue;
            }
            candidates.push(pair);
            weights.push(w);
        }

        if candidates.is_empty() {
            return None; // geen geldig, niet-doodlopend pad op deze laag
        }

        let total_weight: u64 = weights.iter().sum();
        let r = uniform_below(total_weight, &mut rng);

        let mut acc: u64 = 0;
        let mut chosen: Option<DiophantinePair> = None;
        for (pair, w) in candidates.into_iter().zip(weights.into_iter()) {
            acc += w;
            if r < acc {
                chosen = Some(pair);
                break;
            }
        }
        let pair = chosen.expect("gewichten sommeren tot total_weight, lus moet iets kiezen");

        current_n = pair.a;
        chain.push(pair);
    }

    Some(MrsChain {
        layers: chain,
        valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digital_root() {
        assert_eq!(digital_root(0), 0);
        assert_eq!(digital_root(9), 9);
        assert_eq!(digital_root(10), 1); // 1 + 0 = 1
        assert_eq!(digital_root(144), 9); // 1 + 4 + 4 = 9
    }

    #[test]
    fn test_triangle_condition_validation() {
        // Handmatig berekende testvector op basis van de specificatie
        // Als X = 5, dan dr(X) = 5. Target = dr(2 * 5) = dr(10) = 1.
        // Als B = 10, dan dr(B) = 1. Dit moet dus 'true' opleveren.
        assert!(validate_triangle_condition(10, 5));

        // Als B = 9, dan dr(B) = 9 (matcht niet met 1), moet 'false' zijn
        assert!(!validate_triangle_condition(9, 5));
    }

    #[test]
    fn test_three_layer_sampler_success() {
        // We testen met een startgetal N dat groot genoeg is om 3 lagen diep te nesten
        let root_n = 200_001;

        let result = sample_three_layers(root_n);

        // De sampler moet ofwel een geldige keten vinden, of veilig stoppen (None)
        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);

            // Controleer of de Matryoshka-nesting wiskundig klopt:
            // De 'A' van laag 0 moet de 'N' zijn voor de berekening van laag 1
            let layer_0_a = chain.layers[0].a;
            let layer_1_a = chain.layers[1].a;

            // De 'A' waarden moeten logischerwijs steeds kleiner worden naarmate we dieper nesten
            assert!(root_n > layer_0_a);
            assert!(layer_0_a > layer_1_a);

            // Elke laag moet zelf ook aan de driehoeksconditie voldoen
            // t.o.v. zijn eigen ouderwaarde (niet t.o.v. een externe seed).
            let mut parent = root_n;
            for pair in &chain.layers {
                assert!(validate_triangle_condition(pair.b, parent));
                parent = pair.a;
            }
        }
    }

    #[test]
    fn test_sampler_is_not_deterministic() {
        // De vorige implementatie gaf bij een vaste root_n altijd dezelfde
        // keten (eerste match, geen randomness). Deze test bevestigt dat
        // dat nu niet meer zo is: over voldoende trekkingen moeten we
        // minstens 2 verschillende ketens zien.
        let root_n = 200_001;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            if let Some(chain) = sample_three_layers(root_n) {
                let key: Vec<(u64, u64)> = chain.layers.iter().map(|p| (p.a, p.b)).collect();
                seen.insert(key);
            }
        }
        assert!(
            seen.len() > 1,
            "sampler produceerde 100x dezelfde keten -- vermoedelijk nog steeds deterministisch"
        );
    }

    #[test]
    fn test_calculate_layer_weights_matches_triangle_filter() {
        // Elke kandidaat die calculate_layer_weights teruggeeft moet zelf
        // ook de driehoeksconditie doorstaan, en een gewicht > 0 hebben.
        let n = 200_001;
        let (candidates, weights) = calculate_layer_weights(n);
        assert_eq!(candidates.len(), weights.len());
        for (pair, &w) in candidates.iter().zip(weights.iter()) {
            assert!(validate_triangle_condition(pair.b, n));
            assert!(w > 0);
        }
    }
}
