use std::collections::HashMap;
use std::path::Path;

use sanct_classifier::features::{is_letter, is_upper, is_word_char, Extractor};
use sanct_classifier::model::Model;
use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

#[derive(Deserialize)]
struct Fixture {
    weights_sha256: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    subject: String,
    body: String,
    tokens: Vec<Vec<String>>,
    vector: HashMap<String, f64>,
    logit: f64,
}

#[derive(Deserialize)]
struct UnicodeTables {
    unicode_version: String,
    word: Vec<[u32; 2]>,
    letter: Vec<[u32; 2]>,
    upper: Vec<[u32; 2]>,
    unassigned: Vec<[u32; 2]>,
    lower: HashMap<String, String>,
    nfkc: HashMap<String, String>,
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn contains(ranges: &[[u32; 2]], cp: u32) -> bool {
    ranges
        .binary_search_by(|r| {
            if r[1] < cp {
                std::cmp::Ordering::Less
            } else if r[0] > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn check_fixture(path: &Path) -> usize {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let model = Model::load(&root().join("models/sanct-spam.json")).unwrap();
    assert_eq!(
        fixture.weights_sha256, model.weights_sha256,
        "fixture was generated for a different model; rerun `uv run python -m training.golden`"
    );
    let extractor = Extractor::new().unwrap();
    for (n, case) in fixture.cases.iter().enumerate() {
        let tokens = extractor.tokens(&case.subject, &case.body);
        assert_eq!(tokens.to_vec(), case.tokens, "token mismatch in case {n}");

        let vector = extractor.vectorize(&case.subject, &case.body);
        assert_eq!(
            vector.len(),
            case.vector.len(),
            "vector size mismatch in case {n}"
        );
        for (index, expected) in &case.vector {
            let actual = vector[&index.parse::<u32>().unwrap()];
            assert!(
                (actual - expected).abs() <= 1e-9,
                "vector value mismatch in case {n} at {index}: {actual} vs {expected}"
            );
        }
        let logit = model.logit(&vector);
        assert!(
            (logit - case.logit).abs() <= 1e-4,
            "logit mismatch in case {n}: {logit} vs {}",
            case.logit
        );
    }
    fixture.cases.len()
}

#[test]
fn edge_cases_match_python() {
    assert!(check_fixture(&root().join("tests/fixtures/parity.json")) > 0);
}

#[test]
#[ignore = "needs data/parity_corpus.json from `uv run python -m training.golden`"]
fn corpus_matches_python() {
    let checked = check_fixture(&root().join("data/parity_corpus.json"));
    println!("checked {checked} corpus emails");
}

#[test]
fn unicode_tables_match_python_for_assigned_code_points() {
    let tables: UnicodeTables =
        serde_json::from_slice(&std::fs::read(root().join("tests/fixtures/unicode.json")).unwrap())
            .unwrap();
    let mut mismatches = Vec::new();
    for cp in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        if contains(&tables.unassigned, cp) {
            continue;
        }
        if is_word_char(c) != contains(&tables.word, cp) {
            mismatches.push(format!("word U+{cp:04X}"));
        }
        if is_letter(c) != contains(&tables.letter, cp) {
            mismatches.push(format!("letter U+{cp:04X}"));
        }
        if is_upper(c) != contains(&tables.upper, cp) {
            mismatches.push(format!("upper U+{cp:04X}"));
        }
        let key = cp.to_string();
        let lowered: String = c.to_lowercase().collect();
        let expected_lower = tables
            .lower
            .get(&key)
            .cloned()
            .unwrap_or_else(|| c.to_string());
        if lowered != expected_lower {
            mismatches.push(format!("lower U+{cp:04X}"));
        }
        let normalized: String = c.to_string().nfkc().collect();
        let expected_nfkc = tables
            .nfkc
            .get(&key)
            .cloned()
            .unwrap_or_else(|| c.to_string());
        if normalized != expected_nfkc {
            mismatches.push(format!("nfkc U+{cp:04X}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches against Python Unicode {}: {:?}",
        mismatches.len(),
        tables.unicode_version,
        &mismatches[..mismatches.len().min(40)]
    );
}
