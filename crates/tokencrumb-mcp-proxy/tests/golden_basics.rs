//! Differential tests: canonicalization, JSON, durations and fact specs must match the
//! reference corpus produced by the former Python implementation, byte for byte.

mod common;

use common::{assert_outcome, golden};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::biscuit_ops::{FactArg, parse_fact_spec, parse_scope_arg};
use tokencrumb_mcp_proxy::canonical::{
    arguments_hash, canonicalize_arg, canonicalize_prefix, canonicalize_resource,
};
use tokencrumb_mcp_proxy::duration::parse_duration;
use tokencrumb_mcp_proxy::json::{canonicalize, strict_json};

#[test]
fn resources_prefixes_and_args() {
    let corpus = golden("canonical.json");
    for (raw, expected) in corpus["resource"].as_object().unwrap() {
        assert_outcome(
            &format!("resource {raw:?}"),
            expected,
            &canonicalize_resource(raw),
            |s| json!(s),
        );
    }
    for (raw, expected) in corpus["prefix"].as_object().unwrap() {
        assert_outcome(
            &format!("prefix {raw:?}"),
            expected,
            &canonicalize_prefix(raw),
            |s| json!(s),
        );
    }
    for (raw, expected) in corpus["arg"].as_object().unwrap() {
        assert_outcome(
            &format!("arg {raw:?}"),
            expected,
            &canonicalize_arg(&json!(raw)),
            |s| json!(s),
        );
    }
    let types = &corpus["arg_types"];
    assert_outcome(
        "null",
        &types["null"],
        &canonicalize_arg(&Value::Null),
        |s| json!(s),
    );
    assert_outcome("int", &types["int"], &canonicalize_arg(&json!(12)), |s| {
        json!(s)
    });
    assert_outcome(
        "list",
        &types["list"],
        &canonicalize_arg(&json!(["a"])),
        |s| json!(s),
    );
}

#[test]
fn arguments_hash_and_jcs() {
    for (raw, expected) in golden("arguments_hash.json").as_object().unwrap() {
        let parsed = match strict_json(raw) {
            Ok(v) => v,
            Err(e) => panic!("{raw}: strict parse failed: {}", e.message),
        };
        match expected.get("ok") {
            Some(hash) => {
                let jcs = String::from_utf8(canonicalize(&parsed).unwrap()).unwrap();
                assert_eq!(jcs, expected["jcs"].as_str().unwrap(), "jcs of {raw}");
                assert_eq!(
                    &json!(arguments_hash(&parsed).unwrap()),
                    hash,
                    "hash of {raw}"
                );
            }
            None => {
                let err = arguments_hash(&parsed).unwrap_err();
                assert_eq!(err.message, expected["message"].as_str().unwrap(), "{raw}");
            }
        }
    }
}

#[test]
fn strict_json_accepts_and_refuses_like_python() {
    // The corpus holds a lone surrogate (Python accepts it at parse time); serde_json
    // cannot even load that file verbatim, so the case is marked and checked apart.
    let text = std::fs::read_to_string(common::golden_path("strict_json.json")).unwrap();
    let text = text
        .replace(r"\\ud800", "KEY-LONE")
        .replace(r"\ud800", "LONE");
    let corpus: Value = serde_json::from_str(&text).unwrap();
    assert!(
        strict_json(br#"{"a":"\ud800"}"#).is_err(),
        "lone surrogate refused"
    );
    for (raw, expected) in corpus.as_object().unwrap() {
        if raw.contains("KEY-LONE") {
            continue;
        }
        let got = strict_json(raw);
        match (expected.get("ok"), &got) {
            (Some(want), Ok(v)) => {
                // Numbers compare by value: the corpus stores Python's rendering.
                assert_eq!(
                    tokencrumb_mcp_proxy::json::dumps(v),
                    tokencrumb_mcp_proxy::json::dumps(want),
                    "{raw:?}"
                );
            }
            (None, Err(_)) => {}
            (Some(_), Err(e)) => panic!("{raw:?}: expected ok, got {}", e.message),
            (None, Ok(v)) => panic!("{raw:?}: expected refusal, got {v}"),
        }
    }
}

#[test]
fn durations() {
    for (raw, expected) in golden("duration.json").as_object().unwrap() {
        assert_outcome(
            &format!("duration {raw:?}"),
            expected,
            &parse_duration(raw),
            |n| json!(*n as i64),
        );
    }
}

fn fact_args(args: &[FactArg]) -> Value {
    Value::Array(
        args.iter()
            .map(|a| match a {
                FactArg::Str(s) => json!(s),
                FactArg::Int(i) => json!(i),
            })
            .collect(),
    )
}

#[test]
fn fact_and_scope_specs() {
    let corpus = golden("fact_spec.json");
    for (raw, expected) in corpus["fact"].as_object().unwrap() {
        assert_outcome(
            &format!("fact {raw:?}"),
            expected,
            &parse_fact_spec(raw),
            |(p, a)| json!([p, fact_args(a)]),
        );
    }
    for (raw, expected) in corpus["scope"].as_object().unwrap() {
        assert_outcome(
            &format!("scope {raw:?}"),
            expected,
            &parse_scope_arg(raw),
            |(a, p)| json!([a, p]),
        );
    }
    for (raw, expected) in corpus["profiles"]["rank"].as_object().unwrap() {
        assert_outcome(
            &format!("rank {raw}"),
            expected,
            &tokencrumb_mcp_proxy::profiles::rank(raw),
            |r| json!(r),
        );
    }
}
