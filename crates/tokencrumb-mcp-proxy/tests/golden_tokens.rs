//! Differential tests on mandates: every token forged by the former implementation must
//! inspect, parse and bound identically, and our own forge must produce the same blocks.

mod common;

use common::{assert_outcome, golden, key, t0};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::biscuit_ops::{self, Attenuation, ForgeRequest};
use tokencrumb_mcp_proxy::token_contract::{Term, block_facts, metadata};

fn facts_json(facts: &[(String, Vec<Term>)]) -> Value {
    let mut map = serde_json::Map::new();
    for (name, values) in facts {
        map.insert(
            name.clone(),
            Value::Array(values.iter().map(Term::to_json).collect()),
        );
    }
    Value::Object(map)
}

#[test]
fn python_tokens_inspect_identically() {
    let corpus = golden("tokens.json");
    for (name, token) in corpus["tokens"].as_object().unwrap() {
        let token = token.as_str().unwrap();
        let want = &corpus["inspect"][name];
        let result = biscuit_ops::inspect(token);
        if let Some(message) = want.get("inspect_error") {
            assert_eq!(
                result.unwrap_err().message,
                message.as_str().unwrap(),
                "{name}"
            );
            continue;
        }
        let r = result.unwrap_or_else(|e| panic!("{name}: {}", e.message));
        assert_eq!(
            json!(r.block_count),
            want["block_count"],
            "{name}: block_count"
        );
        assert_eq!(
            json!(r.revocation_ids),
            want["revocation_ids"],
            "{name}: revocation_ids"
        );
        assert_eq!(
            json!(r.root_key_id),
            want["root_key_id"],
            "{name}: root_key_id"
        );
        assert_eq!(json!(r.blocks), want["blocks"], "{name}: blocks");
        assert_eq!(facts_json(&r.facts), want["facts"], "{name}: facts");
        assert_outcome(
            &format!("{name}: metadata"),
            &want["metadata"],
            &metadata(&r.blocks),
            |m| m.to_json(),
        );
        for (i, source) in r.blocks.iter().enumerate() {
            assert_outcome(
                &format!("{name}: block_facts[{i}]"),
                &want["block_facts"][i],
                &block_facts(source, true, false),
                |f| f.to_json(),
            );
            assert_outcome(
                &format!("{name}: block_facts_inspect[{i}]"),
                &want["block_facts_inspect"][i],
                &block_facts(source, false, true),
                |f| f.to_json(),
            );
        }
        assert_outcome(
            &format!("{name}: capability_key"),
            &want["capability_key"],
            &biscuit_ops::capability_key(token),
            |k| json!(k),
        );
        assert_outcome(
            &format!("{name}: min_budget_cap"),
            &want["min_budget_cap"],
            &biscuit_ops::min_budget_cap(token),
            |c| json!(c),
        );
        assert_outcome(
            &format!("{name}: agent_id"),
            &want["authority_agent_id"],
            &biscuit_ops::authority_agent_id(token),
            |t| t.as_ref().map(Term::to_json).unwrap_or(Value::Null),
        );
    }
}

/// Replace every date literal so two forges a few milliseconds apart compare equal.
fn undated(source: &str) -> String {
    regex::Regex::new(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
        .unwrap()
        .replace_all(source, "<date>")
        .into_owned()
}

#[test]
fn forge_emits_the_same_blocks() {
    let corpus = golden("tokens.json");
    let authority = key("authority", "private");
    let agent = key("agent", "public");
    let base = ForgeRequest {
        agent_id: "agent-1".into(),
        tool: "read_file".into(),
        operation: "read".into(),
        ttl_seconds: 3600,
        budget: 200,
        audience: "test-gw".into(),
        ..Default::default()
    };
    let cases = [
        (
            "native",
            ForgeRequest {
                resource_prefix: Some("/projects/acme/".into()),
                ..base.clone()
            },
        ),
        (
            "hardened",
            ForgeRequest {
                agent_id: "agent-rag-01".into(),
                tool: "execute_sql".into(),
                operation: "write".into(),
                budget: 20,
                resource_prefix: Some("analytics".into()),
                agent_pubkey: Some(agent.clone()),
                required_profile: "hardened_biscuit_anchored".into(),
                ..base.clone()
            },
        ),
        (
            "scoped",
            ForgeRequest {
                tool: "get_incident".into(),
                facts: vec![
                    "assigned_incident(\"INC-1\")".into(),
                    "assigned_incident(\"INC-3\")".into(),
                ],
                scope_args: vec!["incident_id=assigned_incident".into()],
                ..base.clone()
            },
        ),
        (
            "upstream_catalog",
            ForgeRequest {
                tool: "search_objects".into(),
                upstream: Some("catalog".into()),
                facts: vec!["right(\"get_stock\", \"read\")".into()],
                ..base.clone()
            },
        ),
        (
            "depth1",
            ForgeRequest {
                resource_prefix: Some("/projects/acme/".into()),
                max_delegation_depth: Some(1),
                ..base.clone()
            },
        ),
    ];
    for (name, request) in cases {
        let ours =
            biscuit_ops::inspect(&biscuit_ops::forge_at(&authority, &request, t0()).unwrap())
                .unwrap();
        let theirs: Vec<String> =
            serde_json::from_value(corpus["inspect"][name]["blocks"].clone()).unwrap();
        assert_eq!(
            ours.blocks.iter().map(|b| undated(b)).collect::<Vec<_>>(),
            theirs.iter().map(|b| undated(b)).collect::<Vec<_>>(),
            "{name}"
        );
    }
    // Attenuation blocks too.
    let native = corpus["tokens"]["native"].as_str().unwrap();
    let public = key("authority", "public");
    let ours = biscuit_ops::attenuate_at(
        native,
        &public,
        &Attenuation {
            budget: Some(2),
            ..Default::default()
        },
        t0(),
    )
    .unwrap();
    assert_eq!(
        biscuit_ops::inspect(&ours).unwrap().blocks,
        corpus["inspect"]["native_attenuated_budget"]["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    let ours = biscuit_ops::attenuate_at(
        native,
        &public,
        &Attenuation {
            ttl_seconds: Some(600),
            ..Default::default()
        },
        t0(),
    )
    .unwrap();
    let theirs = corpus["inspect"]["native_attenuated_ttl"]["blocks"][1]
        .as_str()
        .unwrap();
    assert_eq!(
        undated(&biscuit_ops::inspect(&ours).unwrap().blocks[1]),
        undated(theirs)
    );
}

#[test]
fn forge_and_attenuate_refusals() {
    let corpus = golden("forge_errors.json");
    let authority = key("authority", "private");
    let base = ForgeRequest {
        agent_id: "agent-1".into(),
        tool: "read_file".into(),
        operation: "read".into(),
        ttl_seconds: 3600,
        budget: 200,
        audience: "test-gw".into(),
        ..Default::default()
    };
    let forge = |r: ForgeRequest| biscuit_ops::forge(&authority, &r).map(|_| ());
    let check = |label: &str, result: tokencrumb_mcp_proxy::Result<()>| {
        assert_outcome(label, &corpus[label], &result, |_| Value::Null)
    };
    check(
        "no_audience",
        forge(ForgeRequest {
            audience: " ".into(),
            ..base.clone()
        }),
    );
    check(
        "ttl0",
        forge(ForgeRequest {
            ttl_seconds: 0,
            ..base.clone()
        }),
    );
    check(
        "neg_budget",
        forge(ForgeRequest {
            budget: -1,
            ..base.clone()
        }),
    );
    check(
        "bad_profile",
        forge(ForgeRequest {
            required_profile: "gold".into(),
            ..base.clone()
        }),
    );
    check(
        "bad_agent",
        forge(ForgeRequest {
            agent_id: " x".into(),
            ..base.clone()
        }),
    );
    check(
        "bad_pub",
        forge(ForgeRequest {
            agent_pubkey: Some("ed25519/12".into()),
            ..base.clone()
        }),
    );
    check(
        "reserved_fact",
        forge(ForgeRequest {
            facts: vec!["audience(\"x\")".into()],
            ..base.clone()
        }),
    );
    check(
        "bad_scope",
        forge(ForgeRequest {
            scope_args: vec!["a=B".into()],
            ..base.clone()
        }),
    );
    check(
        "bad_prefix",
        forge(ForgeRequest {
            resource_prefix: Some("../x".into()),
            ..base.clone()
        }),
    );
    let native = golden("tokens.json")["tokens"]["native"]
        .as_str()
        .unwrap()
        .to_owned();
    let attenuate =
        |public: &str, a: Attenuation| biscuit_ops::attenuate(&native, public, &a).map(|_| ());
    check(
        "attenuate_nothing",
        attenuate(&key("authority", "public"), Attenuation::default()),
    );
    check(
        "attenuate_wrong_key",
        attenuate(
            &key("attacker", "public"),
            Attenuation {
                budget: Some(1),
                ..Default::default()
            },
        ),
    );
    check(
        "attenuate_depth0",
        attenuate(
            &key("authority", "public"),
            Attenuation {
                max_delegation_depth: Some(0),
                ..Default::default()
            },
        ),
    );
}
