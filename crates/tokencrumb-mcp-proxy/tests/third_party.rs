//! Third-party authorities: a second signer whose blocks the gateway believes predicate
//! by predicate, and only for the tools that require it (architecture decision 7).

mod common;

use std::collections::HashMap;

use biscuit_auth::{Biscuit, BlockBuilder, ThirdPartyRequest};
use common::proxy::{
    TEST_AUDIENCE, World, append_block, biscuit_headers, date_term, forge, in_seconds, mandate,
    verify,
};
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::attestation::build_attestation;
use tokencrumb_mcp_proxy::biscuit_ops::{
    self, Attenuation, Endorse, ForgeRequest, append_third_party, attenuate, sign_third_party,
    sign_third_party_at, third_party_request,
};
use tokencrumb_mcp_proxy::keys::{Keypair, biscuit_private, biscuit_public, generate_keypair};
use tokencrumb_mcp_proxy::policy::{Policy, parse_policy};
use tokencrumb_mcp_proxy::verifier::{Decision, Verifier, VerifierOptions};

const Q3: &str = "/projects/acme/q3.md";

fn policy_for(approver: &[&str]) -> Policy {
    parse_policy(&json!({
        "third_party": {"approver": {"keys": approver, "predicates": ["approval"]}},
        "tools": [
            {"name": "delete_file", "operation": "write", "resource": {"from": "arguments.path"},
             "require_third_party": [{"authority": "approver", "predicate": "approval"}]},
            {"name": "purge_cache", "operation": "write",
             "require_third_party": [{"authority": "approver"}]},
            {"name": "read_file", "operation": "read", "resource": {"from": "arguments.path"}},
        ],
    }))
    .unwrap()
}

struct Setup {
    world: World,
    approver: Keypair,
    verifier: std::sync::Arc<Verifier>,
}

fn setup() -> Setup {
    let world = World::new();
    let approver = generate_keypair();
    let verifier = world.verifier(
        policy_for(&[&approver.public_str]),
        Some(VerifierOptions::new(TEST_AUDIENCE)),
    );
    Setup {
        world,
        approver,
        verifier,
    }
}

fn token(s: &Setup, tool: &str) -> String {
    forge(
        &s.world.authority.private_str,
        mandate("agent-1", tool, "write", 600, 10),
    )
}

fn endorse(tool: &str, prefix: &str) -> Endorse {
    Endorse {
        predicate: "approval".into(),
        tools: vec![tool.into()],
        resource_prefix: prefix.into(),
        ttl_seconds: 300,
    }
}

/// The whole exchange: request from the holder, block from the third party, append.
fn endorsed(s: &Setup, token: &str, signer: &Keypair, what: &Endorse) -> String {
    let request = third_party_request(token, &s.world.authority.public_str).unwrap();
    let block = sign_third_party(&request, &signer.private_str, what).unwrap();
    append_third_party(token, &s.world.authority.public_str, &block, None).unwrap()
}

/// A raw third-party block, for what a careless or hostile third party could sign.
fn raw_endorsed(s: &Setup, token: &str, signer: &Keypair, code: &str) -> String {
    let root = biscuit_public(&s.world.authority.public_str).unwrap();
    let biscuit = Biscuit::from_base64(token, root).unwrap();
    let request = ThirdPartyRequest::deserialize_base64(
        biscuit
            .third_party_request()
            .unwrap()
            .serialize_base64()
            .unwrap(),
    )
    .unwrap();
    let block = request
        .create_block(
            &biscuit_private(&signer.private_str).unwrap(),
            BlockBuilder::new()
                .code_with_params(code, HashMap::new(), HashMap::new())
                .unwrap(),
        )
        .unwrap();
    biscuit
        .append_third_party(biscuit_public(&signer.public_str).unwrap(), block)
        .unwrap()
        .to_base64()
        .unwrap()
}

fn call(v: &Verifier, token: &str, tool: &str, arguments: Value) -> Decision {
    verify(v, tool, arguments, &biscuit_headers(token, None))
}

fn delete(v: &Verifier, token: &str, path: &str) -> Decision {
    call(v, token, "delete_file", json!({"path": path}))
}

fn denied(decision: &Decision, needle: &str) {
    assert!(!decision.allow, "unexpected ALLOW");
    assert!(
        decision.reason.contains(needle),
        "reason {:?} lacks {needle:?}",
        decision.reason
    );
}

#[test]
fn a_required_endorsement_is_missing() {
    let s = setup();
    denied(
        &delete(&s.verifier, &token(&s, "delete_file"), Q3),
        "third-party endorsement missing: approver.approval",
    );
}

#[test]
fn an_endorsed_call_is_allowed_and_reports_its_authority() {
    let s = setup();
    let t = endorsed(
        &s,
        &token(&s, "delete_file"),
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    let decision = delete(&s.verifier, &t, Q3);
    assert!(decision.allow, "{}", decision.reason);
    assert_eq!(decision.endorsements.len(), 1);
    assert_eq!(decision.endorsements[0].authority, "approver");
    assert_eq!(decision.endorsements[0].block, 1);
    assert_eq!(decision.endorsements[0].key, s.approver.public_str);
    let audit = decision.endorsements_json().unwrap();
    assert_eq!(audit[0]["authority"], "approver");
}

#[test]
fn an_endorsement_never_replaces_the_root_right() {
    let s = setup();
    // The root authority granted read_file only: an approval cannot add delete_file.
    let t = endorsed(
        &s,
        &forge(
            &s.world.authority.private_str,
            mandate("agent-1", "read_file", "read", 600, 10),
        ),
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    denied(&delete(&s.verifier, &t, Q3), "right");
}

#[test]
fn an_endorsement_is_bound_to_its_tool_and_resource() {
    let s = setup();
    let base = token(&s, "delete_file");
    let other_tool = endorsed(&s, &base, &s.approver, &endorse("purge_cache", ""));
    denied(&delete(&s.verifier, &other_tool, Q3), "endorsement missing");
    let other_dir = endorsed(
        &s,
        &base,
        &s.approver,
        &endorse("delete_file", "/projects/other/"),
    );
    denied(&delete(&s.verifier, &other_dir, Q3), "endorsement missing");
    assert!(delete(&s.verifier, &other_dir, "/projects/other/a.md").allow);
}

#[test]
fn a_call_without_resource_needs_an_unscoped_endorsement() {
    let s = setup();
    let base = token(&s, "purge_cache");
    let scoped = endorsed(
        &s,
        &base,
        &s.approver,
        &endorse("purge_cache", "/projects/"),
    );
    denied(
        &call(&s.verifier, &scoped, "purge_cache", json!({})),
        "endorsement missing",
    );
    let unscoped = endorsed(&s, &base, &s.approver, &endorse("purge_cache", ""));
    let decision = call(&s.verifier, &unscoped, "purge_cache", json!({}));
    assert!(decision.allow, "{}", decision.reason);
}

#[test]
fn an_expired_endorsement_is_refused() {
    let s = setup();
    let base = token(&s, "delete_file");
    let request = third_party_request(&base, &s.world.authority.public_str).unwrap();
    let block = sign_third_party_at(
        &request,
        &s.approver.private_str,
        &Endorse {
            ttl_seconds: 60,
            ..endorse("delete_file", "/projects/acme/")
        },
        chrono::Utc::now() - chrono::TimeDelta::seconds(120),
    )
    .unwrap();
    let t = append_third_party(&base, &s.world.authority.public_str, &block, None).unwrap();
    denied(&delete(&s.verifier, &t, Q3), "endorsement missing");
}

#[test]
fn an_undeclared_third_party_is_refused() {
    let s = setup();
    let stranger = generate_keypair();
    let t = endorsed(
        &s,
        &token(&s, "delete_file"),
        &stranger,
        &endorse("delete_file", "/projects/acme/"),
    );
    denied(&delete(&s.verifier, &t, Q3), "undeclared third-party key");
    // Even on a tool that needs no endorsement: an unknown signer is never ignored.
    let read = endorsed(
        &s,
        &forge(
            &s.world.authority.private_str,
            mandate("agent-1", "read_file", "read", 600, 10),
        ),
        &stranger,
        &endorse("read_file", ""),
    );
    denied(
        &call(&s.verifier, &read, "read_file", json!({"path": Q3})),
        "undeclared third-party key",
    );
}

#[test]
fn a_third_party_only_states_its_delegated_predicates() {
    let s = setup();
    let base = token(&s, "delete_file");
    for (code, needle) in [
        (r#"right("delete_file", "write")"#, "not delegated"),
        (
            r#"agent_id("mallory")"#,
            "must originate in authority block",
        ),
        (
            r#"resource("/projects/acme/q3.md")"#,
            "reserved context predicate",
        ),
        (
            r#"approval($t, "/", 2100-01-01T00:00:00Z) <- tool($t)"#,
            "cannot carry rules",
        ),
    ] {
        let t = raw_endorsed(&s, &base, &s.approver, code);
        denied(&delete(&s.verifier, &t, Q3), needle);
    }
}

#[test]
fn a_third_party_check_only_restricts() {
    let s = setup();
    let base = token(&s, "delete_file");
    let t = raw_endorsed(
        &s,
        &base,
        &s.approver,
        r#"approval("delete_file", "/projects/acme/", 2100-01-01T00:00:00Z);
           check if resource($r), $r.starts_with("/projects/acme/archive/")"#,
    );
    denied(&delete(&s.verifier, &t, Q3), "policy denied");
    assert!(delete(&s.verifier, &t, "/projects/acme/archive/q3.md").allow);
}

#[test]
fn the_same_fact_without_the_external_signature_is_invisible() {
    let s = setup();
    let fact = r#"approval("delete_file", "/projects/acme/", 2100-01-01T00:00:00Z)"#;
    // Holder-appended block: anyone can write it, so the gateway must not read it.
    let holder = append_block(
        &token(&s, "delete_file"),
        &s.world.authority.public_str,
        fact,
        &[],
    );
    denied(&delete(&s.verifier, &holder, Q3), "endorsement missing");
    // Root-signed: the root authority cannot endorse its own grant either.
    let root = common::proxy::build_token(
        &s.world.authority.private_str,
        &format!(
            r#"agent_id("agent-1"); required_profile("native"); right("delete_file", "write");
               audience("{TEST_AUDIENCE}"); expires_at({{exp}}); {fact};"#
        ),
        &[("exp", date_term(in_seconds(300)))],
    );
    denied(&delete(&s.verifier, &root, Q3), "endorsement missing");
}

#[test]
fn an_endorsement_cannot_be_moved_to_another_mandate() {
    let s = setup();
    let first = token(&s, "delete_file");
    let second = token(&s, "delete_file");
    let request = third_party_request(&first, &s.world.authority.public_str).unwrap();
    let block = sign_third_party(
        &request,
        &s.approver.private_str,
        &endorse("delete_file", "/projects/acme/"),
    )
    .unwrap();
    assert!(append_third_party(&second, &s.world.authority.public_str, &block, None).is_err());
}

#[test]
fn the_append_checks_the_expected_signer() {
    let s = setup();
    let base = token(&s, "delete_file");
    let request = third_party_request(&base, &s.world.authority.public_str).unwrap();
    let block = sign_third_party(
        &request,
        &generate_keypair().private_str,
        &endorse("delete_file", "/projects/acme/"),
    )
    .unwrap();
    let error = append_third_party(
        &base,
        &s.world.authority.public_str,
        &block,
        Some(&s.approver.public_str),
    )
    .unwrap_err();
    assert!(error.message.contains("not by the expected third party"));
}

#[test]
fn a_rotated_third_party_key_is_still_trusted() {
    let world = World::new();
    let (old, new) = (generate_keypair(), generate_keypair());
    let verifier = world.verifier(
        policy_for(&[&new.public_str, &old.public_str]),
        Some(VerifierOptions::new(TEST_AUDIENCE)),
    );
    let s = Setup {
        world,
        approver: new,
        verifier,
    };
    let t = endorsed(
        &s,
        &token(&s, "delete_file"),
        &old,
        &endorse("delete_file", "/projects/acme/"),
    );
    assert!(delete(&s.verifier, &t, Q3).allow);
}

#[test]
fn a_third_party_cannot_reuse_a_root_key() {
    let world = World::new();
    let error = Verifier::new(
        &world.authority.public_str,
        policy_for(&[&world.authority.public_str]),
        VerifierOptions::new(TEST_AUDIENCE),
    )
    .err()
    .unwrap();
    assert!(error.message.contains("reuses a root authority key"));
}

/// A mandate for `read_file`, which needs no endorsement, with the agent's key anchored
/// in block 0 or left to the registry, and the agent's signed call for it.
fn agent_call(world: &World, anchored: bool) -> (String, String) {
    let token = forge(
        &world.authority.private_str,
        ForgeRequest {
            resource_prefix: Some("/projects/acme/".into()),
            agent_pubkey: anchored.then(|| world.agent.public_str.clone()),
            required_profile: if anchored {
                "hardened_biscuit_anchored"
            } else {
                "registry_backed"
            }
            .into(),
            ..mandate("agent-1", "read_file", "read", 600, 10)
        },
    );
    let attestation = build_attestation(
        "agent-1",
        "read_file",
        &json!({"path": Q3}),
        &token,
        &world.agent.private_str,
        None,
    )
    .unwrap();
    (token, attestation)
}

const AGENT_KEY_REUSED: &str = "third-party key is the agent key";

#[tokio::test]
async fn a_third_party_cannot_reuse_the_anchored_agent_key() {
    use common::proxy::{FakeUpstream, bearer, post};
    use tokencrumb_mcp_proxy::proxy::upstream::SharedUpstream;

    let world = World::new();
    let ally = generate_keypair();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_file", "arguments": {"path": Q3}}});
    for (key, allowed) in [(&world.agent.public_str, false), (&ally.public_str, true)] {
        let upstream = FakeUpstream::default_json();
        let verifier = world.verifier(policy_for(&[key.as_str()]), None);
        let app = world.proxy_with(
            vec![(None, upstream.clone() as SharedUpstream)],
            None,
            verifier,
            true,
        );
        let (token, attestation) = agent_call(&world, true);
        post(
            &app,
            body.clone(),
            &[
                ("authorization", &bearer(&token)),
                ("agent-attestation", &attestation),
            ],
        )
        .await;
        assert_eq!(upstream.reached(), allowed, "ally key {key}");
        let entry = world.audit_entries().last().unwrap().clone();
        if allowed {
            assert_eq!(entry["decision"], "ALLOW", "{entry}");
        } else {
            assert_eq!(entry["decision"], "DENY");
            assert!(
                entry["reason"].as_str().unwrap().contains(AGENT_KEY_REUSED),
                "{entry}"
            );
        }
    }
}

#[test]
fn a_third_party_cannot_reuse_the_registry_agent_key() {
    let world = World::new();
    // A registry answering in uppercase hex still names the same key.
    let agent_public = world
        .agent
        .public_str
        .to_ascii_uppercase()
        .replace("ED25519/", "ed25519/");
    let mut options = VerifierOptions::new(TEST_AUDIENCE);
    options.resolve_agent_pubkey = Some(Box::new(move |id: &str| {
        (id == "agent-1").then(|| agent_public.clone())
    }));
    let verifier = world.verifier(policy_for(&[&world.agent.public_str]), Some(options));
    let (token, attestation) = agent_call(&world, false);
    let decision = verify(
        &verifier,
        "read_file",
        json!({"path": Q3}),
        &biscuit_headers(&token, Some(&attestation)),
    );
    denied(&decision, AGENT_KEY_REUSED);
    assert_eq!(decision.profile, "registry_backed");
}

#[test]
fn a_previous_third_party_key_cannot_be_the_agent_key() {
    let world = World::new();
    let current = generate_keypair();
    let verifier = world.verifier(
        policy_for(&[&current.public_str, &world.agent.public_str]),
        None,
    );
    let (token, attestation) = agent_call(&world, true);
    denied(
        &verify(
            &verifier,
            "read_file",
            json!({"path": Q3}),
            &biscuit_headers(&token, Some(&attestation)),
        ),
        AGENT_KEY_REUSED,
    );
}

#[test]
fn an_endorsement_is_not_a_delegation_step() {
    let s = setup();
    let root = forge(
        &s.world.authority.private_str,
        ForgeRequest {
            max_delegation_depth: Some(0),
            ..mandate("agent-1", "delete_file", "write", 600, 10)
        },
    );
    let t = endorsed(
        &s,
        &root,
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    assert!(delete(&s.verifier, &t, Q3).allow);
    // A holder block after it still counts.
    let child = attenuate(
        &t,
        &s.world.authority.public_str,
        &Attenuation {
            budget: Some(5),
            ..Default::default()
        },
    )
    .unwrap();
    denied(&delete(&s.verifier, &child, Q3), "depth");
}

#[test]
fn a_holder_can_narrow_after_the_endorsement() {
    let s = setup();
    let t = endorsed(
        &s,
        &forge(
            &s.world.authority.private_str,
            mandate("agent-1", "delete_file", "write", 600, 10),
        ),
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    let narrowed = attenuate(
        &t,
        &s.world.authority.public_str,
        &Attenuation {
            resource: Some("/projects/acme/drafts/".into()),
            ..Default::default()
        },
    )
    .unwrap();
    denied(&delete(&s.verifier, &narrowed, Q3), "policy denied");
    assert!(delete(&s.verifier, &narrowed, "/projects/acme/drafts/a.md").allow);
}

#[test]
fn inspect_reports_the_external_key() {
    let s = setup();
    let t = endorsed(
        &s,
        &token(&s, "delete_file"),
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    let inspected = biscuit_ops::inspect(&t).unwrap();
    assert_eq!(
        inspected.external_keys,
        vec![None, Some(s.approver.public_str.clone())]
    );
    assert_eq!(inspected.revocation_ids.len(), 2);
}

#[test]
fn the_policy_refuses_unsafe_third_party_declarations() {
    let key = generate_keypair().public_str;
    for (doc, needle) in [
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["right"]}}}),
            "cannot be delegated",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["resource"]}}}),
            "cannot be delegated",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["nonce_fresh"]}}}),
            "cannot be delegated",
        ),
        (
            json!({"third_party": {"a": {"keys": ["ed25519/zz"], "predicates": ["ok"]}}}),
            "expected ed25519",
        ),
        (
            json!({"third_party": {"a": {"keys": [], "predicates": ["ok"]}}}),
            "1 to 8 keys",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["ok"]},
                                   "b": {"keys": [key], "predicates": ["ok"]}}}),
            "declared twice",
        ),
        (
            json!({"tools": [{"name": "t", "operation": "w",
                              "require_third_party": [{"authority": "ghost"}]}]}),
            "not declared",
        ),
        (
            json!({"third_party": {"a": {"keys": [key], "predicates": ["ok"]}},
                   "tools": [{"name": "t", "operation": "w",
                              "require_third_party": [{"authority": "a", "predicate": "other"}]}]}),
            "not delegated",
        ),
    ] {
        let error = parse_policy(&doc).unwrap_err();
        assert!(
            error.message.contains(needle),
            "{} lacks {needle}",
            error.message
        );
    }
}

#[tokio::test]
async fn the_audit_records_which_authorities_endorsed_a_call() {
    use common::proxy::{FakeUpstream, bearer, post};
    use tokencrumb_mcp_proxy::proxy::upstream::SharedUpstream;

    let s = setup();
    let upstream = FakeUpstream::default_json();
    let app = s.world.proxy_with(
        vec![(None, upstream.clone() as SharedUpstream)],
        None,
        s.verifier.clone(),
        true,
    );
    let body = |path: &str| {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "delete_file", "arguments": {"path": path}}})
    };
    let bare = token(&s, "delete_file");
    post(&app, body(Q3), &[("authorization", &bearer(&bare))]).await;
    assert!(!upstream.reached());
    let entry = s.world.audit_entries().last().unwrap().clone();
    assert_eq!(entry["decision"], "DENY");
    assert!(
        entry["reason"]
            .as_str()
            .unwrap()
            .contains("third-party endorsement missing: approver.approval")
    );
    assert!(entry["detail"].get("third_party").is_none());

    let t = endorsed(
        &s,
        &bare,
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    post(&app, body(Q3), &[("authorization", &bearer(&t))]).await;
    assert!(upstream.reached());
    let entry = s.world.audit_entries().last().unwrap().clone();
    assert_eq!(entry["decision"], "ALLOW");
    assert_eq!(
        entry["detail"]["third_party"],
        json!([{"authority": "approver", "block": 1, "key": s.approver.public_str}])
    );
}

#[test]
fn the_cli_runs_the_whole_endorsement_exchange() {
    use common::{bm, keyfiles, stderr, stdout};

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keyfiles(d, "authority");
    let approver = keyfiles(d, "approver");
    let ok = |args: &[&str]| {
        let out = bm(d, args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        out
    };
    ok(&[
        "forge",
        "--key",
        "authority.key",
        "--tool",
        "delete_file",
        "--operation",
        "write",
        "--audience",
        TEST_AUDIENCE,
        "--out",
        "mandate.b64",
    ]);
    ok(&[
        "third-party-request",
        "--token",
        "mandate.b64",
        "--authority-pub",
        "authority.pub",
        "--out",
        "request.b64",
    ]);
    ok(&[
        "third-party-sign",
        "--key",
        "approver.key",
        "--request",
        "request.b64",
        "--tool",
        "delete_file",
        "--resource-prefix",
        "/projects/acme/",
        "--ttl",
        "5m",
        "--out",
        "block.b64",
    ]);
    ok(&[
        "third-party-append",
        "--token",
        "mandate.b64",
        "--authority-pub",
        "authority.pub",
        "--block",
        "block.b64",
        "--third-party-pub",
        "approver.pub",
        "--out",
        "endorsed.b64",
    ]);
    let panels = stdout(&ok(&["inspect", "endorsed.b64"]));
    assert!(panels.contains(&format!("block 1 · third-party {}", approver.public_str)));
    let inspected: Value =
        serde_json::from_str(&stdout(&ok(&["inspect", "--json", "endorsed.b64"]))).unwrap();
    assert_eq!(inspected["blocks"][1]["kind"], "third-party");
    assert_eq!(inspected["blocks"][1]["external_key"], approver.public_str);
    let block_id = inspected["blocks"][1]["revocation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(&[
        "revoke",
        "--key",
        "authority.key",
        "--from-token",
        "endorsed.b64",
        "--block",
        "1",
        "--out",
        "revoked.list",
    ]);
    let list = std::fs::read_to_string(d.join("revoked.list")).unwrap();
    assert!(list.contains(&block_id));
    let root_id = inspected["blocks"][0]["revocation_id"].as_str().unwrap();
    assert!(!list.contains(root_id));
    // A block for another signer is refused at append time.
    keyfiles(d, "other");
    let refused = bm(
        d,
        &[
            "third-party-append",
            "--token",
            "mandate.b64",
            "--authority-pub",
            "authority.pub",
            "--block",
            "block.b64",
            "--third-party-pub",
            "other.pub",
        ],
    );
    assert!(!refused.status.success());
}

#[test]
fn revoking_an_endorsement_leaves_the_unendorsed_mandate_valid() {
    use tokencrumb_mcp_proxy::revocation::StaticRevocations;

    let s = setup();
    let base = token(&s, "delete_file");
    let t = endorsed(
        &s,
        &base,
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    let endorsement_id = biscuit_ops::inspect(&t).unwrap().revocation_ids[1].clone();
    let mut options = VerifierOptions::new(TEST_AUDIENCE);
    options.revocation = Some(std::sync::Arc::new(StaticRevocations(
        [endorsement_id].into(),
    )));
    let v = s
        .world
        .verifier(policy_for(&[&s.approver.public_str]), Some(options));
    denied(&delete(&v, &t, Q3), "revoked");
    let read = call(&v, &t, "read_file", json!({"path": Q3}));
    denied(&read, "revoked");
    assert!(
        !delete(&v, &base, Q3).allow,
        "the bare mandate still needs an endorsement"
    );
    // A fresh endorsement on the same mandate works again.
    let again = endorsed(
        &s,
        &base,
        &s.approver,
        &endorse("delete_file", "/projects/acme/"),
    );
    assert!(delete(&v, &again, Q3).allow);
}
