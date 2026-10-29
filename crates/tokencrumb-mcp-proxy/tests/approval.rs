//! Human approval of one exact call (HOLD, lot 1): tests H-01 to H-19 and H-29 to H-31
//! of the implementation specification.
//!
//! Every refusal is checked on both sides: nothing reached the upstream, and the audit
//! entry carries the expected reason. A test that only read the client's answer could
//! mistake a forwarded call that came back as an error for a refusal.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use common::proxy::{FakeUpstream, Reply, TEST_AUDIENCE, World, bearer, post};
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use tokencrumb_mcp_proxy::approval::{self, IntentInput, encode_receipt, sign_receipt};
use tokencrumb_mcp_proxy::attestation::{biscuit_hash, build_attestation};
use tokencrumb_mcp_proxy::biscuit_ops::{self, Attenuation, Endorse, ForgeRequest};
use tokencrumb_mcp_proxy::budget::BudgetStore;
use tokencrumb_mcp_proxy::canonical::arguments_hash;
use tokencrumb_mcp_proxy::error::{Error, ErrorKind};
use tokencrumb_mcp_proxy::keys::{Keypair, generate_keypair};
use tokencrumb_mcp_proxy::nonce_cache::{NonceCache, ReceiptStore};
use tokencrumb_mcp_proxy::policy::{Policy, PolicyReloader, parse_policy, parse_policy_text};
use tokencrumb_mcp_proxy::proxy::upstream::{
    ForwardHeaders, PROPAGATE, SharedUpstream, Upstream, UpstreamResponse,
};
use tokencrumb_mcp_proxy::verifier::{Verifier, VerifierOptions};

const TOOL: &str = "delete_file";
const PATH: &str = "/workspace/report.txt";
const AGENT: &str = "agent-1";

/// One gateway deployment: keys, a controllable clock and the persistent state files.
/// Building a second app over the same files is a restart.
struct Gw {
    world: World,
    approver: Keypair,
    other: Keypair,
    third_party: Keypair,
    clock: Arc<Mutex<DateTime<Utc>>>,
    budget: u32,
}

fn base_policy(g: &Gw, extra_member: Option<&str>, third_party: bool) -> Value {
    let mut ops = vec![json!({"id": "a.dupont", "keys": [g.approver.public_str]})];
    if let Some(key) = extra_member {
        ops.push(json!({"id": "c.agent", "keys": [key]}));
    }
    let mut tool = json!({
        "name": TOOL, "operation": "write", "resource": {"from": "arguments.path"},
        "allow": {"resource_prefix": "/workspace/", "budget": g.budget},
        "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"],
        "approval": {"approvers": ["ops"], "receipt_ttl": "5m"},
    });
    let mut policy = json!({
        "min_profile": "hardened_biscuit_anchored",
        "approvers": {
            "ops": {"members": ops},
            "legal": {"members": [{"id": "b.martin", "keys": [g.other.public_str]}]},
        },
        "tools": [],
    });
    if third_party {
        policy["third_party"] =
            json!({"notary": {"keys": [g.third_party.public_str], "predicates": ["approval"]}});
        tool["require_third_party"] = json!([{"authority": "notary"}]);
    }
    policy["tools"] = json!([
        tool,
        {"name": "wipe_file", "operation": "write", "resource": {"from": "arguments.path"},
         "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"],
         "approval": {"approvers": ["ops"]}},
    ]);
    policy
}

impl Gw {
    fn new() -> Self {
        Self::with_budget(5)
    }

    fn with_budget(budget: u32) -> Self {
        let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        Self {
            world: World::new(),
            approver: generate_keypair(),
            other: generate_keypair(),
            third_party: generate_keypair(),
            clock: Arc::new(Mutex::new(now)),
            budget,
        }
    }

    fn now(&self) -> DateTime<Utc> {
        *self.clock.lock().unwrap()
    }

    fn advance(&self, seconds: i64) {
        *self.clock.lock().unwrap() += TimeDelta::seconds(seconds);
    }

    fn db(&self) -> PathBuf {
        self.world.dir.path().join("state.nonces.db")
    }

    fn policy(&self) -> Policy {
        self.policy_from(base_policy(self, None, false))
    }

    fn policy_from(&self, raw: Value) -> Policy {
        let mut policy = parse_policy(&raw).unwrap();
        policy.policy_digest = "approval-test".into();
        policy
    }

    fn options(&self) -> VerifierOptions {
        let mut options = VerifierOptions::new(TEST_AUDIENCE);
        let clock = self.clock.clone();
        options.now_fn = Some(Box::new(move || *clock.lock().unwrap()));
        options.nonce_cache = Some(Arc::new(
            NonceCache::new(1000, 120, Some(&self.db())).unwrap(),
        ));
        options.receipt_store = Some(Arc::new(ReceiptStore::open(&self.db(), 1000).unwrap()));
        options.budget_store = Some(Arc::new(
            BudgetStore::open(self.world.dir.path().join("budget.json")).unwrap(),
        ));
        options.approval_forbidden_keys = vec![self.world.audit_key.public_str.clone()];
        options
    }

    fn verifier_with(&self, policy: Policy) -> Arc<Verifier> {
        Arc::new(Verifier::new(&self.world.authority.public_str, policy, self.options()).unwrap())
    }

    fn app_with(
        &self,
        upstream: SharedUpstream,
        policy: Policy,
        mode: Option<&str>,
    ) -> axum::Router {
        self.world.proxy_with(
            vec![(None, upstream)],
            mode,
            self.verifier_with(policy),
            true,
        )
    }

    fn app(&self, upstream: &Arc<FakeUpstream>) -> axum::Router {
        self.app_with(upstream.clone(), self.policy(), None)
    }

    fn token_for(&self, tool: &str, prefix: &str) -> String {
        biscuit_ops::forge(
            &self.world.authority.private_str,
            &ForgeRequest {
                agent_id: AGENT.into(),
                tool: tool.into(),
                operation: "write".into(),
                ttl_seconds: 3600,
                budget: 100,
                resource_prefix: Some(prefix.into()),
                agent_pubkey: Some(self.world.agent.public_str.clone()),
                required_profile: "hardened_biscuit_anchored".into(),
                audience: TEST_AUDIENCE.into(),
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn token(&self) -> String {
        self.token_for(TOOL, "/workspace/")
    }

    /// One signed `tools/call`, with a fresh attestation and an optional receipt.
    async fn call_tool(
        &self,
        app: &axum::Router,
        token: &str,
        tool: &str,
        arguments: Value,
        receipt: Option<&str>,
    ) -> Reply {
        let attestation = build_attestation(
            AGENT,
            tool,
            &arguments,
            token,
            &self.world.agent.private_str,
            Some(self.now()),
        )
        .unwrap();
        let auth = bearer(token);
        let mut headers = vec![
            ("authorization", auth.as_str()),
            ("agent-attestation", attestation.as_str()),
        ];
        if let Some(receipt) = receipt {
            headers.push(("approval-receipt", receipt));
        }
        post(
            app,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments}}),
            &headers,
        )
        .await
    }

    async fn call(&self, app: &axum::Router, token: &str, receipt: Option<&str>) -> Reply {
        self.call_tool(app, token, TOOL, json!({"path": PATH}), receipt)
            .await
    }

    /// The intent the gateway computes for a call, recomputed independently.
    fn intent_hash(&self, token: &str, tool: &str, path: &str) -> String {
        let intent = approval::intent(&IntentInput {
            tool,
            operation: "write",
            resource: Some(path),
            arguments_hash: &arguments_hash(&json!({"path": path})).unwrap(),
            mandate_hash: &biscuit_hash(token),
            agent_id: Some(AGENT),
            agent_key: &self.world.agent.public_str,
            audience: TEST_AUDIENCE,
        });
        approval::intent_hash(&intent).unwrap()
    }

    fn sign(
        &self,
        signer: &Keypair,
        id: &str,
        intent_hash: &str,
        issued: DateTime<Utc>,
        ttl: i128,
    ) -> String {
        encode_receipt(
            &sign_receipt(
                &signer.private_str,
                id,
                "apr_test",
                intent_hash,
                issued,
                ttl,
            )
            .unwrap(),
        )
    }

    /// A valid receipt for the request a HOLD answer carries.
    fn approve(&self, held: &Reply) -> String {
        let request = approval_required(held);
        let checked = approval::check_request(&request).unwrap();
        encode_receipt(
            &sign_receipt(
                &self.approver.private_str,
                "a.dupont",
                &checked.request_id,
                &checked.intent_hash,
                self.now(),
                300,
            )
            .unwrap(),
        )
    }

    fn entries(&self) -> Vec<Value> {
        self.world.audit_entries()
    }

    fn last(&self) -> Value {
        self.entries().last().cloned().expect("an audit entry")
    }

    fn store(&self) -> ReceiptStore {
        ReceiptStore::open(&self.db(), 1000).unwrap()
    }
}

fn approval_required(reply: &Reply) -> Value {
    reply.json()["result"]["structuredContent"]["approval_required"].clone()
}

fn receipt_id(receipt: &str) -> String {
    approval::Receipt::from_header(receipt).unwrap().receipt_id
}

fn is_deny(reply: &Reply) -> bool {
    reply.json()["result"]["content"][0]["text"]
        .as_str()
        .is_some_and(|t| t.starts_with("DENY — authorization failed"))
}

/// The refusal contract: generic answer, nothing forwarded, the reason in the audit.
fn assert_refused(g: &Gw, reply: &Reply, upstream: &FakeUpstream, reason: &str) {
    assert!(is_deny(reply), "expected a denial, got {}", reply.text());
    assert!(!upstream.reached(), "a refused call reached the upstream");
    let last = g.last();
    assert_eq!(last["decision"], "DENY");
    assert_eq!(last["reason"], reason, "audit reason");
}

/// An upstream that records the call and answers what `reply` says.
struct Scripted {
    calls: Mutex<usize>,
    reply: Box<dyn Fn() -> Option<tokencrumb_mcp_proxy::Result<UpstreamResponse>> + Send + Sync>,
}

impl Scripted {
    fn new(
        reply: impl Fn() -> Option<tokencrumb_mcp_proxy::Result<UpstreamResponse>>
        + Send
        + Sync
        + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(0),
            reply: Box::new(reply),
        })
    }

    fn count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl Upstream for Scripted {
    fn forward<'a>(
        &'a self,
        _method: &'a str,
        _body: Bytes,
        _headers: &'a ForwardHeaders,
    ) -> BoxFuture<'a, tokencrumb_mcp_proxy::Result<UpstreamResponse>> {
        *self.calls.lock().unwrap() += 1;
        let reply = (self.reply)();
        Box::pin(async move {
            match reply {
                Some(reply) => reply,
                // Never answers: a call in flight when the gateway goes away.
                None => std::future::pending().await,
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

fn json_reply(value: Value) -> Option<tokencrumb_mcp_proxy::Result<UpstreamResponse>> {
    Some(Ok(UpstreamResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: Bytes::from(value.to_string()),
    }))
}

// -- H-01, H-02 ------------------------------------------------------------------------

#[tokio::test]
async fn h01_a_call_without_receipt_is_held_not_forwarded_not_charged() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let reply = g.call(&app, &token, None).await;

    assert!(!upstream.reached());
    let result = &reply.json()["result"];
    assert_eq!(result["isError"], true);
    let first = result["content"][0]["text"].as_str().unwrap();
    assert!(
        first.starts_with("APPROVAL REQUIRED — request apr_"),
        "{first}"
    );
    assert!(first.contains("· correlation_id: "));
    let text_object: Value =
        serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text_object, result["structuredContent"]);
    let request = approval_required(&reply);
    assert_eq!(request["intent"]["tool"], TOOL);
    assert_eq!(request["intent"]["resource"], PATH);
    assert_eq!(request["arguments"], json!({"path": PATH}));
    assert_eq!(request["approvers"], json!(["ops"]));
    assert_eq!(
        request["intent_hash"],
        g.intent_hash(&token, TOOL, PATH).as_str()
    );
    assert!(!reply.text().contains(&token), "the mandate never leaves");

    let entry = g.last();
    assert_eq!(entry["decision"], "HOLD");
    assert_eq!(entry["detail"]["request_id"], request["request_id"]);
    assert_eq!(entry["detail"]["intent_hash"], request["intent_hash"]);
    assert_eq!(entry["detail"]["approvers"], json!(["ops"]));
    // Nothing charged: a second hold sees the same remaining budget.
    g.call(&app, &token, None).await;
    assert_eq!(g.last()["decision"], "HOLD");
    assert_eq!(g.last()["remaining_budget"], entry["remaining_budget"]);
    assert_eq!(entry["remaining_budget"], 5);
}

#[tokio::test]
async fn h02_a_valid_receipt_on_the_identical_replay_is_forwarded_once() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let held = g.call(&app, &token, None).await;
    let receipt = g.approve(&held);

    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_eq!(reply.json()["result"]["ok"], true);
    assert_eq!(upstream.bodies().len(), 1);
    // The receipt header is not a session header: it never reaches the upstream.
    assert!(!PROPAGATE.contains(&approval::RECEIPT_HEADER));

    let entries = g.entries();
    let allow = &entries[entries.len() - 2];
    assert_eq!(allow["decision"], "ALLOW");
    assert_eq!(
        allow["detail"]["approval"]["receipt_id"],
        receipt_id(&receipt).as_str()
    );
    assert_eq!(
        allow["detail"]["approval"]["request_id"],
        approval_required(&held)["request_id"]
    );
    assert_eq!(allow["detail"]["approval"]["approver_id"], "a.dupont");
    assert_eq!(
        allow["detail"]["approval"]["key"],
        g.approver.public_str.as_str()
    );
    assert_eq!(
        allow["detail"]["approval"]["intent_hash"],
        approval_required(&held)["intent_hash"]
    );
    assert_eq!(allow["remaining_budget"], 4);
    let outcome = entries.last().unwrap();
    assert_eq!(outcome["decision"], "OUTCOME");
    assert_eq!(outcome["detail"]["state"], "ok");
    assert_eq!(
        outcome["detail"]["receipt_id"],
        receipt_id(&receipt).as_str()
    );
    assert_eq!(
        g.store().get(&receipt_id(&receipt)).unwrap().unwrap().state,
        "ok"
    );
}

// -- H-03, H-04: the receipt binds the exact call ---------------------------------------

#[tokio::test]
async fn h03_a_receipt_for_other_arguments_is_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);
    let reply = g
        .call_tool(
            &app,
            &token,
            TOOL,
            json!({"path": "/workspace/other.txt"}),
            Some(&receipt),
        )
        .await;
    assert_refused(&g, &reply, &upstream, "receipt intent mismatch");
    assert!(
        g.store().get(&receipt_id(&receipt)).unwrap().is_none(),
        "not consumed"
    );
}

#[tokio::test]
async fn h04_a_receipt_does_not_move_to_another_tool_or_mandate() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);

    // The same mandate, attenuated after the approval.
    let narrowed = biscuit_ops::attenuate(
        &token,
        &g.world.authority.public_str,
        &Attenuation {
            ttl_seconds: Some(600),
            ..Default::default()
        },
    )
    .unwrap();
    let reply = g.call(&app, &narrowed, Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt intent mismatch");

    // Another mandate for the same agent and tool.
    let reply = g.call(&app, &g.token(), Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt intent mismatch");

    // Another tool, same arguments, under its own mandate.
    let wipe = g.token_for("wipe_file", "/workspace/");
    let reply = g
        .call_tool(
            &app,
            &wipe,
            "wipe_file",
            json!({"path": PATH}),
            Some(&receipt),
        )
        .await;
    assert_refused(&g, &reply, &upstream, "receipt intent mismatch");

    // Still usable on the call it was given for.
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_eq!(reply.json()["result"]["ok"], true);
}

// -- H-05 to H-08: single use, durable, atomic -------------------------------------------

#[tokio::test]
async fn h05_a_replayed_receipt_is_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);
    g.call(&app, &token, Some(&receipt)).await;
    upstream.clear();
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt already used");
}

#[tokio::test]
async fn h06_a_receipt_replayed_after_a_restart_is_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let token = g.token();
    let receipt = {
        let app = g.app(&upstream);
        let receipt = g.approve(&g.call(&app, &token, None).await);
        g.call(&app, &token, Some(&receipt)).await;
        receipt
    };
    upstream.clear();
    let restarted = g.app(&upstream);
    let reply = g.call(&restarted, &token, Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt already used");
}

#[tokio::test]
async fn h07_two_concurrent_replays_forward_exactly_one_call() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);
    let (one, two) = tokio::join!(
        g.call(&app, &token, Some(&receipt)),
        g.call(&app, &token, Some(&receipt))
    );
    assert_eq!(upstream.bodies().len(), 1, "exactly one call forwarded");
    let allowed = [&one, &two]
        .iter()
        .filter(|r| r.json()["result"]["ok"] == true)
        .count();
    assert_eq!(allowed, 1);
    assert!(is_deny(&one) || is_deny(&two));
    let entries = g.entries();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["reason"] == "receipt already used")
            .count(),
        1
    );
    assert_eq!(
        entries.iter().filter(|e| e["decision"] == "ALLOW").count(),
        1
    );
}

#[tokio::test]
async fn h08_a_restart_in_flight_settles_unknown_once_the_lease_expires() {
    let g = Gw::new();
    let hanging = Scripted::new(|| None);
    let token = g.token();
    let app = g.app_with(hanging.clone(), g.policy(), None);
    let held = g.call(&app, &token, None).await;
    let receipt = g.approve(&held);

    // The approved call is consumed, then the gateway dies before any answer.
    let in_flight = {
        let app = app.clone();
        let receipt = receipt.clone();
        let g = &g;
        let token = token.clone();
        async move { g.call(&app, &token, Some(&receipt)).await }
    };
    let cut = tokio::time::timeout(Duration::from_millis(500), in_flight).await;
    assert!(cut.is_err(), "the upstream never answered");
    assert_eq!(hanging.count(), 1);
    let id = receipt_id(&receipt);
    assert_eq!(g.store().get(&id).unwrap().unwrap().state, "reserved");

    // A restart while the lease runs leaves the row alone ...
    let fake = FakeUpstream::default_json();
    let _restart = g.app(&fake);
    assert_eq!(g.store().get(&id).unwrap().unwrap().state, "reserved");
    // ... and one after it settles it as unknown, on the record.
    g.advance(120);
    let restarted = g.app(&fake);
    assert_eq!(g.store().get(&id).unwrap().unwrap().state, "unknown");
    let outcome = g.last();
    assert_eq!(outcome["decision"], "OUTCOME");
    assert_eq!(outcome["detail"]["receipt_id"], id.as_str());
    assert_eq!(outcome["detail"]["state"], "unknown");

    let reply = g.call(&restarted, &token, Some(&receipt)).await;
    assert_refused(&g, &reply, &fake, "receipt already used");
}

// -- H-09, H-10, H-31: outcomes ------------------------------------------------------------

#[tokio::test]
async fn h09_an_upstream_error_keeps_the_receipt_and_the_budget_consumed() {
    let g = Gw::new();
    let upstream = FakeUpstream::new(
        Some(json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}})),
        "application/json",
    );
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);
    g.call(&app, &token, Some(&receipt)).await;
    assert_eq!(upstream.bodies().len(), 1);
    let entries = g.entries();
    assert_eq!(entries[entries.len() - 2]["remaining_budget"], 4);
    let outcome = entries.last().unwrap();
    assert_eq!(outcome["decision"], "OUTCOME");
    assert_eq!(outcome["detail"]["state"], "upstream_error");
    assert_eq!(
        g.store().get(&receipt_id(&receipt)).unwrap().unwrap().state,
        "upstream_error"
    );
    upstream.clear();
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt already used");
    // The budget stayed charged: the next hold sees 4.
    g.call(&app, &token, None).await;
    assert_eq!(g.last()["remaining_budget"], 4);
}

#[tokio::test]
async fn h10_an_audit_failure_after_consumption_forwards_nothing() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);
    std::fs::remove_file(g.world.audit_path()).unwrap();
    std::fs::create_dir(g.world.audit_path()).unwrap();

    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_eq!(reply.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(!upstream.reached());
    // The audit itself is the failing part; the receipt table shows it stayed consumed.
    let row = g.store().get(&receipt_id(&receipt)).unwrap().unwrap();
    assert_eq!(row.state, "reserved");
}

#[tokio::test]
async fn h31_a_tool_error_result_is_ok_and_a_timeout_is_unknown() {
    let g = Gw::new();
    let token = g.token();
    let failing_tool = Scripted::new(|| {
        json_reply(json!({"jsonrpc": "2.0", "id": 1,
                          "result": {"content": [{"type": "text", "text": "no"}], "isError": true}}))
    });
    let app = g.app_with(failing_tool.clone(), g.policy(), None);
    let receipt = g.approve(&g.call(&app, &token, None).await);
    g.call(&app, &token, Some(&receipt)).await;
    assert_eq!(failing_tool.count(), 1);
    assert_eq!(g.last()["decision"], "OUTCOME");
    assert_eq!(g.last()["detail"]["state"], "ok");

    let timing_out = Scripted::new(|| Some(Err(Error::new(ErrorKind::Io, "TimeoutError"))));
    let app = g.app_with(timing_out.clone(), g.policy(), None);
    let receipt = g.approve(&g.call(&app, &token, None).await);
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_eq!(reply.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(timing_out.count(), 1);
    let entries = g.entries();
    let outcome = entries
        .iter()
        .rev()
        .find(|e| e["decision"] == "OUTCOME")
        .unwrap();
    assert_eq!(outcome["detail"]["state"], "unknown");
    assert_eq!(
        outcome["detail"]["receipt_id"],
        receipt_id(&receipt).as_str()
    );
}

// -- H-11 to H-13, H-18: receipt checks -----------------------------------------------------

#[tokio::test]
async fn h11_expired_overlong_and_future_receipts_are_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let hash = g.intent_hash(&token, TOOL, PATH);
    let now = g.now();
    for (receipt, reason) in [
        (
            g.sign(
                &g.approver,
                "a.dupont",
                &hash,
                now - TimeDelta::seconds(400),
                300,
            ),
            "receipt expired",
        ),
        (
            g.sign(&g.approver, "a.dupont", &hash, now, 3600),
            "receipt lifetime exceeds policy",
        ),
        (
            g.sign(
                &g.approver,
                "a.dupont",
                &hash,
                now + TimeDelta::seconds(120),
                60,
            ),
            "receipt issued in the future",
        ),
    ] {
        let reply = g.call(&app, &token, Some(&receipt)).await;
        assert_refused(&g, &reply, &upstream, reason);
        assert!(g.store().get(&receipt_id(&receipt)).unwrap().is_none());
    }
    // Within the tolerated skew, a receipt issued slightly ahead is fine.
    let ahead = g.sign(
        &g.approver,
        "a.dupont",
        &hash,
        now + TimeDelta::seconds(10),
        200,
    );
    assert_eq!(
        g.call(&app, &token, Some(&ahead)).await.json()["result"]["ok"],
        true
    );
}

#[tokio::test]
async fn h12_unregistered_unlisted_or_misnamed_signers_are_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let hash = g.intent_hash(&token, TOOL, PATH);
    let stranger = generate_keypair();
    for receipt in [
        g.sign(&stranger, "a.dupont", &hash, g.now(), 300),
        // A registered approver, but of a group this tool does not list.
        g.sign(&g.other, "b.martin", &hash, g.now(), 300),
        // The right key under another member's id.
        g.sign(&g.approver, "b.martin", &hash, g.now(), 300),
    ] {
        let reply = g.call(&app, &token, Some(&receipt)).await;
        assert_refused(
            &g,
            &reply,
            &upstream,
            "receipt signer not registered for this tool",
        );
    }
}

#[tokio::test]
async fn h13_a_receipt_signed_by_the_agent_key_is_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    // A misconfiguration the policy cannot detect: the agent key registered as approver.
    let policy = g.policy_from(base_policy(&g, Some(&g.world.agent.public_str), false));
    let app = g.app_with(upstream.clone(), policy, None);
    let token = g.token();
    let hash = g.intent_hash(&token, TOOL, PATH);
    let receipt = g.sign(&g.world.agent, "c.agent", &hash, g.now(), 300);
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt signed by the agent key");
}

#[tokio::test]
async fn h18_malformed_receipts_are_refused() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let hash = g.intent_hash(&token, TOOL, PATH);
    let signed = sign_receipt(
        &g.approver.private_str,
        "a.dupont",
        "apr_x",
        &hash,
        g.now(),
        300,
    )
    .unwrap();
    let resigned = |change: &dyn Fn(&mut Value)| {
        let mut receipt = signed.clone();
        change(&mut receipt);
        receipt.as_object_mut().unwrap().remove("sig");
        let sig = tokencrumb_mcp_proxy::keys::sign(
            &g.approver.private_str,
            &tokencrumb_mcp_proxy::canonical::canonicalize(&receipt).unwrap(),
        )
        .unwrap();
        receipt["sig"] = json!(tokencrumb_mcp_proxy::attestation::b64u_encode(&sig));
        encode_receipt(&receipt)
    };
    let cases = [
        "not base64 !".to_owned(),
        encode_receipt(&json!({"v": 1})),
        "A".repeat(5000),
        resigned(&|r| r["v"] = json!(2)),
        resigned(&|r| r["max_uses"] = json!(2)),
        resigned(&|r| r["decision"] = json!("deny")),
        resigned(&|r| r["extra"] = json!("field")),
        resigned(&|r| r["intent_hash"] = json!("sha256:short")),
    ];
    for receipt in cases {
        let reply = g.call(&app, &token, Some(&receipt)).await;
        assert_refused(&g, &reply, &upstream, "receipt malformed");
    }
    // A tampered field breaks the signature.
    let mut tampered = signed.clone();
    tampered["request_id"] = json!("apr_other");
    let reply = g.call(&app, &token, Some(&encode_receipt(&tampered))).await;
    assert_refused(&g, &reply, &upstream, "receipt signature invalid");
}

// -- H-14: the policy keeps approvers apart --------------------------------------------------

#[test]
fn h14_misconfigured_approvers_are_refused_at_startup_and_reload() {
    let g = Gw::new();
    let with_key = |key: &str| {
        let mut raw = base_policy(&g, None, false);
        raw["approvers"]["ops"]["members"][0]["keys"] = json!([key]);
        raw
    };
    let build = |policy: Policy, options: VerifierOptions| {
        Verifier::new(&g.world.authority.public_str, policy, options)
            .err()
            .map(|e| e.message)
    };

    // A root key, the audit key: refused when the verifier starts.
    let root = build(
        g.policy_from(with_key(&g.world.authority.public_str)),
        g.options(),
    );
    assert!(root.unwrap().contains("reuses a root authority key"));
    let audit = build(
        g.policy_from(with_key(&g.world.audit_key.public_str)),
        g.options(),
    );
    assert!(audit.unwrap().contains("reuses the audit key"));
    // In-memory state: single use would not survive a restart.
    let mut memory = g.options();
    memory.receipt_store = None;
    assert!(
        build(g.policy(), memory)
            .unwrap()
            .contains("persistent state")
    );

    // Rules the file alone can break: refused by the parser.
    let mut third = base_policy(&g, None, true);
    third["approvers"]["ops"]["members"][0]["keys"] = json!([g.third_party.public_str]);
    let err = parse_policy(&third).unwrap_err().message;
    assert!(err.contains("third-party authority key"), "{err}");
    let mut shared = base_policy(&g, None, false);
    shared["approvers"]["legal"]["members"][0]["keys"] = json!([g.approver.public_str]);
    assert!(
        parse_policy(&shared)
            .unwrap_err()
            .message
            .contains("one approver only")
    );
    for proof in ["call_signature_valid", "nonce_fresh", "arguments_bound"] {
        let mut missing = base_policy(&g, None, false);
        let require: Vec<&str> = ["call_signature_valid", "nonce_fresh", "arguments_bound"]
            .into_iter()
            .filter(|p| *p != proof)
            .collect();
        missing["tools"][0]["require"] = json!(require);
        assert!(
            parse_policy(&missing)
                .unwrap_err()
                .message
                .contains("approval requires")
        );
    }
    let mut unknown_group = base_policy(&g, None, false);
    unknown_group["tools"][0]["approval"]["approvers"] = json!(["nobody"]);
    assert!(parse_policy(&unknown_group).is_err());
    let mut too_long = base_policy(&g, None, false);
    too_long["tools"][0]["approval"]["receipt_ttl"] = json!("2h");
    assert!(parse_policy(&too_long).is_err());

    // Reload: an invalid file and a root-key reuse both keep the policy in force.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let publish = |raw: &Value| {
        let next = dir.path().join("next.yaml");
        std::fs::write(&next, serde_json::to_string(raw).unwrap()).unwrap();
        std::fs::rename(&next, &path).unwrap();
    };
    publish(&base_policy(&g, None, false));
    let current = parse_policy_text(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let verifier = g.verifier_with(g.policy());
    let check = verifier.clone();
    let reloader = PolicyReloader::new(&path, current.clone(), Duration::ZERO, Box::new(|_, _| {}))
        .with_validator(Box::new(move |p| check.check_approval_policy(p)));
    for bad in [shared, with_key(&g.world.authority.public_str)] {
        std::thread::sleep(Duration::from_millis(5));
        publish(&bad);
        assert_eq!(
            reloader.current().approvers,
            current.approvers,
            "reload refused"
        );
    }

    // And a verifier handed such a policy anyway refuses every call.
    verifier.set_policy(g.policy_from(with_key(&g.world.authority.public_str)));
    let token = g.token();
    let arguments = json!({"path": PATH});
    let attestation = build_attestation(
        AGENT,
        TOOL,
        &arguments,
        &token,
        &g.world.agent.private_str,
        Some(g.now()),
    )
    .unwrap();
    let decision = verifier
        .verify_call(
            TOOL,
            &arguments,
            &common::proxy::biscuit_headers(&token, Some(&attestation)),
            None,
            None,
        )
        .unwrap();
    assert!(!decision.allow && decision.hold.is_none());
    assert!(
        decision.reason.starts_with("policy error: approver"),
        "{}",
        decision.reason
    );
}

// -- H-15 to H-17: an approval never replaces anything else ---------------------------------

#[tokio::test]
async fn h15_a_receipt_does_not_create_a_right() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    // The mandate covers /workspace/project/ only; the policy would allow /workspace/.
    let token = g.token_for(TOOL, "/workspace/project/");
    let receipt = g.sign(
        &g.approver,
        "a.dupont",
        &g.intent_hash(&token, TOOL, PATH),
        g.now(),
        300,
    );
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert!(is_deny(&reply) && !upstream.reached());
    let last = g.last();
    assert_eq!(last["decision"], "DENY");
    assert!(
        last["reason"]
            .as_str()
            .unwrap()
            .starts_with("policy denied"),
        "{last}"
    );
    assert!(
        g.store().get(&receipt_id(&receipt)).unwrap().is_none(),
        "not consumed"
    );
    // Without a receipt the out-of-mandate call is denied, not held.
    let reply = g.call(&app, &token, None).await;
    assert!(is_deny(&reply));
    assert_eq!(g.last()["decision"], "DENY");
}

#[tokio::test]
async fn h16_a_receipt_and_an_endorsement_are_both_required() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let policy = g.policy_from(base_policy(&g, None, true));
    let app = g.app_with(upstream.clone(), policy, None);
    let token = g.token();
    let request = biscuit_ops::third_party_request(&token, &g.world.authority.public_str).unwrap();
    let block = biscuit_ops::sign_third_party(
        &request,
        &g.third_party.private_str,
        &Endorse {
            predicate: "approval".into(),
            tools: vec![TOOL.into()],
            resource_prefix: "/workspace/".into(),
            ttl_seconds: 600,
        },
    )
    .unwrap();
    let endorsed =
        biscuit_ops::append_third_party(&token, &g.world.authority.public_str, &block, None)
            .unwrap();

    // The receipt alone: the endorsement is still missing.
    let receipt = g.sign(
        &g.approver,
        "a.dupont",
        &g.intent_hash(&token, TOOL, PATH),
        g.now(),
        300,
    );
    let reply = g.call(&app, &token, Some(&receipt)).await;
    assert_refused(
        &g,
        &reply,
        &upstream,
        "policy denied: third-party endorsement missing: notary.approval (absent, expired or out of scope)",
    );
    // A receipt given before the endorsement was appended does not cover the new mandate.
    let reply = g.call(&app, &endorsed, Some(&receipt)).await;
    assert_refused(&g, &reply, &upstream, "receipt intent mismatch");
    // The endorsement alone: held.
    let held = g.call(&app, &endorsed, None).await;
    assert_eq!(g.last()["decision"], "HOLD");
    assert!(!upstream.reached());
    // Both: allowed, with both on the record.
    let reply = g.call(&app, &endorsed, Some(&g.approve(&held))).await;
    assert_eq!(reply.json()["result"]["ok"], true);
    let allow = g
        .entries()
        .into_iter()
        .rev()
        .find(|e| e["decision"] == "ALLOW")
        .unwrap();
    assert_eq!(allow["detail"]["third_party"][0]["authority"], "notary");
    assert_eq!(allow["detail"]["approval"]["approver_id"], "a.dupont");
}

#[tokio::test]
async fn h17_holds_cost_nothing_and_an_exhausted_budget_keeps_the_receipt() {
    let g = Gw::with_budget(1);
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let first = g.approve(&g.call(&app, &token, None).await);
    let second = g.approve(&g.call(&app, &token, None).await);
    assert_eq!(g.last()["remaining_budget"], 1, "no debit while held");

    g.call(&app, &token, Some(&first)).await;
    let entries = g.entries();
    let allow = &entries[entries.len() - 2];
    assert_eq!(allow["decision"], "ALLOW");
    assert_eq!(
        allow["remaining_budget"], 0,
        "charged after the receipt was consumed"
    );
    upstream.clear();

    // Exhausted: refused before any hold, and before the receipt is looked at.
    let reply = g.call(&app, &token, None).await;
    assert_refused(&g, &reply, &upstream, "policy denied: budget exhausted");
    let reply = g.call(&app, &token, Some(&second)).await;
    assert_refused(&g, &reply, &upstream, "policy denied: budget exhausted");
    assert!(
        g.store().get(&receipt_id(&second)).unwrap().is_none(),
        "second receipt intact"
    );
}

// -- H-19: the audit chain ---------------------------------------------------------------------

#[tokio::test]
async fn h19_the_audit_of_the_whole_scenario_verifies() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let receipt = g.approve(&g.call(&app, &token, None).await);
    g.call(&app, &token, Some(&receipt)).await;
    g.call(&app, &token, Some(&receipt)).await;

    let decisions: Vec<String> = g
        .entries()
        .iter()
        .map(|e| e["decision"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(decisions, ["HOLD", "ALLOW", "OUTCOME", "DENY"]);
    let trusted = tokencrumb_mcp_proxy::audit::trusted_from(std::slice::from_ref(
        &g.world.audit_key.public_str,
    ))
    .unwrap();
    let result = tokencrumb_mcp_proxy::audit::verify_log(&g.world.audit_path(), &trusted).unwrap();
    assert!(result.ok, "{:?}", result.failures);
    // The CLI reads the new decisions too.
    let dir = g.world.dir.path();
    tokencrumb_mcp_proxy::keys::save_public_key(
        dir.join("audit.pub"),
        &g.world.audit_key.public_str,
    )
    .unwrap();
    let out = common::bm(
        dir,
        &["audit-verify", "--log", "audit.log", "--pub", "audit.pub"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
}

// -- H-29: processes sharing the database -----------------------------------------------------

#[tokio::test]
async fn h29_a_restart_never_settles_another_process_call_in_flight() {
    let g = Gw::new();
    let token = g.token();
    let fake = FakeUpstream::default_json();
    let one = g.app(&fake);
    let receipt = g.approve(&g.call(&one, &token, None).await);

    // Process A consumes the receipt; its call is in flight (lease of 90 s).
    let process_a = g.verifier_with(g.policy());
    let arguments = json!({"path": PATH});
    let attestation = build_attestation(
        AGENT,
        TOOL,
        &arguments,
        &token,
        &g.world.agent.private_str,
        Some(g.now()),
    )
    .unwrap();
    let mut headers = common::proxy::biscuit_headers(&token, Some(&attestation));
    headers.0.push(("approval-receipt".into(), receipt.clone()));
    let decision = process_a
        .verify_call(TOOL, &arguments, &headers, None, None)
        .unwrap();
    assert!(decision.allow);
    let id = receipt_id(&receipt);

    // Process B restarts meanwhile: A's row is left alone.
    g.advance(30);
    let _restart = g.app(&fake);
    let row = g.store().get(&id).unwrap().unwrap();
    assert_eq!(
        (row.state.as_str(), row.instance_id.as_str()),
        ("reserved", process_a.instance_id.as_str())
    );
    assert!(!g.entries().iter().any(|e| e["decision"] == "OUTCOME"));

    // A settles its own call.
    let store = process_a.receipts.clone().unwrap();
    assert!(
        store
            .finish(&id, &process_a.instance_id, "ok", 0.0)
            .unwrap()
    );
    assert_eq!(g.store().get(&id).unwrap().unwrap().state, "ok");

    // A reservation whose owner died, past its lease, is settled unknown by B.
    let other = sign_receipt(
        &g.approver.private_str,
        "a.dupont",
        "apr_y",
        &g.intent_hash(&token, TOOL, PATH),
        g.now(),
        300,
    )
    .unwrap();
    let other = encode_receipt(&other);
    let attestation = build_attestation(
        AGENT,
        TOOL,
        &arguments,
        &token,
        &g.world.agent.private_str,
        Some(g.now()),
    )
    .unwrap();
    let mut headers = common::proxy::biscuit_headers(&token, Some(&attestation));
    headers.0.push(("approval-receipt".into(), other.clone()));
    assert!(
        process_a
            .verify_call(TOOL, &arguments, &headers, None, None)
            .unwrap()
            .allow
    );
    g.advance(100);
    let _restart = g.app(&fake);
    assert_eq!(
        g.store().get(&receipt_id(&other)).unwrap().unwrap().state,
        "unknown"
    );
    assert_eq!(
        g.store().get(&id).unwrap().unwrap().state,
        "ok",
        "final rows untouched"
    );
    // A late answer from A no longer moves it.
    assert!(
        !store
            .finish(&receipt_id(&other), &process_a.instance_id, "ok", 0.0)
            .unwrap()
    );
}

// -- warn-only ------------------------------------------------------------------------------

#[tokio::test]
async fn warn_only_still_holds_and_never_forwards_a_refused_receipt() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app_with(upstream.clone(), g.policy(), Some("warn-only"));
    let token = g.token();
    let held = g.call(&app, &token, None).await;
    assert!(approval_required(&held).is_object());
    assert!(!upstream.reached());
    let reply = g.call(&app, &token, Some("garbage")).await;
    assert_refused(&g, &reply, &upstream, "receipt malformed");
    assert_eq!(g.last()["enforced"], true);
    let reply = g.call(&app, &token, Some(&g.approve(&held))).await;
    assert_eq!(reply.json()["result"]["ok"], true);
}

// -- H-30 and the CLI ----------------------------------------------------------------------

#[tokio::test]
async fn h30_approve_neutralizes_the_display_and_signs_the_real_arguments() {
    let g = Gw::new();
    let upstream = FakeUpstream::default_json();
    let app = g.app(&upstream);
    let token = g.token();
    let hostile = "/workspace/a\u{1b}]8;;https://evil\u{7}ok\u{1b}]8;;\u{7}\u{202e}txt.exe";
    let arguments = json!({"path": "/workspace/x.txt", "note": hostile, "bell": "\u{7}\u{200b}"});
    let held = g
        .call_tool(&app, &token, TOOL, arguments.clone(), None)
        .await;
    let dir = g.world.dir.path();
    std::fs::write(
        dir.join("request.json"),
        serde_json::to_string(&json!({"approval_required": approval_required(&held)})).unwrap(),
    )
    .unwrap();
    tokencrumb_mcp_proxy::keys::save_private_key(
        dir.join("approver.key"),
        &g.approver.private_str,
        None,
    )
    .unwrap();

    let out = common::bm(
        dir,
        &[
            "approve",
            "--request",
            "request.json",
            "--key",
            "approver.key",
            "--approver-id",
            "a.dupont",
            "--ttl",
            "5m",
            "--yes",
            "--out",
            "receipt.json",
        ],
    );
    let shown = common::stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{shown}");
    for raw in ['\u{1b}', '\u{7}', '\u{202e}', '\u{200b}'] {
        assert!(!shown.contains(raw), "raw {raw:?} reached the terminal");
    }
    assert!(shown.contains("\\u{202E}") && shown.contains("\\u{200B}"));
    assert!(shown.contains("WARNING"));
    assert!(shown.contains("delete_file") && shown.contains("/workspace/x.txt"));

    let receipt: Value =
        serde_json::from_slice(&std::fs::read(dir.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(
        receipt["intent_hash"],
        approval_required(&held)["intent_hash"]
    );
    let reply = g
        .call_tool(
            &app,
            &token,
            TOOL,
            arguments,
            Some(&encode_receipt(&receipt)),
        )
        .await;
    assert_eq!(reply.json()["result"]["ok"], true);

    let inspected = common::bm(
        dir,
        &[
            "inspect-receipt",
            "--receipt",
            "receipt.json",
            "--request",
            "request.json",
        ],
    );
    assert_eq!(
        inspected.status.code(),
        Some(0),
        "{}",
        common::stderr(&inspected)
    );
    assert!(common::stdout(&inspected).contains("signature  : valid"));

    // A request whose arguments were edited after the hold is refused, not signed.
    let mut edited = approval_required(&held);
    edited["arguments"]["path"] = json!("/workspace/y.txt");
    std::fs::write(dir.join("edited.json"), edited.to_string()).unwrap();
    let out = common::bm(
        dir,
        &[
            "approve",
            "--request",
            "edited.json",
            "--key",
            "approver.key",
            "--approver-id",
            "a.dupont",
            "--yes",
            "--out",
            "edited-receipt.json",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(common::stderr(&out).contains("do not match"));
    assert!(!dir.join("edited-receipt.json").exists());
    // An unknown intent version is refused.
    let mut future = approval_required(&held);
    future["intent"]["v"] = json!(2);
    std::fs::write(dir.join("v2.json"), future.to_string()).unwrap();
    let out = common::bm(
        dir,
        &[
            "approve",
            "--request",
            "v2.json",
            "--key",
            "approver.key",
            "--approver-id",
            "a.dupont",
            "--yes",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(common::stderr(&out).contains("unknown version"));
    // Without --yes, nothing is signed unless the approver confirms.
    let out = common::bm_stdin(
        dir,
        &[
            "approve",
            "--request",
            "request.json",
            "--key",
            "approver.key",
            "--approver-id",
            "a.dupont",
            "--out",
            "declined.json",
        ],
        b"n\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.join("declined.json").exists());
}

#[test]
fn keygen_writes_an_approver_pair() {
    let dir = tempfile::tempdir().unwrap();
    let out = common::bm(
        dir.path(),
        &["keygen", "--type", "approver", "--out", "ops"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(dir.path().join("ops.key").is_file() && dir.path().join("ops.pub").is_file());
}

#[test]
fn the_example_policy_parses_once_its_keys_are_filled_in() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy-approval.yaml");
    let text = std::fs::read_to_string(path)
        .unwrap()
        .replace(
            "ed25519/REPLACE_WITH_A_DUPONT_CURRENT_KEY",
            &generate_keypair().public_str,
        )
        .replace(
            "ed25519/REPLACE_WITH_B_MARTIN_KEY",
            &generate_keypair().public_str,
        );
    let policy = parse_policy_text(&text).unwrap();
    let tool = policy.tool("delete_file").unwrap();
    assert_eq!(tool.approval.as_ref().unwrap().receipt_ttl_seconds, 300);
    assert_eq!(policy.approvers[0].members.len(), 2);
}

// -- §6.13: end to end, with the binary ----------------------------------------------------

/// `serve`, `client-wrap --approval-dir` and `approve` as separate processes: the hold,
/// the request written by the wrapper, the approval, the accepted replay, the refused
/// replay and the verified audit.
#[test]
fn end_to_end_hold_approve_replay_with_the_binary() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let authority = common::keyfiles(state, "authority");
    let agent = common::keyfiles(state, "agent");
    common::keyfiles(state, "audit");
    let approver = common::keyfiles(state, "approver");
    let policy = json!({
        "mode": "enforce",
        "min_profile": "hardened_biscuit_anchored",
        "approvers": {"ops": {"members": [{"id": "a.dupont", "keys": [approver.public_str]}]}},
        "tools": [{
            "name": TOOL, "operation": "write", "resource": {"from": "arguments.path"},
            "allow": {"resource_prefix": "/workspace/", "budget": 5},
            "require": ["call_signature_valid", "nonce_fresh", "arguments_bound"],
            "approval": {"approvers": ["ops"], "receipt_ttl": "5m"},
        }],
    });
    std::fs::write(state.join("policy.yaml"), policy.to_string()).unwrap();
    let token = biscuit_ops::forge(
        &authority.private_str,
        &ForgeRequest {
            agent_id: AGENT.into(),
            tool: TOOL.into(),
            operation: "write".into(),
            ttl_seconds: 900,
            budget: 5,
            resource_prefix: Some("/workspace/".into()),
            agent_pubkey: Some(agent.public_str.clone()),
            required_profile: "hardened_biscuit_anchored".into(),
            audience: TEST_AUDIENCE.into(),
            ..Default::default()
        },
    )
    .unwrap();
    std::fs::write(state.join("capability.b64"), &token).unwrap();

    let upstream = common::stub::serve(|request| {
        let message = request.json();
        let result = match message["method"].as_str() {
            Some("initialize") => {
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                          "serverInfo": {"name": "stub", "version": "1"}})
            }
            _ => json!({"content": [{"type": "text", "text": "deleted"}]}),
        };
        common::stub::StubResponse::json(
            &json!({"jsonrpc": "2.0", "id": message["id"], "result": result}),
        )
    });
    let listen = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let binary = env!("CARGO_BIN_EXE_tokencrumb");
    let log = std::fs::File::create(state.join("serve.log")).unwrap();
    let mut proxy = Command::new(binary)
        .args([
            "serve",
            "--upstream",
            &format!("{}/mcp", upstream.url),
            "--authority-pub",
            "authority.pub",
            "--policy",
            "policy.yaml",
            "--audience",
            TEST_AUDIENCE,
            "--audit-key",
            "audit.key",
            "--audit",
            "audit.log",
            "--budget-state",
            "budget.json",
            "--listen",
            &format!("127.0.0.1:{listen}"),
        ])
        .current_dir(state)
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::net::TcpStream::connect(("127.0.0.1", listen)).is_err() {
        assert!(
            proxy.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(state.join("serve.log")).unwrap()
        );
        assert!(std::time::Instant::now() < deadline, "proxy did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut wrapper = Command::new(binary)
        .args([
            "client-wrap",
            "--proxy",
            &format!("http://127.0.0.1:{listen}/mcp"),
            "--token",
            "capability.b64",
            "--agent-key",
            "agent.key",
            "--approval-dir",
            "approvals",
        ])
        .current_dir(state)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = wrapper.stdin.take().unwrap();
    let mut output = BufReader::new(wrapper.stdout.take().unwrap());
    let mut sequence = 0;
    let mut rpc = |method: &str, params: Value| -> Value {
        sequence += 1;
        writeln!(
            input,
            "{}",
            json!({"jsonrpc": "2.0", "id": sequence, "method": method, "params": params})
        )
        .unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let delete = json!({"name": TOOL, "arguments": {"path": PATH}});

    assert!(
        rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "e2e", "version": "1"}})
        )["result"]
            .is_object()
    );
    let held = rpc("tools/call", delete.clone());
    let request_id = held["result"]["structuredContent"]["approval_required"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let tool_calls = || {
        upstream
            .calls()
            .iter()
            .filter(|c| c.json()["method"] == "tools/call")
            .count()
    };
    assert_eq!(tool_calls(), 0, "held, not forwarded");
    let request = format!("approvals/requests/{request_id}.json");
    assert!(
        state.join(&request).is_file(),
        "the wrapper wrote the request"
    );

    let receipt = format!("approvals/receipts/{request_id}.json");
    let approved = common::bm(
        state,
        &[
            "approve",
            "--request",
            &request,
            "--key",
            "approver.key",
            "--approver-id",
            "a.dupont",
            "--yes",
            "--out",
            &receipt,
        ],
    );
    assert_eq!(
        approved.status.code(),
        Some(0),
        "{}",
        common::stderr(&approved)
    );

    let allowed = rpc("tools/call", delete.clone());
    assert_eq!(
        allowed["result"]["content"][0]["text"], "deleted",
        "{allowed}"
    );
    assert_eq!(tool_calls(), 1);
    let used = state.join(format!("approvals/used/{request_id}.json"));
    assert!(
        used.is_file() && !state.join(&receipt).exists(),
        "the receipt moved to used/"
    );
    assert!(
        upstream
            .calls()
            .iter()
            .all(|c| c.header("approval-receipt").is_none())
    );

    // The same receipt again: refused by the gateway, nothing forwarded.
    std::fs::copy(&used, state.join(&receipt)).unwrap();
    let replayed = rpc("tools/call", delete);
    assert!(
        replayed["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("DENY")
    );
    assert_eq!(tool_calls(), 1);

    let _ = wrapper.kill();
    let _ = wrapper.wait();
    let _ = proxy.kill();
    let _ = proxy.wait();
    let entries = common::proxy::audit_entries(&state.join("audit.log"));
    let decisions: Vec<&str> = entries
        .iter()
        .filter(|e| e["method"] == "tools/call")
        .map(|e| e["decision"].as_str().unwrap())
        .collect();
    assert_eq!(decisions, ["HOLD", "ALLOW", "OUTCOME", "DENY"]);
    assert_eq!(entries.last().unwrap()["reason"], "receipt already used");
    let verified = common::bm(
        state,
        &["audit-verify", "--log", "audit.log", "--pub", "audit.pub"],
    );
    assert_eq!(
        verified.status.code(),
        Some(0),
        "{}",
        common::stderr(&verified)
    );
}
