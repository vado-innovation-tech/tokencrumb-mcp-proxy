//! The `tokencrumb` binary, command by command.
//!
//! Ported from the CLI-driven parts of `tests/test_security_lifecycle.py`
//! (`test_cli_inline_token_and_existing_key_are_handled`,
//! `test_revoke_child_can_be_targeted_but_from_token_revokes_the_root_family`,
//! `test_revocation_migration_authenticates_old_entries_and_keeps_them`), with
//! `tests/test_biscuit_ops.py` and `tests/test_one_shot.py` re-driven through the CLI:
//! the mandates are forged and attenuated by the binary, then checked by the verifier.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use base64::Engine as _;
use tokencrumb_mcp_proxy::biscuit_ops as ops;
use tokencrumb_mcp_proxy::canonical::canonicalize;
use tokencrumb_mcp_proxy::json::strict_json;
use tokencrumb_mcp_proxy::keys;
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::revocation::{RevocationList, update_revocation_list, validate_document};
use tokencrumb_mcp_proxy::verifier::{Headers, Verifier, VerifierOptions};
use common::{TEST_AUDIENCE, bm, keyfiles, stderr, stdout};
use serde_json::{Value, json};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// `forge` through the binary; returns the token printed on stdout.
fn forge(dir: &Path, extra: &[&str]) -> String {
    let mut args = vec![
        "forge",
        "--key",
        "authority.key",
        "--audience",
        TEST_AUDIENCE,
    ];
    args.extend_from_slice(extra);
    let output = bm(dir, &args);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stderr(&output), "forged token:\n");
    let text = stdout(&output);
    assert_eq!(text.lines().count(), 1, "stdout carries the token only");
    text.trim().to_owned()
}

fn verifier(public: &str, policy: Value, options: VerifierOptions) -> Verifier {
    let mut policy = parse_policy(&policy).unwrap();
    policy.policy_digest = "test".into();
    Verifier::new(public, policy, options).unwrap()
}

fn allowed(verifier: &Verifier, token: &str, tool: &str, arguments: Value) -> bool {
    let headers = Headers::new([("authorization", format!("Biscuit {token}"))]);
    verifier
        .verify_call(tool, &arguments, &headers, None, None)
        .unwrap()
        .allow
}

fn read_file_policy() -> Value {
    json!({
        "deny_unknown_tools": true,
        "min_profile": "native",
        "tools": [{
            "name": "read_file",
            "operation": "read",
            "resource": {"from": "arguments.path"},
            "allow": {"resource_prefix": "/projets/acme/", "budget": 200},
        }],
    })
}

// --------------------------------------------------------------------------- //
// keygen
// --------------------------------------------------------------------------- //

#[test]
fn keygen_writes_a_private_pair_and_never_overwrites_it() {
    let dir = tempfile::tempdir().unwrap();
    let output = bm(dir.path(), &["keygen", "--out", "key"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let public = std::fs::read_to_string(dir.path().join("key.pub")).unwrap();
    let text = stdout(&output);
    assert!(text.lines().next().unwrap().contains(" keygen "));
    assert!(text.contains("authority keypair generated"));
    assert!(text.contains("private : key.key (0600)"));
    assert!(text.contains(&format!("pubkey  : {}", public.trim())));
    assert_eq!(mode(&dir.path().join("key.key")), 0o600);
    let private = keys::load_private_key(dir.path().join("key.key"), None).unwrap();
    assert_eq!(keys::public_from_private(&private).unwrap(), public.trim());

    let original = std::fs::read(dir.path().join("key.key")).unwrap();
    let again = bm(dir.path(), &["keygen", "--out", "key"]);
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(
        stderr(&again).trim(),
        "error: key files already exist; choose another --out for an explicit rotation"
    );
    assert_eq!(std::fs::read(dir.path().join("key.key")).unwrap(), original);

    let bad = bm(dir.path(), &["keygen", "--out", "x", "--type", "root"]);
    assert_eq!(bad.status.code(), Some(1));
    assert_eq!(
        stderr(&bad).trim(),
        "error: --type must be 'authority', 'agent' or 'audit'"
    );
}

#[test]
fn keygen_can_encrypt_and_forge_then_needs_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let output = bm(
        dir.path(),
        &[
            "keygen",
            "--out",
            "authority",
            "--type",
            "agent",
            "--passphrase",
            "pw",
        ],
    );
    assert!(stdout(&output).contains("private : authority.key (0600, encrypted)"));
    let refused = bm(
        dir.path(),
        &[
            "forge",
            "--key",
            "authority.key",
            "--tool",
            "t",
            "--audience",
            "gw",
        ],
    );
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        stderr(&refused).trim(),
        "error: cannot load private key: private key is encrypted; a passphrase is required"
    );
    let ok = bm(
        dir.path(),
        &[
            "forge",
            "--key",
            "authority.key",
            "--tool",
            "t",
            "--audience",
            "gw",
            "--passphrase",
            "pw",
        ],
    );
    assert!(ok.status.success(), "{}", stderr(&ok));
}

// --------------------------------------------------------------------------- //
// forge / attenuate / inspect (test_biscuit_ops.py, through the binary)
// --------------------------------------------------------------------------- //

#[test]
fn forge_inspect_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    keyfiles(dir.path(), "authority");
    let agent = keys::generate_keypair();
    let token = forge(
        dir.path(),
        &[
            "--agent-id",
            "a1",
            "--tool",
            "read_file",
            "--ttl",
            "1h",
            "--resource-prefix",
            "/projets/acme/",
            "--agent-pubkey",
            &agent.public_str,
            "--required-profile",
            "hardened_biscuit_anchored",
        ],
    );
    let inspected = ops::inspect(&token).unwrap();
    assert_eq!(inspected.block_count, 1);
    assert_eq!(inspected.first_str("agent_id"), Some("a1"));
    assert_eq!(
        inspected.first_str("required_profile"),
        Some("hardened_biscuit_anchored")
    );
    assert_eq!(
        ops::authority_pubkey(&token).unwrap().unwrap().as_str(),
        Some(agent.public_str.as_str())
    );

    // `inspect` shows it — from the literal token (longer than a file name may be)
    // and from a file.
    assert!(token.len() > 255);
    std::fs::write(dir.path().join("mandate.b64"), format!("{token}\n")).unwrap();
    for argument in [token.as_str(), "mandate.b64"] {
        let output = bm(dir.path(), &["inspect", argument]);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        let rows: Vec<Vec<&str>> = text
            .lines()
            .skip(1)
            .take(7)
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert_eq!(rows[0], ["│", "blocks", "1", "│"]);
        assert_eq!(rows[1], ["│", "root_key_id", "None", "│"]);
        assert_eq!(rows[2], ["│", "agent_id", "a1", "│"]);
        assert_eq!(
            rows[3],
            ["│", "required_profile", "hardened_biscuit_anchored", "│"]
        );
        assert_eq!(rows[4], ["│", "agent_pubkey", &agent.public_str, "│"]);
        assert_eq!(rows[5], ["│", "audience", TEST_AUDIENCE, "│"]);
        assert_eq!(rows[6], ["│", "revocation_ids", "1", "│"]);
        assert!(text.contains(" block 0 · authority "));
        assert!(text.contains("│ right(\"read_file\", \"read\");"));
        assert!(text.contains("check if resource($r), $r.starts_with(\"/projets/acme/\");"));
    }

    let output = bm(dir.path(), &["inspect", "not-a-token"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: cannot inspect token: "));
}

#[test]
fn attenuate_is_monotonic_appends_and_keeps_the_capability_key() {
    let dir = tempfile::tempdir().unwrap();
    keyfiles(dir.path(), "authority");
    let token = forge(
        dir.path(),
        &[
            "--agent-id",
            "a1",
            "--tool",
            "read_file",
            "--ttl",
            "1h",
            "--resource-prefix",
            "/projets/",
        ],
    );
    std::fs::write(dir.path().join("mandate.b64"), &token).unwrap();
    let output = bm(
        dir.path(),
        &[
            "attenuate",
            "--token",
            "mandate.b64",
            "--authority-pub",
            "authority.pub",
            "--resource",
            "/projets/acme/",
            "--budget",
            "10",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stderr(&output), "attenuated token:\n");
    let attenuated = stdout(&output).trim().to_owned();
    assert_eq!(ops::inspect(&attenuated).unwrap().block_count, 2);
    assert_eq!(ops::min_budget_cap(&attenuated).unwrap(), Some(10));
    assert_eq!(
        ops::capability_key(&token).unwrap(),
        ops::capability_key(&attenuated).unwrap()
    );
    let text = stdout(&bm(dir.path(), &["inspect", &attenuated]));
    assert!(text.contains(" block 1 · attenuation "));
    assert!(text.contains("│ budget_cap(10);"));

    // --out writes a private file and says so on stderr; stdout stays empty.
    let output = bm(
        dir.path(),
        &[
            "attenuate",
            "--token",
            &token,
            "--authority-pub",
            "authority.pub",
            "--ttl",
            "5m",
            "--out",
            "narrow.b64",
        ],
    );
    assert!(output.status.success());
    assert!(stdout(&output).is_empty());
    assert_eq!(stderr(&output).trim(), "attenuated token -> narrow.b64");
    assert_eq!(mode(&dir.path().join("narrow.b64")), 0o600);

    for (extra, message) in [
        (
            vec![],
            "error: attenuation failed: attenuate needs at least one of: resource, budget, ttl, upstream, max-depth",
        ),
        (
            vec!["--ttl", "soon"],
            "error: attenuation failed: invalid duration: 'soon' (use e.g. 300s, 15m, 8h, 1d)",
        ),
        (
            vec!["--budget", "-1"],
            "error: attenuation failed: budget: expected integer in [0, 9007199254740991]",
        ),
    ] {
        let mut args = vec![
            "attenuate",
            "--token",
            "mandate.b64",
            "--authority-pub",
            "authority.pub",
        ];
        args.extend(extra);
        let output = bm(dir.path(), &args);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stderr(&output).trim(), message);
    }
    // Only a token the authority signed is re-serialized.
    keyfiles(dir.path(), "other");
    let output = bm(
        dir.path(),
        &[
            "attenuate",
            "--token",
            "mandate.b64",
            "--authority-pub",
            "other.pub",
            "--budget",
            "1",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: attenuation failed: "));
}

#[test]
fn forge_refusals_and_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    keyfiles(dir.path(), "authority");
    let base = [
        "forge",
        "--key",
        "authority.key",
        "--tool",
        "t",
        "--audience",
        "gw",
    ];
    for (extra, message) in [
        (
            vec!["--fact", "bad"],
            "error: cannot parse fact 'bad' (expected: name(\"value\", ...))",
        ),
        (
            vec!["--budget", "-1"],
            "error: budget: expected integer in [0, 9007199254740991]",
        ),
        (
            vec!["--fact", "agent_id(\"x\")"],
            "error: reserved predicate: agent_id",
        ),
        (
            vec!["--scope-arg", "x"],
            "error: cannot parse scope arg 'x' (expected: arg_name=fact_predicate)",
        ),
    ] {
        let mut args = base.to_vec();
        args.extend(extra);
        let output = bm(dir.path(), &args);
        assert_eq!(output.status.code(), Some(1), "{message}");
        assert_eq!(stderr(&output).trim(), message);
        assert!(stdout(&output).is_empty());
    }
    let missing = bm(
        dir.path(),
        &[
            "forge",
            "--key",
            "none.key",
            "--tool",
            "t",
            "--audience",
            "gw",
        ],
    );
    assert_eq!(
        stderr(&missing).trim(),
        "error: cannot load private key: [Errno 2] No such file or directory: 'none.key'"
    );

    // Usage errors: exit code 2.
    let mut args = base.to_vec();
    args.extend(["--ttl", "xx"]);
    let output = bm(dir.path(), &args);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid duration: 'xx'"));
    assert_eq!(
        bm(dir.path(), &["forge", "--key", "k", "--tool", "t"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        bm(
            dir.path(),
            &[
                "forge",
                "--key",
                "k",
                "--tool",
                "t",
                "--audience",
                "gw",
                "--budget",
                "many"
            ]
        )
        .status
        .code(),
        Some(2)
    );
    assert_eq!(bm(dir.path(), &[]).status.code(), Some(2));
    assert_eq!(bm(dir.path(), &["nope"]).status.code(), Some(2));
    assert_eq!(bm(dir.path(), &["--help"]).status.code(), Some(0));
}

#[test]
fn forge_to_a_file_is_private_and_repeatable_options_accumulate() {
    let dir = tempfile::tempdir().unwrap();
    keyfiles(dir.path(), "authority");
    let output = bm(
        dir.path(),
        &[
            "forge",
            "--key",
            "authority.key",
            "--tool",
            "search",
            "--audience",
            "gw",
            "--fact",
            "site(\"A\")",
            "--fact",
            "site(\"B\")",
            "--fact",
            "level(3)",
            "--scope-arg",
            "site=site",
            "--upstream",
            "catalog",
            "--max-depth",
            "2",
            "--out",
            "m.b64",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).is_empty());
    assert_eq!(stderr(&output).trim(), "forged token -> m.b64");
    assert_eq!(mode(&dir.path().join("m.b64")), 0o600);
    let token = std::fs::read_to_string(dir.path().join("m.b64")).unwrap();
    assert!(token.ends_with('\n'));
    let source = &ops::inspect(token.trim()).unwrap().blocks[0];
    for statement in [
        "site(\"A\");",
        "site(\"B\");",
        "level(3);",
        "check if arg(\"site\", $x), site($x);",
        "check if upstream(\"catalog\");",
        "max_delegation_depth(2);",
    ] {
        assert!(source.contains(statement), "{statement} in {source}");
    }
}

// --------------------------------------------------------------------------- //
// One-shot mandate bound to an approved draft version (test_one_shot.py)
// --------------------------------------------------------------------------- //

#[test]
fn one_shot_forged_by_the_cli_allows_exactly_the_approved_version_once() {
    let dir = tempfile::tempdir().unwrap();
    let authority = keyfiles(dir.path(), "authority");
    let policy = json!({
        "deny_unknown_tools": true,
        "tools": [
            {"name": "prepare_email_draft", "operation": "write", "allow": {"budget": 20}},
            {"name": "send_email", "operation": "write",
             "args": [{"from": "arguments.draft_version_id", "as": "draft_version_id"}],
             "allow": {"budget": 10}},
        ],
    });
    let v = verifier(
        &authority.public_str,
        policy,
        VerifierOptions::new(TEST_AUDIENCE),
    );
    let send = |token: &str, version: &str| {
        allowed(
            &v,
            token,
            "send_email",
            json!({"draft_version_id": version}),
        )
    };
    let one_shot = |version: &str| {
        forge(
            dir.path(),
            &[
                "--agent-id",
                "redacteur",
                "--tool",
                "send_email",
                "--operation",
                "write",
                "--ttl",
                "300",
                "--budget",
                "1",
                "--fact",
                &format!("draft_version_id(\"{version}\")"),
                "--scope-arg",
                "draft_version_id=draft_version_id",
            ],
        )
    };

    // B4a: the drafting agent holds no send right before approval.
    let writer = forge(
        dir.path(),
        &[
            "--agent-id",
            "redacteur",
            "--tool",
            "prepare_email_draft",
            "--operation",
            "write",
            "--ttl",
            "1h",
            "--budget",
            "20",
        ],
    );
    assert!(!send(&writer, "v-7"));
    // B4b/B4c: the one-shot sends the approved version, once.
    let token = one_shot("v-7");
    assert!(send(&token, "v-7"));
    assert!(!send(&token, "v-7"), "budget_cap(1) is spent");
    // B4d: an edited draft is a version absent from the token.
    let token = one_shot("v-7");
    assert!(!send(&token, "v-8"));
    assert!(send(&token, "v-7"));

    // Why the one-shot must be forged, not attenuated: the counter is keyed on the
    // authority block, which survives attenuation.
    let parent = forge(
        dir.path(),
        &[
            "--agent-id",
            "redacteur",
            "--tool",
            "send_email",
            "--operation",
            "write",
            "--ttl",
            "1h",
            "--budget",
            "2",
            "--fact",
            "draft_version_id(\"v-7\")",
            "--scope-arg",
            "draft_version_id=draft_version_id",
        ],
    );
    assert!(send(&parent, "v-7") && send(&parent, "v-7"));
    let derived = bm(
        dir.path(),
        &[
            "attenuate",
            "--token",
            &parent,
            "--authority-pub",
            "authority.pub",
            "--budget",
            "1",
        ],
    );
    assert!(!send(stdout(&derived).trim(), "v-7"));
    assert!(
        send(&one_shot("v-7"), "v-7"),
        "a fresh forge has its own counter"
    );
}

// --------------------------------------------------------------------------- //
// revoke
// --------------------------------------------------------------------------- //

#[test]
fn revoke_child_can_be_targeted_but_from_token_revokes_the_root_family() {
    let dir = tempfile::tempdir().unwrap();
    let authority = keyfiles(dir.path(), "authority");
    let native = forge(
        dir.path(),
        &[
            "--agent-id",
            "agent-1",
            "--tool",
            "read_file",
            "--ttl",
            "1h",
            "--resource-prefix",
            "/projets/acme/",
        ],
    );
    let child = ops::attenuate(
        &native,
        &authority.public_str,
        &ops::Attenuation {
            resource: Some("/projets/acme/x/".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let sibling = ops::attenuate(
        &native,
        &authority.public_str,
        &ops::Attenuation {
            resource: Some("/projets/acme/y/".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let path = dir.path().join("revoked");
    let child_id = ops::inspect(&child)
        .unwrap()
        .revocation_ids
        .last()
        .unwrap()
        .clone();
    update_revocation_list(&path, &authority.private_str, &[child_id]).unwrap();
    let mut options = VerifierOptions::new(TEST_AUDIENCE);
    options.revocation = Some(Arc::new(
        RevocationList::new(&path, &authority.public_str, None, None).unwrap(),
    ));
    let v = verifier(&authority.public_str, read_file_policy(), options);
    let call = |token: &str, target: &str| allowed(&v, token, "read_file", json!({"path": target}));

    assert!(!call(&child, "/projets/acme/x/item"));
    assert!(call(&sibling, "/projets/acme/y/item") && call(&native, "/projets/acme/x/item"));

    let output = bm(
        dir.path(),
        &[
            "revoke",
            "--key",
            "authority.key",
            "--out",
            "revoked",
            "--from-token",
            &child,
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).trim(),
        "revocation list revoked now has 2 id(s)"
    );
    assert_eq!(
        ops::capability_key(&child).unwrap(),
        ops::capability_key(&native).unwrap()
    );
    assert!(!call(&native, "/projets/acme/x/item") && !call(&sibling, "/projets/acme/y/item"));
}

#[test]
fn revoke_adds_ids_and_refuses_a_token_from_another_authority() {
    let dir = tempfile::tempdir().unwrap();
    let authority = keyfiles(dir.path(), "authority");
    let output = bm(
        dir.path(),
        &["revoke", "--key", "authority.key", "--add", "jti:1"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).trim(),
        "revocation list revoked.list now has 1 id(s)"
    );
    let doc = strict_json(std::fs::read(dir.path().join("revoked.list")).unwrap()).unwrap();
    validate_document(&doc, &authority.public_str, None, true).unwrap();
    assert_eq!(doc["revoked"], json!(["jti:1"]));

    // A token signed by another authority is refused unless --authority-pub names it.
    let other = keyfiles(dir.path(), "other");
    let foreign = ops::forge(
        &other.private_str,
        &ops::ForgeRequest {
            tool: "t".into(),
            audience: "gw".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let refused = bm(
        dir.path(),
        &["revoke", "--key", "authority.key", "--from-token", &foreign],
    );
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).starts_with("error: "));
    let accepted = bm(
        dir.path(),
        &[
            "revoke",
            "--key",
            "authority.key",
            "--from-token",
            &foreign,
            "--authority-pub",
            "other.pub",
        ],
    );
    assert!(accepted.status.success(), "{}", stderr(&accepted));
    assert_eq!(
        stdout(&accepted).trim(),
        "revocation list revoked.list now has 2 id(s)"
    );
}

// --------------------------------------------------------------------------- //
// policy-install / revocation-migrate
// --------------------------------------------------------------------------- //

#[test]
fn policy_install_publishes_only_a_valid_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("candidate.yaml"),
        "tools:\n  - name: read_file\n    operation: read\n",
    )
    .unwrap();
    let output = bm(
        dir.path(),
        &["policy-install", "candidate.yaml", "policy.yaml"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "policy published policy.yaml");
    assert_eq!(
        std::fs::read(dir.path().join("policy.yaml")).unwrap(),
        std::fs::read(dir.path().join("candidate.yaml")).unwrap()
    );
    assert_eq!(mode(&dir.path().join("policy.yaml")), 0o600);

    std::fs::write(dir.path().join("bad.yaml"), "tools: 3\n").unwrap();
    let output = bm(dir.path(), &["policy-install", "bad.yaml", "other.yaml"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output).trim(), "error: tools: expected a list");
    assert!(!dir.path().join("other.yaml").exists());

    let output = bm(dir.path(), &["policy-install", "absent.yaml", "other.yaml"]);
    assert_eq!(
        stderr(&output).trim(),
        "error: [Errno 2] No such file or directory: 'absent.yaml'"
    );
}

#[test]
fn revocation_migration_authenticates_old_entries_and_keeps_them() {
    let dir = tempfile::tempdir().unwrap();
    let old = keyfiles(dir.path(), "old");
    let new = keyfiles(dir.path(), "new");
    let body = json!({"revoked": ["parent", "child"]});
    let signature = keys::sign(&old.private_str, &canonicalize(&body).unwrap()).unwrap();
    let legacy = json!({
        "revoked": ["parent", "child"],
        "sig": base64::engine::general_purpose::STANDARD.encode(signature),
    });
    std::fs::write(dir.path().join("legacy.list"), legacy.to_string()).unwrap();
    let args = [
        "revocation-migrate",
        "legacy.list",
        "fresh.list",
        "--old-pub",
        "old.pub",
        "--key",
        "new.key",
    ];
    let output = bm(dir.path(), &args);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "revocations migrated fresh.list");
    let migrated = strict_json(std::fs::read(dir.path().join("fresh.list")).unwrap()).unwrap();
    validate_document(&migrated, &new.public_str, None, true).unwrap();
    assert_eq!(migrated["revoked"], json!(["child", "parent"]));

    // The destination must be new…
    let again = bm(dir.path(), &args);
    assert_eq!(
        stderr(&again).trim(),
        "error: migration destination must be a new path"
    );
    let same = bm(
        dir.path(),
        &[
            "revocation-migrate",
            "legacy.list",
            "./legacy.list",
            "--old-pub",
            "old.pub",
            "--key",
            "new.key",
        ],
    );
    assert_eq!(same.status.code(), Some(1));
    // …and an entry the old key did not sign is never carried over.
    let tampered = json!({"revoked": [], "sig": legacy["sig"]});
    std::fs::write(dir.path().join("tampered.list"), tampered.to_string()).unwrap();
    let refused = bm(
        dir.path(),
        &[
            "revocation-migrate",
            "tampered.list",
            "out.list",
            "--old-pub",
            "old.pub",
            "--key",
            "new.key",
        ],
    );
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).starts_with("error: revocation migration refused: "));
    assert!(!dir.path().join("out.list").exists());
}

// --------------------------------------------------------------------------- //
// registry-add / registry-serve
// --------------------------------------------------------------------------- //

#[test]
fn registry_add_writes_a_store_and_refuses_a_key_change() {
    let dir = tempfile::tempdir().unwrap();
    let agent = keys::generate_keypair();
    let output = bm(
        dir.path(),
        &[
            "registry-add",
            "--agent-id",
            "a1",
            "--pubkey",
            &agent.public_str,
            "--store",
            "agents.json",
            "--owner-ref",
            "team",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "registered a1 -> agents.json");
    let stored = strict_json(std::fs::read(dir.path().join("agents.json")).unwrap()).unwrap();
    assert_eq!(stored["a1"]["agent_pubkey"], json!(agent.public_str));
    assert_eq!(stored["a1"]["owner_ref"], json!("team"));
    assert_eq!(stored["a1"]["status"], json!("active"));

    let other = keys::generate_keypair().public_str;
    let conflict = bm(
        dir.path(),
        &[
            "registry-add",
            "--agent-id",
            "a1",
            "--pubkey",
            &other,
            "--store",
            "agents.json",
        ],
    );
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(
        stderr(&conflict).trim(),
        "error: agent already registered with a different public key"
    );
    let invalid = bm(
        dir.path(),
        &[
            "registry-add",
            "--agent-id",
            "../x",
            "--pubkey",
            &other,
            "--store",
            "agents.json",
        ],
    );
    assert_eq!(stderr(&invalid).trim(), "error: invalid agent_id");
    let nowhere = bm(
        dir.path(),
        &["registry-add", "--agent-id", "a1", "--pubkey", &other],
    );
    assert_eq!(
        stderr(&nowhere).trim(),
        "error: provide --registry URL or --store path"
    );
    let no_token = bm(
        dir.path(),
        &[
            "registry-add",
            "--agent-id",
            "a1",
            "--pubkey",
            &other,
            "--registry",
            "http://127.0.0.1:1",
        ],
    );
    assert_eq!(
        stderr(&no_token).trim(),
        "error: --token is required to write to a registry"
    );
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn registry_serve_and_registry_add_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let signing = keyfiles(dir.path(), "registry");
    let token_file = dir.path().join("write.token");
    std::fs::write(&token_file, "  s3cret \n").unwrap();
    let secret = format!("file:{}", token_file.display());
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_tokencrumb"))
        .args([
            "registry-serve",
            "--signing-key",
            "registry.key",
            "--listen",
            &listen,
            "--store",
            "agents.json",
            "--write-token",
            &secret,
        ])
        .current_dir(dir.path())
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _server = Server(child);
    let url = format!("http://{listen}");
    let started = (0..100).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(50));
        ureq::get(&format!("{url}/healthz")).call().is_ok()
    });
    assert!(started, "registry did not start");

    let agent = keys::generate_keypair();
    let add = |pubkey: &str, token: &str| {
        bm(
            dir.path(),
            &[
                "registry-add",
                "--agent-id",
                "alice",
                "--pubkey",
                pubkey,
                "--registry",
                &url,
                "--token",
                token,
            ],
        )
    };
    let wrong = add(&agent.public_str, "literal:nope");
    assert_eq!(wrong.status.code(), Some(1));
    assert_eq!(
        stderr(&wrong).trim(),
        "error: registry rejected: 401 {\"error\":\"unauthorized\"}"
    );
    let ok = add(&agent.public_str, "s3cret");
    assert!(ok.status.success(), "{}", stderr(&ok));
    assert_eq!(stdout(&ok).trim(), format!("registered alice -> {url}"));
    let takeover = add(&keys::generate_keypair().public_str, &secret);
    assert_eq!(
        stderr(&takeover).trim(),
        "error: registry rejected: 409 {\"error\":\"key replacement requires replace_key=true\"}"
    );

    let resolve = tokencrumb_mcp_proxy::registry::registry_resolver(&url, &signing.public_str, 8).unwrap();
    assert_eq!(resolve("alice").as_deref(), Some(agent.public_str.as_str()));
}

#[test]
fn registry_serve_refuses_a_missing_secret_or_key() {
    let dir = tempfile::tempdir().unwrap();
    keyfiles(dir.path(), "registry");
    let empty = bm(
        dir.path(),
        &[
            "registry-serve",
            "--signing-key",
            "registry.key",
            "--write-token",
            "literal: ",
            "--listen",
            "127.0.0.1:0",
        ],
    );
    assert_eq!(empty.status.code(), Some(1));
    assert_eq!(
        stderr(&empty).trim(),
        "error: a registry write token is required"
    );
    let no_key = bm(
        dir.path(),
        &[
            "registry-serve",
            "--signing-key",
            "absent.key",
            "--write-token",
            "x",
            "--listen",
            "127.0.0.1:0",
        ],
    );
    assert_eq!(no_key.status.code(), Some(1));
    assert_eq!(
        stderr(&no_key).trim(),
        "error: [Errno 2] No such file or directory: 'absent.key'"
    );
}
