//! Verify a fixture freshly emitted by the Java unit or live Keycloak integration test
//! (`keycloak-biscuit`, see its README) against this verifier.
//!
//!     cargo run -p tokencrumb --example check_java_interop -- <fixture.json>
//!
//! The mandate must be allowed for its granted tool, refused out of scope, and refused
//! once its budget is spent — with the issuer and subject it carries recorded.

use std::process::ExitCode;

use tokencrumb_mcp_proxy::attestation::build_attestation;
use tokencrumb_mcp_proxy::json::strict_json;
use tokencrumb_mcp_proxy::policy::parse_policy;
use tokencrumb_mcp_proxy::verifier::{Decision, Headers, Verifier, VerifierOptions};
use serde_json::{Value, json};

fn check(path: &str) -> Result<(), String> {
    let fixture =
        strict_json(std::fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let text = |name: &str| {
        fixture[name]
            .as_str()
            .map(str::to_owned)
            .ok_or(format!("fixture lacks {name}"))
    };
    let now = chrono::DateTime::parse_from_rfc3339(&text("now")?)
        .map_err(|e| e.to_string())?
        .with_timezone(&chrono::Utc);
    let policy = parse_policy(&json!({"tools": [
        {"name": "read_file", "operation": "read"},
        {"name": "write_file", "operation": "write"},
    ]}))
    .map_err(|e| e.to_string())?;
    let mut options = VerifierOptions::new("biscuitmcp://interop");
    options.now_fn = Some(Box::new(move || now));
    let verifier =
        Verifier::new(&text("authority_pub")?, policy, options).map_err(|e| e.to_string())?;
    let token = text("token")?;
    let call = |tool: &str| -> Result<Decision, String> {
        let mut headers = vec![("authorization".to_owned(), format!("Biscuit {token}"))];
        if let Some(private) = fixture.get("agent_private").and_then(Value::as_str) {
            let attestation = build_attestation(
                "interop-agent",
                tool,
                &json!({}),
                &token,
                private,
                Some(now),
            )
            .map_err(|e| e.to_string())?;
            headers.push(("agent-attestation".into(), attestation));
        }
        verifier
            .verify_call(tool, &json!({}), &Headers::new(headers), None, None)
            .map_err(|e| e.to_string())
    };
    if call("write_file")?.allow {
        return Err("write_file must be refused: the mandate does not grant it".into());
    }
    let first = call("read_file")?;
    if !(first.allow && first.subject.is_some() && first.issuer.is_some()) {
        return Err(format!(
            "read_file must be allowed with issuer and subject: {}",
            first.reason
        ));
    }
    if !call("read_file")?.allow {
        return Err("the second read_file is within budget".into());
    }
    if call("read_file")?.allow {
        return Err("the third read_file exceeds the budget".into());
    }
    println!("{path}: issuer → Rust ALLOW, scope DENY, exhausted budget DENY");
    Ok(())
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: check_java_interop <fixture.json>");
        return ExitCode::from(2);
    };
    match check(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
