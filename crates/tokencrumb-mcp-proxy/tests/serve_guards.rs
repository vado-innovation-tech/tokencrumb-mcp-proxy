//! Startup guards on the listening socket (ROADMAP v0.2.0).
//!
//! Ported from `tests/test_serve_guards.py`. A mandate travels in an `Authorization`
//! header. Served in the clear on a routable address, anyone on the path holds a
//! replayable capability — so that combination has to be an explicit, greppable
//! choice rather than the default. The former tests called the CLI helpers and caught
//! `typer.Exit`; here the same helpers live in `net` and return errors, and the CLI
//! itself is exercised for the exit code and message.

mod common;

use std::path::Path;

use common::{bm, stderr};
use tokencrumb_mcp_proxy::net::{guard_cleartext_bind, tls_pair};

#[test]
fn loopback_in_the_clear_is_allowed() {
    for host in ["127.0.0.1", "::1", "localhost"] {
        guard_cleartext_bind(host, false, false, "serve").unwrap();
    }
}

#[test]
fn a_routable_address_in_the_clear_is_refused() {
    for host in ["0.0.0.0", "10.0.0.4", "::"] {
        assert!(
            guard_cleartext_bind(host, false, false, "serve").is_err(),
            "{host}"
        );
    }
}

/// Unresolvable at startup, so it cannot be proven to stay on the host.
#[test]
fn a_hostname_that_is_not_localhost_is_refused() {
    assert!(guard_cleartext_bind("gw.example.org", false, false, "serve").is_err());
}

#[test]
fn tls_or_the_explicit_opt_in_lifts_the_guard() {
    guard_cleartext_bind("0.0.0.0", true, false, "serve").unwrap();
    guard_cleartext_bind("0.0.0.0", false, true, "serve").unwrap();
}

#[test]
fn no_tls_material_means_no_tls() {
    assert!(tls_pair(None, None, "serve").unwrap().is_none());
}

#[test]
fn half_a_tls_pair_or_a_missing_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    std::fs::write(&cert, "x").unwrap();
    assert!(tls_pair(Some(&cert), None, "serve").is_err());
    assert!(tls_pair(None, Some(&cert), "serve").is_err());
    let absent = dir.path().join("absent.pem");
    let error = tls_pair(Some(&cert), Some(&absent), "serve").unwrap_err();
    assert!(error.message.contains("--tls-key") && error.message.contains("does not exist"));
}

#[test]
fn a_complete_pair_is_passed_to_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert, "x").unwrap();
    std::fs::write(&key, "y").unwrap();
    let pair = tls_pair(Some(&cert), Some(&key), "serve").unwrap().unwrap();
    assert_eq!(pair, (cert.as_path(), key.as_path()));
}

fn refused(dir: &Path, args: &[&str]) -> String {
    let output = bm(dir, args);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    stderr(&output).trim().to_owned()
}

#[test]
fn cli_serve_and_registry_serve_refuse_before_loading_anything() {
    let dir = tempfile::tempdir().unwrap();
    let serve = [
        "serve",
        "--authority-pub",
        "a.pub",
        "--policy",
        "p.yaml",
        "--audience",
        "gw",
    ];
    let mut args = serve.to_vec();
    args.extend(["--listen", "0.0.0.0:9999"]);
    assert_eq!(
        refused(dir.path(), &args),
        "error: serve: refusing to serve 0.0.0.0 in cleartext — mandates would travel \
         unprotected. Pass --tls-cert/--tls-key, bind 127.0.0.1, or accept the risk \
         explicitly with --insecure-http"
    );
    // The default listen address (`:9443`, every interface) is not loopback either.
    assert!(refused(dir.path(), &serve).contains("refusing to serve 0.0.0.0 in cleartext"));

    std::fs::write(dir.path().join("cert.pem"), "x").unwrap();
    let mut args = serve.to_vec();
    args.extend(["--tls-cert", "cert.pem"]);
    assert_eq!(
        refused(dir.path(), &args),
        "error: serve: --tls-cert and --tls-key go together"
    );
    let mut args = serve.to_vec();
    args.extend(["--tls-cert", "cert.pem", "--tls-key", "absent.pem"]);
    assert_eq!(
        refused(dir.path(), &args),
        "error: serve: --tls-key 'absent.pem' does not exist"
    );

    let registry = [
        "registry-serve",
        "--signing-key",
        "k.key",
        "--write-token",
        "x",
        "--listen",
        "10.0.0.4:8081",
    ];
    assert!(
        refused(dir.path(), &registry)
            .starts_with("error: registry-serve: refusing to serve 10.0.0.4 in cleartext")
    );
}

/// Past the guards, a configuration the runtime refuses is reported as such.
#[test]
fn cli_serve_reports_a_refused_start() {
    let dir = tempfile::tempdir().unwrap();
    let message = refused(
        dir.path(),
        &[
            "serve",
            "--authority-pub",
            "absent.pub",
            "--policy",
            "absent.yaml",
            "--audience",
            "gw",
            "--listen",
            "127.0.0.1:0",
        ],
    );
    assert!(
        message.starts_with("error: cannot start proxy: "),
        "{message}"
    );
}
