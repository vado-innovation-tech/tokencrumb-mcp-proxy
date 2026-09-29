//! Listening sockets: address parsing, the cleartext guard and native TLS.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;

use crate::error::{Error, Result};

/// `[host]:port` -> (host, port); an empty host means every interface (`0.0.0.0`).
pub fn parse_listen(listen: &str) -> Result<(String, u16)> {
    let (host, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| Error::value(format!("invalid listen address: {listen}")))?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::value(format!("invalid port: {port}")))?;
    Ok((host.to_owned(), port))
}

pub fn socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::value(format!("cannot resolve {host}")))
}

/// Refuse to serve a non-loopback address in the clear.
///
/// Mandates travel in an `Authorization` header: in cleartext, anyone on the path holds
/// a replayable capability. On loopback the traffic never leaves the host, so it is
/// allowed; anywhere else it takes an explicit, greppable opt-in.
pub fn guard_cleartext_bind(host: &str, tls: bool, insecure_http: bool, what: &str) -> Result<()> {
    if tls || insecure_http {
        return Ok(());
    }
    let loopback = match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        // a hostname, not an address — cannot prove it stays local
        Err(_) => host == "localhost",
    };
    if !loopback {
        return Err(Error::value(format!(
            "{what}: refusing to serve {host} in cleartext — mandates would travel \
             unprotected. Pass --tls-cert/--tls-key, bind 127.0.0.1, or accept the \
             risk explicitly with --insecure-http"
        )));
    }
    Ok(())
}

/// Validate the TLS pair. Native termination only — no ACME: renewing a certificate
/// means restarting the process.
pub fn tls_pair<'a>(
    cert: Option<&'a Path>,
    key: Option<&'a Path>,
    what: &str,
) -> Result<Option<(&'a Path, &'a Path)>> {
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            for (label, path) in [("--tls-cert", cert), ("--tls-key", key)] {
                if !path.is_file() {
                    return Err(Error::value(format!(
                        "{what}: {label} {} does not exist",
                        crate::error::py_repr(&path.display().to_string())
                    )));
                }
            }
            Ok(Some((cert, key)))
        }
        _ => Err(Error::value(format!(
            "{what}: --tls-cert and --tls-key go together"
        ))),
    }
}

/// Install the process-wide rustls provider (ring) once.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn rustls_config(
    cert: &Path,
    key: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    install_crypto_provider();
    axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|e| Error::io(format!("cannot load TLS material: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_and_guard() {
        assert_eq!(parse_listen(":9443").unwrap(), ("0.0.0.0".into(), 9443));
        assert_eq!(parse_listen("[::1]:80").unwrap(), ("::1".into(), 80));
        assert!(guard_cleartext_bind("0.0.0.0", false, false, "serve").is_err());
        assert!(guard_cleartext_bind("127.0.0.1", false, false, "serve").is_ok());
        assert!(guard_cleartext_bind("::1", false, false, "serve").is_ok());
        assert!(guard_cleartext_bind("0.0.0.0", false, true, "serve").is_ok());
    }
}
