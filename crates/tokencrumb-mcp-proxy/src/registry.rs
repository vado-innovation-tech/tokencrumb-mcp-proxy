//! TEMPORARY local stub — replaced by the ported registry at merge (never committed).
pub fn registry_resolver(
    _url: &str,
    _public: &str,
) -> crate::Result<crate::verifier::AgentKeyResolver> {
    Err(crate::Error::value("registry not merged yet"))
}
