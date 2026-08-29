//! Transport-security policy shared by every HTTP client in this crate.
//!
//! Both clients authenticate with a bearer-style API key sent on every request.
//! Two things follow, and neither was previously enforced:
//!
//! 1. **The key must not travel in cleartext.** `Url::parse` accepts any scheme,
//!    so a mistyped or copy-pasted `http://` production endpoint would ship the
//!    credential unencrypted, and `ftp://` or `file://` would be accepted
//!    outright. Only `https` is allowed, with a carve-out for `http` to a
//!    loopback address — the documented local development setup
//!    (`http://localhost:8080`) is not exposed to a network attacker.
//!
//! 2. **The key must not reach logs.** `reqwest` will render a `HeaderValue` in
//!    `Debug` output unless it is marked sensitive, which puts the credential
//!    into any tracing or error dump that formats the client or its headers.

use std::net::IpAddr;

use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Hosts for which cleartext `http` is permitted.
///
/// Matching on string prefixes is not safe here: `127.0.0.1.evil.com` starts
/// with `127.` and `localhost.evil.com` starts with `localhost`, but both are
/// ordinary attacker-controlled domains. IP literals are therefore parsed and
/// tested with [`IpAddr::is_loopback`], and the only domain accepted is exactly
/// `localhost`.
fn is_loopback_host(host: &str) -> bool {
    // `Url::host_str` keeps the brackets around an IPv6 literal.
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    match unbracketed.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

/// Validate a client base URL and return it normalized (no trailing slash).
///
/// Rejects empty input, unparseable URLs, non-HTTP(S) schemes, and cleartext
/// `http` to any non-loopback host.
pub(crate) fn validate_base_url(base_url: &str) -> Result<String, ClientError> {
    let base_url = base_url.trim();
    if base_url.is_empty() {
        return Err(ClientError::InvalidBaseUrl(
            "base_url must not be empty".to_string(),
        ));
    }

    let parsed =
        reqwest::Url::parse(base_url).map_err(|e| ClientError::InvalidBaseUrl(e.to_string()))?;

    match parsed.scheme() {
        "https" => {}
        "http" => {
            let host = parsed.host_str().unwrap_or_default();
            if !is_loopback_host(host) {
                return Err(ClientError::InvalidBaseUrl(format!(
                    "refusing to send an API key in cleartext: base_url uses http:// with \
                     non-loopback host `{host}`. Use https://, or http:// on localhost for \
                     local development."
                )));
            }
        }
        other => {
            return Err(ClientError::InvalidBaseUrl(format!(
                "unsupported scheme `{other}`: base_url must be https:// \
                 (or http:// on localhost)"
            )));
        }
    }

    Ok(base_url.trim_end_matches('/').to_string())
}

/// Build an `Authorization` header value that will not be printed by `Debug`.
///
/// `value` is consumed as a [`Zeroizing`] string so the formatted credential is
/// wiped once the header has been constructed.
pub(crate) fn sensitive_auth_header(value: &Zeroizing<String>) -> Result<HeaderValue, ClientError> {
    let mut header =
        HeaderValue::from_str(value).map_err(|e| ClientError::InvalidHeader(e.to_string()))?;
    // Keeps the credential out of `Debug` output, and out of any tracing or
    // error dump that formats the client.
    header.set_sensitive(true);
    Ok(header)
}

/// Reject an empty API key before it is placed in a header.
pub(crate) fn validate_api_key(api_key: &str) -> Result<&str, ClientError> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err(ClientError::InvalidHeader(
            "api_key must not be empty".to_string(),
        ));
    }
    Ok(api_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_accepted_and_normalized() {
        assert_eq!(
            validate_base_url("https://sequencer.example.com/").unwrap(),
            "https://sequencer.example.com"
        );
    }

    /// The documented local development endpoint must keep working.
    #[test]
    fn http_to_loopback_is_accepted() {
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.0.0.2:9090",
            "http://[::1]:8080",
        ] {
            assert!(
                validate_base_url(url).is_ok(),
                "loopback dev endpoint `{url}` must be accepted"
            );
        }
    }

    /// The finding this module exists for: an API key must never be sent in
    /// cleartext to a host someone else can observe.
    #[test]
    fn http_to_remote_host_is_rejected() {
        let err = validate_base_url("http://sequencer.example.com").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cleartext"),
            "error should explain the credential risk, got: {msg}"
        );
    }

    /// A hostname merely *containing* a loopback-ish substring is not loopback.
    #[test]
    fn lookalike_hosts_are_not_treated_as_loopback() {
        for url in [
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            "http://notlocalhost",
        ] {
            assert!(
                validate_base_url(url).is_err(),
                "`{url}` must not be accepted as loopback"
            );
        }
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        for url in ["ftp://host/x", "file:///etc/passwd", "ws://host"] {
            let err = validate_base_url(url).unwrap_err();
            assert!(
                err.to_string().contains("unsupported scheme"),
                "`{url}` must be rejected by scheme"
            );
        }
    }

    #[test]
    fn empty_and_unparseable_urls_are_rejected() {
        assert!(validate_base_url("").is_err());
        assert!(validate_base_url("   ").is_err());
        assert!(validate_base_url("not a url").is_err());
    }

    #[test]
    fn empty_api_key_is_rejected() {
        assert!(validate_api_key("").is_err());
        assert!(validate_api_key("   ").is_err());
        assert_eq!(validate_api_key("  ss_key  ").unwrap(), "ss_key");
    }

    /// The credential must not be recoverable from `Debug` output.
    #[test]
    fn auth_header_is_marked_sensitive_and_redacted_in_debug() {
        let key = Zeroizing::new("ApiKey ss_super_secret_value".to_string());
        let header = sensitive_auth_header(&key).unwrap();
        assert!(header.is_sensitive());
        let rendered = format!("{header:?}");
        assert!(
            !rendered.contains("ss_super_secret_value"),
            "Debug output leaked the API key: {rendered}"
        );
    }
}
