//! TLS helpers built on rustls with the `ring` provider and bundled Mozilla roots.

use std::sync::{Arc, OnceLock};

use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};

use crate::error::{Error, Result};

/// A shareable client configuration: TLS 1.2+, certificate verification
/// against the bundled Mozilla root store, no ALPN.
///
/// Pass it as `CheckOptions::tls` to add a target TLS handshake to a TCP
/// check. For private CAs build your own [`ClientConfig`], e.g. with
/// [`client_config_with_roots`].
pub fn default_client_config() -> Arc<ClientConfig> {
    static DEFAULT: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            client_config_with_roots(roots)
        })
        .clone()
}

/// Client configuration verifying against `roots` (TLS 1.2+, `ring` provider).
pub fn client_config_with_roots(roots: RootCertStore) -> Arc<ClientConfig> {
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Copy of `config` that offers exactly `alpn`.
pub(crate) fn with_alpn(config: &Arc<ClientConfig>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let wanted: Vec<Vec<u8>> = alpn.iter().map(|p| p.to_vec()).collect();
    if config.alpn_protocols == wanted {
        return config.clone();
    }
    let mut c = (**config).clone();
    c.alpn_protocols = wanted;
    Arc::new(c)
}

pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|_| Error::invalid("TLS server name"))
}
