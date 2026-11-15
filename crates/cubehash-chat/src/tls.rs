use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as rustls_ring, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Relay TLS configuration used to serve `wss://` (or explicit `ws://` for local non-TLS tests).
#[derive(Clone, Debug)]
pub enum RelayTlsConfig {
    /// Generates an ephemeral ECDSA X.509 certificate for `san_hosts` via `rcgen` and serves TLS (`wss://`).
    SelfSigned { san_hosts: Vec<String> },
    /// Loads X.509 certificate chain and PKCS8/RSA/EC private key from PEM files on disk.
    PemFiles {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
    /// Explicitly disables TLS (`ws://`). Intended ONLY for local automated diagnostics.
    InsecureDisabled,
}

impl RelayTlsConfig {
    pub fn from_pem_paths(cert_path: &Path, key_path: &Path) -> Result<Self, String> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| format!("failed to read TLS cert {}: {e}", cert_path.display()))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| format!("failed to read TLS key {}: {e}", key_path.display()))?;
        Ok(Self::PemFiles { cert_pem, key_pem })
    }
}

/// Prepared server TLS material plus leaf certificate SHA-256 fingerprint.
#[derive(Clone)]
pub struct BuiltRelayTls {
    pub acceptor: Option<tokio_rustls::TlsAcceptor>,
    pub cert_sha256: Option<[u8; 32]>,
    pub cert_pem: Option<String>,
}

impl BuiltRelayTls {
    pub fn build(cfg: RelayTlsConfig) -> Result<Self, String> {
        match cfg {
            RelayTlsConfig::InsecureDisabled => Ok(Self {
                acceptor: None,
                cert_sha256: None,
                cert_pem: None,
            }),
            RelayTlsConfig::SelfSigned { mut san_hosts } => {
                if san_hosts.is_empty() {
                    san_hosts.push("localhost".to_string());
                    san_hosts.push("127.0.0.1".to_string());
                }
                let certified = generate_simple_self_signed(san_hosts)
                    .map_err(|e| format!("failed to generate self-signed TLS cert: {e}"))?;
                let cert_pem = certified.cert.pem();
                let cert_der = CertificateDer::from(certified.cert.der().to_vec());
                let cert_sha256: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
                let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
                    .map_err(|e| format!("invalid generated TLS key: {e}"))?;

                let server_cfg = ServerConfig::builder_with_provider(Arc::new(
                    rustls_ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .map_err(|e| format!("failed to configure rustls server: {e}"))?;

                Ok(Self {
                    acceptor: Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))),
                    cert_sha256: Some(cert_sha256),
                    cert_pem: Some(cert_pem),
                })
            }
            RelayTlsConfig::PemFiles { cert_pem, key_pem } => {
                let mut cert_reader = Cursor::new(&cert_pem);
                let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("failed to parse TLS cert PEM: {e}"))?;
                if certs.is_empty() {
                    return Err("TLS cert PEM contains no certificates".to_string());
                }
                let cert_sha256: [u8; 32] = Sha256::digest(certs[0].as_ref()).into();

                let mut key_reader = Cursor::new(&key_pem);
                let key_der = rustls_pemfile::private_key(&mut key_reader)
                    .map_err(|e| format!("failed to parse TLS private key PEM: {e}"))?
                    .ok_or_else(|| "TLS key PEM contains no private key".to_string())?;

                let server_cfg = ServerConfig::builder_with_provider(Arc::new(
                    rustls_ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_no_client_auth()
                .with_single_cert(certs, key_der)
                .map_err(|e| format!("failed to build rustls ServerConfig: {e}"))?;

                Ok(Self {
                    acceptor: Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))),
                    cert_sha256: Some(cert_sha256),
                    cert_pem: Some(String::from_utf8_lossy(&cert_pem).to_string()),
                })
            }
        }
    }
}

/// Client TLS trust policy when dialing `wss://` relays.
#[derive(Clone, Debug, Default)]
pub enum ClientTlsConfig {
    /// Verifies server certs against Mozilla WebPKI root CAs.
    #[default]
    WebPkiRoots,
    /// Verifies server certs against explicit PEM CA certificates.
    CaPem(Vec<u8>),
    /// Pins exact SHA-256 digest of the relay's leaf DER certificate AND verifies TLS signatures.
    PinnedCertSha256([u8; 32]),
}

impl ClientTlsConfig {
    pub fn build_connector(&self) -> Result<tokio_rustls::TlsConnector, String> {
        let provider = Arc::new(rustls_ring::default_provider());
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?;

        let cfg = match self {
            ClientTlsConfig::WebPkiRoots => {
                let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            ClientTlsConfig::CaPem(pem) => {
                let mut reader = Cursor::new(pem);
                let certs = rustls_pemfile::certs(&mut reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("invalid CA PEM: {e}"))?;
                let mut roots = RootCertStore::empty();
                for c in certs {
                    roots.add(c).map_err(|e| format!("failed adding CA cert: {e}"))?;
                }
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            ClientTlsConfig::PinnedCertSha256(expected_sha256) => {
                let verifier = Arc::new(PinnedCertVerifier {
                    expected_sha256: *expected_sha256,
                    supported_algs: provider.signature_verification_algorithms,
                });
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
        };

        Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
    }
}

#[derive(Debug)]
struct PinnedCertVerifier {
    expected_sha256: [u8; 32],
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if bool::from(actual.ct_eq(&self.expected_sha256)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Parsed relay WebSocket URL (`wss://host:port/path` or `ws://host:port/path`).
pub struct ParsedWsEndpoint {
    pub is_tls: bool,
    pub tcp_addr: String,
    pub server_name: ServerName<'static>,
    pub full_url: String,
}

pub fn parse_ws_url(url: &str) -> Result<ParsedWsEndpoint, String> {
    let trimmed = url.trim();
    let (is_tls, rest, default_port) = if let Some(r) = trimmed.strip_prefix("wss://") {
        (true, r, 443u16)
    } else if let Some(r) = trimmed.strip_prefix("ws://") {
        (false, r, 80u16)
    } else {
        return Err("relay URL must begin with wss:// or ws://".to_string());
    };

    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err("relay URL missing host".to_string());
    }

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| "invalid IPv6 host in URL".to_string())?;
        let ip_part = &stripped[..end];
        let after = &stripped[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| "invalid port in URL")?
        } else {
            default_port
        };
        (ip_part.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|_| "invalid port in URL")?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default_port)
    };

    let tcp_addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let server_name = ServerName::try_from(host)
        .map_err(|_| "invalid TLS server name in URL".to_string())?
        .to_owned();

    Ok(ParsedWsEndpoint {
        is_tls,
        tcp_addr,
        server_name,
        full_url: trimmed.to_string(),
    })
}

/// Parses a SHA-256 hex certificate pin (colons/spaces optional).
pub fn parse_sha256_pin_hex(input: &str) -> Result<[u8; 32], String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' '))
        .collect();
    let bytes = hex::decode(&cleaned).map_err(|e| format!("invalid hex TLS pin: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| "TLS pin must be a 32-byte (64 hex chars) SHA-256 digest".to_string())
}
