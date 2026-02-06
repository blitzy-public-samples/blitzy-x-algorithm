/// S2S (Service-to-Service) certificate paths — internal configuration,
/// excluded from open source release for security reasons.

use once_cell::sync::Lazy;

/// Path to the S2S certificate chain file.
pub static S2S_CHAIN_PATH: Lazy<String> =
    Lazy::new(|| std::env::var("S2S_CHAIN_PATH").unwrap_or_else(|_| "/certs/chain.pem".to_string()));

/// Path to the S2S client certificate file.
pub static S2S_CRT_PATH: Lazy<String> =
    Lazy::new(|| std::env::var("S2S_CRT_PATH").unwrap_or_else(|_| "/certs/client.pem".to_string()));

/// Path to the S2S private key file.
pub static S2S_KEY_PATH: Lazy<String> =
    Lazy::new(|| std::env::var("S2S_KEY_PATH").unwrap_or_else(|_| "/certs/key.pem".to_string()));
