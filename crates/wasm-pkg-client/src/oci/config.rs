use anyhow::Context;
use base64::{
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use wasm_pkg_common::{config::RegistryConfig, Error};

#[cfg(not(feature = "wasm"))]
use oci_client::client::ClientConfig;

/// The protocol to use for OCI registry communication.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum OciProtocol {
    Http,
    #[default]
    Https,
}

/// Registry configuration for OCI backends.
///
/// See: [`RegistryConfig::backend_config`]
#[derive(Default, Serialize)]
#[serde(into = "OciRegistryConfigToml")]
pub struct OciRegistryConfig {
    /// The full oci_client ClientConfig (only available on native).
    #[cfg(not(feature = "wasm"))]
    pub client_config: ClientConfig,
    /// Protocol selection (available on all targets).
    #[serde(skip)]
    pub protocol: OciProtocol,
    pub credentials: Option<BasicCredentials>,
}

impl Clone for OciRegistryConfig {
    fn clone(&self) -> Self {
        #[cfg(not(feature = "wasm"))]
        let client_config = ClientConfig {
            protocol: self.client_config.protocol.clone(),
            extra_root_certificates: self.client_config.extra_root_certificates.clone(),
            tls_certs_only: self.client_config.tls_certs_only.clone(),
            platform_resolver: None,
            http_proxy: self.client_config.http_proxy.clone(),
            https_proxy: self.client_config.https_proxy.clone(),
            no_proxy: self.client_config.no_proxy.clone(),
            ..self.client_config
        };
        Self {
            #[cfg(not(feature = "wasm"))]
            client_config,
            protocol: self.protocol.clone(),
            credentials: self.credentials.clone(),
        }
    }
}

impl std::fmt::Debug for OciRegistryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciConfig")
            .field("protocol", &self.protocol)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl TryFrom<&RegistryConfig> for OciRegistryConfig {
    type Error = Error;

    fn try_from(registry_config: &RegistryConfig) -> Result<Self, Self::Error> {
        let OciRegistryConfigToml { auth, protocol } =
            registry_config.backend_config("oci")?.unwrap_or_default();

        let oci_protocol = match protocol.as_deref() {
            Some("http") => OciProtocol::Http,
            Some("https") | None => OciProtocol::Https,
            Some(other) => {
                return Err(Error::InvalidConfig(anyhow::anyhow!(
                    "Unknown OCI protocol {other:?}"
                )));
            }
        };

        #[cfg(not(feature = "wasm"))]
        let client_config = {
            let mut cfg = ClientConfig::default();
            if let Some(ref p) = protocol {
                cfg.protocol = oci_client_protocol(p)?;
            }
            cfg
        };

        let credentials = auth
            .map(TryInto::try_into)
            .transpose()
            .map_err(Error::InvalidConfig)?;

        Ok(Self {
            #[cfg(not(feature = "wasm"))]
            client_config,
            protocol: oci_protocol,
            credentials,
        })
    }
}

#[derive(Default, Deserialize, Serialize)]
struct OciRegistryConfigToml {
    auth: Option<TomlAuth>,
    protocol: Option<String>,
}

impl From<OciRegistryConfig> for OciRegistryConfigToml {
    fn from(value: OciRegistryConfig) -> Self {
        let protocol_str = match value.protocol {
            OciProtocol::Http => "http",
            OciProtocol::Https => "https",
        };
        OciRegistryConfigToml {
            auth: value.credentials.map(|c| TomlAuth::UsernamePassword {
                username: c.username,
                password: c.password,
            }),
            protocol: Some(protocol_str.to_string()),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
enum TomlAuth {
    #[serde(serialize_with = "serialize_secret")]
    Base64(SecretString),
    UsernamePassword {
        username: String,
        #[serde(serialize_with = "serialize_secret")]
        password: SecretString,
    },
}

#[derive(Clone, Debug)]
pub struct BasicCredentials {
    pub username: String,
    pub password: SecretString,
}

const OCI_AUTH_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

impl TryFrom<TomlAuth> for BasicCredentials {
    type Error = anyhow::Error;

    fn try_from(value: TomlAuth) -> Result<Self, Self::Error> {
        match value {
            TomlAuth::Base64(b64) => {
                fn decode_b64_creds(b64: &str) -> anyhow::Result<BasicCredentials> {
                    let bs = OCI_AUTH_BASE64.decode(b64)?;
                    let s = String::from_utf8(bs)?;
                    let (username, password) = s
                        .split_once(':')
                        .context("expected <username>:<password> but no ':' found")?;
                    Ok(BasicCredentials {
                        username: username.into(),
                        password: password.to_string().into(),
                    })
                }
                decode_b64_creds(b64.expose_secret()).context("invalid base64-encoded creds")
            }
            TomlAuth::UsernamePassword { username, password } => {
                Ok(BasicCredentials { username, password })
            }
        }
    }
}

#[cfg(not(feature = "wasm"))]
fn oci_client_protocol(text: &str) -> Result<oci_client::client::ClientProtocol, Error> {
    match text {
        "http" => Ok(oci_client::client::ClientProtocol::Http),
        "https" => Ok(oci_client::client::ClientProtocol::Https),
        _ => Err(Error::InvalidConfig(anyhow::anyhow!(
            "Unknown OCI protocol {text:?}"
        ))),
    }
}

fn serialize_secret<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    secret.expose_secret().serialize(serializer)
}

#[cfg(test)]
mod tests {
    use wasm_pkg_common::config::RegistryMapping;

    use crate::oci::OciRegistryMetadata;

    use super::*;

    #[test]
    fn smoke_test() {
        let toml_config = r#"
            [registry."example.com"]
            type = "oci"
            [registry."example.com".oci]
            auth = { username = "open", password = "sesame" }
            protocol = "http"

            [registry."wasi.dev"]
            type = "oci"
            [registry."wasi.dev".oci]
            auth = "cGluZzpwb25n"
        "#;
        let cfg = wasm_pkg_common::config::Config::from_toml(toml_config).unwrap();

        let oci_config: OciRegistryConfig = cfg
            .registry_config(&"example.com".parse().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let BasicCredentials { username, password } = oci_config.credentials.as_ref().unwrap();
        assert_eq!(username, "open");
        assert_eq!(password.expose_secret(), "sesame");
        assert_eq!(OciProtocol::Http, oci_config.protocol);

        let oci_config: OciRegistryConfig = cfg
            .registry_config(&"wasi.dev".parse().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let BasicCredentials { username, password } = oci_config.credentials.as_ref().unwrap();
        assert_eq!(username, "ping");
        assert_eq!(password.expose_secret(), "pong");
    }

    #[test]
    fn test_roundtrip() {
        let config = OciRegistryConfig {
            #[cfg(not(feature = "wasm"))]
            client_config: oci_client::client::ClientConfig {
                protocol: oci_client::client::ClientProtocol::Http,
                ..Default::default()
            },
            protocol: OciProtocol::Http,
            credentials: Some(BasicCredentials {
                username: "open".into(),
                password: SecretString::new("sesame".into()),
            }),
        };

        // Set the data and then try to load it back
        let mut conf = crate::Config::empty();

        let registry: crate::Registry = "example.com:8080".parse().unwrap();
        let reg_conf = conf.get_or_insert_registry_config_mut(&registry);
        reg_conf
            .set_backend_config("oci", &config)
            .expect("Unable to set config");

        let reg_conf = conf.registry_config(&registry).unwrap();

        let roundtripped = OciRegistryConfig::try_from(reg_conf).expect("Unable to load config");
        assert_eq!(
            roundtripped.protocol, config.protocol,
            "Protocol should be set to the right value"
        );
        let creds = config.credentials.unwrap();
        let roundtripped_creds = roundtripped.credentials.expect("Should have creds");
        assert_eq!(
            creds.username, roundtripped_creds.username,
            "Username should be set to the right value"
        );
        assert_eq!(
            creds.password.expose_secret(),
            roundtripped_creds.password.expose_secret(),
            "Password should be set to the right value"
        );
    }

    #[test]
    fn test_custom_namespace_config() {
        let toml_config = toml::toml! {
            [namespace_registries]
            test = { registry = "localhost:1234", metadata = { preferredProtocol = "oci", "oci" = { registry = "ghcr.io", namespacePrefix = "webassembly/" } } }
        };

        let cfg = wasm_pkg_common::config::Config::from_toml(&toml_config.to_string())
            .expect("Should be able to load config");

        let ns_config = cfg
            .namespace_registry(&"test".parse().unwrap())
            .expect("Should have a namespace config");
        let custom = match ns_config {
            RegistryMapping::Custom(c) => c,
            _ => panic!("Should have a custom namespace config"),
        };
        let map: OciRegistryMetadata = custom
            .metadata
            .protocol_config("oci")
            .expect("Should be able to deserialize config")
            .expect("protocol config should be present");
        assert_eq!(map.namespace_prefix, Some("webassembly/".to_string()));
        assert_eq!(map.registry, Some("ghcr.io".to_string()));
    }
}
