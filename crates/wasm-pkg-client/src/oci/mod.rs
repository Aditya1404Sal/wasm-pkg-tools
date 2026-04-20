//! OCI package client.
//!
//! This follows the CNCF TAG Runtime guidance for [Wasm OCI Artifacts][1].
//!
//! [1]: https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/

mod config;
mod loader;
#[cfg(not(feature = "wasm"))]
mod publisher;
pub mod transport;

#[cfg(not(feature = "wasm"))]
mod transport_default;
#[cfg(feature = "wasm")]
mod transport_wasm;

#[cfg(not(feature = "wasm"))]
use docker_credential::{CredentialRetrievalError, DockerCredential};

#[cfg(not(feature = "wasm"))]
use oci_client::errors::OciDistributionError;
use secrecy::ExposeSecret;
use serde::Deserialize;
use wasm_pkg_common::{
    config::RegistryConfig,
    metadata::RegistryMetadata,
    package::{PackageRef, Version},
    registry::Registry,
    Error,
};

pub use config::{BasicCredentials, OciProtocol, OciRegistryConfig};
pub use transport::{OciCredentials, OciOperation, OciReference, OciTransport};

#[cfg(not(feature = "wasm"))]
pub use transport_default::DefaultOciTransport;
#[cfg(feature = "wasm")]
pub use transport_wasm::WasmOciTransport;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciRegistryMetadata {
    registry: Option<String>,
    namespace_prefix: Option<String>,
}

pub(crate) struct OciBackend {
    transport: Box<dyn OciTransport>,
    oci_registry: String,
    namespace_prefix: Option<String>,
    credentials: OciCredentials,
}

impl OciBackend {
    pub fn new(
        registry: &Registry,
        registry_config: &RegistryConfig,
        registry_meta: &RegistryMetadata,
    ) -> Result<Self, Error> {
        let oci_config: OciRegistryConfig = registry_config.try_into()?;
        let credentials = oci_config.credentials.clone();

        #[cfg(not(feature = "wasm"))]
        let transport: Box<dyn OciTransport> =
            Box::new(DefaultOciTransport::new(oci_config.client_config));

        #[cfg(feature = "wasm")]
        let transport: Box<dyn OciTransport> = Box::new(WasmOciTransport::new(oci_config.protocol));

        let oci_meta = registry_meta
            .protocol_config::<OciRegistryMetadata>("oci")?
            .unwrap_or_default();
        let oci_registry = oci_meta.registry.unwrap_or_else(|| registry.to_string());

        // Convert BasicCredentials to OciCredentials
        let oci_credentials = match &credentials {
            Some(BasicCredentials { username, password }) => {
                OciCredentials::Basic(username.clone(), password.expose_secret().clone())
            }
            None => Self::get_docker_credentials(&oci_registry),
        };

        Ok(Self {
            transport,
            oci_registry,
            namespace_prefix: oci_meta.namespace_prefix,
            credentials: oci_credentials,
        })
    }

    pub(crate) async fn auth(
        &self,
        reference: &OciReference,
        operation: OciOperation,
    ) -> Result<OciCredentials, Error> {
        // Always delegate to the transport so it can handle per-repository
        // token caching (e.g. GHCR issues repo-scoped bearer tokens).
        self.transport
            .auth(reference, &self.credentials, operation)
            .await
    }

    /// Look up docker credentials from the credential store.
    #[cfg(not(feature = "wasm"))]
    fn get_docker_credentials(oci_registry: &str) -> OciCredentials {
        match get_docker_credential(oci_registry) {
            Ok(Some(c)) => c,
            Ok(None) => {
                tracing::debug!("Failed to look up OCI credentials by registry, trying server URL");
                let server_url = format!("https://{}", oci_registry);
                match get_docker_credential(&server_url) {
                    Ok(Some(c)) => c,
                    Ok(None) | Err(_) => OciCredentials::Anonymous,
                }
            }
            Err(_) => OciCredentials::Anonymous,
        }
    }

    /// Docker credential store is not available in wasm.
    #[cfg(feature = "wasm")]
    fn get_docker_credentials(_oci_registry: &str) -> OciCredentials {
        OciCredentials::Anonymous
    }

    pub(crate) fn make_reference(
        &self,
        package: &PackageRef,
        version: Option<&Version>,
    ) -> OciReference {
        let repository = format!(
            "{}{}/{}",
            self.namespace_prefix.as_deref().unwrap_or_default(),
            package.namespace(),
            package.name()
        );
        let tag = version
            .map(|ver| ver.to_string())
            .unwrap_or_else(|| "latest".into());
        OciReference::new(self.oci_registry.clone(), repository, tag)
    }
}

#[cfg(not(feature = "wasm"))]
pub(crate) fn oci_registry_error(err: OciDistributionError) -> Error {
    match err {
        OciDistributionError::ImageManifestNotFoundError(_) => Error::PackageNotFound,
        _ => Error::RegistryError(err.into()),
    }
}

#[cfg(not(feature = "wasm"))]
fn get_docker_credential(registry: &str) -> Result<Option<OciCredentials>, Error> {
    match docker_credential::get_credential(registry) {
        Ok(DockerCredential::UsernamePassword(username, password)) => {
            return Ok(Some(OciCredentials::Basic(username, password)));
        }
        Ok(DockerCredential::IdentityToken(_)) => {
            return Err(Error::CredentialError(anyhow::anyhow!(
                "identity tokens not supported"
            )));
        }
        Err(err) => {
            if matches!(
                err,
                CredentialRetrievalError::ConfigNotFound
                    | CredentialRetrievalError::ConfigReadError
                    | CredentialRetrievalError::NoCredentialConfigured
                    | CredentialRetrievalError::HelperFailure { .. }
            ) {
                tracing::debug!("Failed to look up OCI credentials: {err}");
            } else {
                tracing::warn!("Failed to look up OCI credentials: {err}");
            };
        }
    }

    Ok(None)
}
