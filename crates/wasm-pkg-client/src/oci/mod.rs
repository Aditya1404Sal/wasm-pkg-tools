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

use crate::http_client::HttpClient;

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

    /// Discover all packages in `namespace` by querying the registry catalog.
    ///
    /// For `ghcr.io`, the OCI `_catalog` endpoint is disabled; we fall back to
    /// the GitHub Packages REST API (`GET /orgs/{org}/packages?package_type=container`).
    /// Supply `github_token` (a PAT with `read:packages`) to authenticate that call.
    ///
    /// For other registries the standard `GET /v2/_catalog` is used.
    pub(crate) async fn list_packages_in_namespace(
        &self,
        namespace: &str,
        github_token: Option<&str>,
        http_client: &dyn HttpClient,
    ) -> Result<Vec<PackageRef>, Error> {
        if self.oci_registry.trim_end_matches('/') == "ghcr.io" {
            self.list_packages_github(namespace, github_token, http_client)
                .await
        } else {
            self.list_packages_catalog(namespace).await
        }
    }

    /// List packages via the GitHub Packages REST API (ghcr.io only).
    async fn list_packages_github(
        &self,
        namespace: &str,
        github_token: Option<&str>,
        http_client: &dyn HttpClient,
    ) -> Result<Vec<PackageRef>, Error> {
        // The OCI repository prefix for this namespace, e.g. "webassembly/wasco-dev/"
        // or just "wasco-dev/" if there's no namespace_prefix.
        let repo_prefix = format!(
            "{}{}/",
            self.namespace_prefix.as_deref().unwrap_or_default(),
            namespace
        );

        // The "owner" on ghcr.io is the first path component of the prefix, or
        // falls back to the namespace name itself.
        // e.g. namespace_prefix="webassembly/" → org="webassembly"
        //      namespace_prefix=None            → org=namespace
        let org = self
            .namespace_prefix
            .as_deref()
            .and_then(|p| p.trim_end_matches('/').split('/').next())
            .unwrap_or(namespace);

        let mut packages = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "https://api.github.com/orgs/{org}/packages?package_type=container&per_page=100&page={page}"
            );

            let body = http_client
                .get_json_bytes_authed(&url, github_token)
                .await
                .map_err(|e| Error::RegistryError(e.into()))?;

            let body = match body {
                None => break, // 404 → no packages
                Some(b) => b,
            };

            #[derive(Deserialize)]
            struct GhPackage {
                name: String,
            }

            let page_pkgs: Vec<GhPackage> =
                serde_json::from_slice(&body).map_err(|e| Error::RegistryError(e.into()))?;

            if page_pkgs.is_empty() {
                break;
            }

            for pkg in &page_pkgs {
                // pkg.name is the full repo path, e.g. "webassembly/wasco-dev/my-pkg"
                // Strip the prefix to get just the package name.
                if let Some(pkg_name) = pkg.name.strip_prefix(&repo_prefix) {
                    // Skip names that contain a further '/' (nested sub-repos).
                    if !pkg_name.contains('/') {
                        let pkg_ref_str = format!("{namespace}:{pkg_name}");
                        match pkg_ref_str.parse::<PackageRef>() {
                            Ok(r) => packages.push(r),
                            Err(e) => {
                                tracing::debug!("Skipping invalid package ref {pkg_ref_str}: {e}")
                            }
                        }
                    }
                }
            }

            if page_pkgs.len() < 100 {
                break;
            }
            page += 1;
        }

        Ok(packages)
    }

    /// List packages via the OCI `_catalog` endpoint (non-ghcr.io registries).
    async fn list_packages_catalog(&self, namespace: &str) -> Result<Vec<PackageRef>, Error> {
        // The repository prefix to filter on, e.g. "wasco-dev/" or "webassembly/wasco-dev/"
        let repo_prefix = format!(
            "{}{}/",
            self.namespace_prefix.as_deref().unwrap_or_default(),
            namespace
        );

        // Auth against the catalog endpoint (uses a minimal reference — _catalog
        // is registry-wide, not repo-scoped).
        let probe_ref = OciReference::new(self.oci_registry.clone(), String::new(), String::new());
        let auth = self.auth(&probe_ref, OciOperation::Pull).await?;

        let mut packages = Vec::new();
        let mut last: Option<String> = None;

        loop {
            let page = self
                .transport
                .list_catalog(&self.oci_registry, &auth, Some(100), last.as_deref())
                .await?;

            for repo in &page.repositories {
                if let Some(pkg_name) = repo.strip_prefix(&repo_prefix) {
                    if !pkg_name.contains('/') {
                        let pkg_ref_str = format!("{namespace}:{pkg_name}");
                        match pkg_ref_str.parse::<PackageRef>() {
                            Ok(r) => packages.push(r),
                            Err(e) => {
                                tracing::debug!("Skipping invalid package ref {pkg_ref_str}: {e}")
                            }
                        }
                    }
                }
            }

            last = page.next_last;
            if last.is_none() {
                break;
            }
        }

        Ok(packages)
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
