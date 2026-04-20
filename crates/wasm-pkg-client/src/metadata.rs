use anyhow::Context;
use wasm_pkg_common::{
    metadata::{RegistryMetadata, REGISTRY_METADATA_PATH},
    registry::Registry,
    Error,
};

use crate::http_client::HttpClient;

/// Extension trait for [`RegistryMetadata`] adding client functionality.
pub trait RegistryMetadataExt: Sized {
    /// Attempt to fetch [`RegistryMetadata`] from the given [`Registry`]. On
    /// failure, return defaults.
    fn fetch_or_default(
        registry: &Registry,
        http: &dyn HttpClient,
    ) -> impl std::future::Future<Output = Self> + Send;

    /// Fetch [`RegistryMetadata`] from the given [`Registry`].
    fn fetch(
        registry: &Registry,
        http: &dyn HttpClient,
    ) -> impl std::future::Future<Output = Result<Option<Self>, Error>> + Send;
}

impl RegistryMetadataExt for RegistryMetadata {
    async fn fetch_or_default(registry: &Registry, http: &dyn HttpClient) -> Self {
        match Self::fetch(registry, http).await {
            Ok(Some(meta)) => {
                tracing::debug!(?meta, "Got registry metadata");
                meta
            }
            Ok(None) => {
                tracing::debug!("Metadata not found");
                Default::default()
            }
            Err(err) => {
                tracing::warn!(error = ?err, "Error fetching registry metadata");
                Default::default()
            }
        }
    }

    async fn fetch(registry: &Registry, http: &dyn HttpClient) -> Result<Option<Self>, Error> {
        let scheme = if registry.host() == "localhost" {
            "http"
        } else {
            "https"
        };
        let url = format!("{scheme}://{registry}{REGISTRY_METADATA_PATH}");
        tracing::debug!(?url, "Fetching registry metadata");

        let bytes = http
            .get_json_bytes(&url)
            .await
            .with_context(|| format!("error fetching registry metadata from {url:?}"))
            .map_err(Error::RegistryMetadataError)?;

        match bytes {
            None => Ok(None),
            Some(b) => {
                let meta = serde_json::from_slice(&b)
                    .with_context(|| format!("error parsing registry metadata from {url:?}"))
                    .map_err(Error::RegistryMetadataError)?;
                Ok(Some(meta))
            }
        }
    }
}
