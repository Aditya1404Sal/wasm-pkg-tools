//! Default [`HttpClient`] implementation backed by `reqwest`.
//!
//! Compiled only when the `native` feature is active.

use async_trait::async_trait;
use wasm_pkg_common::Error;

use crate::http_client::HttpClient;

pub struct DefaultHttpClient;

#[async_trait]
impl HttpClient for DefaultHttpClient {
    async fn get_json_bytes(&self, url: &str) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!(?url, "Fetching URL");
        let resp = reqwest::get(url)
            .await
            .map_err(|e| Error::RegistryMetadataError(e.into()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp
            .error_for_status()
            .map_err(|e| Error::RegistryMetadataError(e.into()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::RegistryMetadataError(e.into()))?;
        Ok(Some(bytes.to_vec()))
    }
}
