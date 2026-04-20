//! [`HttpClient`] implementation backed by `wstd::http::Client` for use in
//! WebAssembly component targets.
//!
//! Compiled only when the `wasm` feature is active.

use async_trait::async_trait;
use wasm_pkg_common::Error;
use wstd::http as wstd_http;

use crate::http_client::HttpClient;

pub struct WasmHttpClient {
    client: wstd_http::Client,
}

impl WasmHttpClient {
    pub fn new() -> Self {
        Self {
            client: wstd_http::Client::new(),
        }
    }
}

#[async_trait]
impl HttpClient for WasmHttpClient {
    async fn get_json_bytes(&self, url: &str) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!(?url, "Fetching URL via wstd");

        let req = wstd_http::Request::builder()
            .method(wstd_http::Method::GET)
            .uri(url)
            .header("Accept", "application/json")
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryMetadataError(e.into()))?;

        let mut resp = self
            .client
            .send(req)
            .await
            .map_err(|e| Error::RegistryMetadataError(e.into()))?;

        if resp.status() == wstd_http::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(Error::RegistryMetadataError(anyhow::anyhow!(
                "HTTP {} fetching {url}",
                resp.status()
            )));
        }

        let body_bytes = resp
            .body_mut()
            .contents()
            .await
            .map_err(|e| Error::RegistryMetadataError(e.into()))?
            .to_vec();

        Ok(Some(body_bytes))
    }
}
