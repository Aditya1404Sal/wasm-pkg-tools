//! Pluggable HTTP client trait for simple HTTP operations (e.g. registry
//! metadata discovery).

use async_trait::async_trait;
use wasm_pkg_common::Error;

/// A minimal HTTP client abstraction used for operations that are not
/// OCI-specific (e.g. fetching registry metadata JSON).
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform an HTTP GET and return the response body as bytes.
    ///
    /// Returns `Ok(None)` for 404 responses.
    async fn get_json_bytes(&self, url: &str) -> Result<Option<Vec<u8>>, Error> {
        self.get_json_bytes_authed(url, None).await
    }

    /// Perform an HTTP GET with an optional `Authorization: Bearer <token>`
    /// header and return the response body as bytes.
    ///
    /// Returns `Ok(None)` for 404 responses.
    async fn get_json_bytes_authed(
        &self,
        url: &str,
        bearer_token: Option<&str>,
    ) -> Result<Option<Vec<u8>>, Error>;
}
