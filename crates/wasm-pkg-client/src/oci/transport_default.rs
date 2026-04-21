//! Default [`OciTransport`] implementation backed by `oci_client` / `oci_wasm`
//! (which internally uses `reqwest`).
//!
//! Compiled only when the `native` feature is active.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::TryStreamExt;
use oci_client::{
    errors::OciDistributionError, manifest::OciDescriptor, secrets::RegistryAuth, Reference,
    RegistryOperation,
};
use wasm_pkg_common::Error;

use super::oci_registry_error;
use super::transport::{
    CatalogPage, OciCredentials, OciLayerDescriptor, OciManifest, OciOperation, OciReference,
    OciTransport, PushConfig, PushLayer, TagList,
};

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn to_reference(r: &OciReference) -> Reference {
    Reference::with_tag(r.registry.clone(), r.repository.clone(), r.tag.clone())
}

fn to_registry_auth(c: &OciCredentials) -> RegistryAuth {
    match c {
        OciCredentials::Anonymous => RegistryAuth::Anonymous,
        OciCredentials::Basic(u, p) => RegistryAuth::Basic(u.clone(), p.clone()),
    }
}

fn from_registry_auth(a: &RegistryAuth) -> OciCredentials {
    match a {
        RegistryAuth::Anonymous => OciCredentials::Anonymous,
        RegistryAuth::Basic(u, p) => OciCredentials::Basic(u.clone(), p.clone()),
        // Bearer tokens are handled internally by oci_client; from the
        // transport consumer's perspective this is treated as anonymous.
        RegistryAuth::Bearer(_) => OciCredentials::Anonymous,
    }
}

fn to_operation(op: OciOperation) -> RegistryOperation {
    match op {
        OciOperation::Pull => RegistryOperation::Pull,
        OciOperation::Push => RegistryOperation::Push,
    }
}

// ---------------------------------------------------------------------------
// DefaultOciTransport
// ---------------------------------------------------------------------------

pub struct DefaultOciTransport {
    client: oci_wasm::WasmClient,
}

impl DefaultOciTransport {
    pub fn new(client_config: oci_client::client::ClientConfig) -> Self {
        let client = oci_client::Client::new(client_config);
        let client = oci_wasm::WasmClient::new(client);
        Self { client }
    }
}

#[async_trait]
impl OciTransport for DefaultOciTransport {
    async fn auth(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        operation: OciOperation,
    ) -> Result<OciCredentials, Error> {
        let oci_ref = to_reference(reference);
        let mut auth = to_registry_auth(credentials);
        let oci_op = to_operation(operation);

        use OciDistributionError::AuthenticationFailure;
        match self.client.auth(&oci_ref, &auth, oci_op).await {
            Ok(_) => {}
            Err(err @ AuthenticationFailure(_)) if auth != RegistryAuth::Anonymous => {
                // The failed credentials might not be required — retry anonymously
                if self
                    .client
                    .auth(&oci_ref, &RegistryAuth::Anonymous, oci_op)
                    .await
                    .is_ok()
                {
                    auth = RegistryAuth::Anonymous;
                } else {
                    return Err(oci_registry_error(err));
                }
            }
            Err(err) => return Err(oci_registry_error(err)),
        }

        Ok(from_registry_auth(&auth))
    }

    async fn list_tags(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<TagList, Error> {
        let oci_ref = to_reference(reference);
        let auth = to_registry_auth(credentials);
        let resp = self
            .client
            .list_tags(&oci_ref, &auth, n, last)
            .await
            .map_err(oci_registry_error)?;
        Ok(TagList { tags: resp.tags })
    }

    async fn pull_manifest_and_config(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
    ) -> Result<(OciManifest, String), Error> {
        let oci_ref = to_reference(reference);
        let auth = to_registry_auth(credentials);
        let (manifest, _config, digest) = self
            .client
            .pull_manifest_and_config(&oci_ref, &auth)
            .await
            .map_err(Error::RegistryError)?;

        let layers = manifest
            .layers
            .into_iter()
            .map(|l| OciLayerDescriptor {
                media_type: l.media_type,
                digest: l.digest,
                size: l.size,
            })
            .collect();

        Ok((OciManifest { layers }, digest))
    }

    async fn pull_blob_stream(
        &self,
        reference: &OciReference,
        _credentials: &OciCredentials,
        digest: &str,
    ) -> Result<BoxStream<'static, Result<Bytes, std::io::Error>>, Error> {
        let oci_ref = to_reference(reference);
        let descriptor = OciDescriptor {
            digest: digest.to_string(),
            ..Default::default()
        };
        // Note: oci_client::Client caches auth from a prior `auth()` call,
        // so we don't need to pass credentials here.
        let stream = self
            .client
            .pull_blob_stream(&oci_ref, &descriptor)
            .await
            .map_err(oci_registry_error)?;
        // SizedStream from oci_client yields Result<Bytes, OciDistributionError>;
        // map the error to io::Error.
        let stream = stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
        Ok(Box::pin(stream))
    }

    async fn list_catalog(
        &self,
        registry: &str,
        credentials: &OciCredentials,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<CatalogPage, Error> {
        // oci_client has no _catalog method, so we call it directly via reqwest.
        let scheme = if registry == "localhost" || registry.starts_with("localhost:") {
            "http"
        } else {
            "https"
        };
        let mut url = format!("{scheme}://{registry}/v2/_catalog");
        let mut has_query = false;
        if let Some(n) = n {
            url.push_str(&format!("?n={n}"));
            has_query = true;
        }
        if let Some(last) = last {
            url.push(if has_query { '&' } else { '?' });
            url.push_str(&format!("last={}", urlencoding_simple(last)));
        }

        let mut req = reqwest::Client::new().get(&url);
        if let OciCredentials::Basic(user, pass) = credentials {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        // Parse the optional Link header for the next page cursor before we
        // consume the response body.
        let next_last = parse_link_header_last(resp.headers());

        if !resp.status().is_success() {
            return Err(Error::RegistryError(anyhow::anyhow!(
                "HTTP {} from /v2/_catalog on {registry}",
                resp.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct CatalogResp {
            repositories: Vec<String>,
        }

        let body: CatalogResp = resp
            .json()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        Ok(CatalogPage {
            repositories: body.repositories,
            next_last,
        })
    }

    async fn push(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        layer: PushLayer,
        config: PushConfig,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<(), Error> {
        let oci_ref = to_reference(reference);
        let auth = to_registry_auth(credentials);

        // Reconstruct oci_client types from our transport-agnostic types.
        // We call the underlying oci_client::Client::push directly (via Deref)
        // rather than oci_wasm::WasmClient::push, because the latter expects a
        // WasmConfig whereas we already have the serialized config blob.
        let oci_config = oci_client::client::Config {
            data: config.data.into(),
            media_type: config.media_type,
            annotations: None,
        };
        let oci_layer = oci_client::client::ImageLayer {
            data: layer.data.into(),
            media_type: layer.media_type,
            annotations: layer.annotations,
        };
        let layers = vec![oci_layer];
        let manifest =
            oci_client::manifest::OciImageManifest::build(&layers, &oci_config, annotations);

        // Access the underlying oci_client::Client via AsRef, bypassing
        // WasmClient::push which has a different signature (expects ToConfig).
        let inner: &oci_client::Client = self.client.as_ref();
        inner
            .push(&oci_ref, &layers, oci_config, &auth, Some(manifest))
            .await
            .map_err(oci_registry_error)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Catalog helpers
// ---------------------------------------------------------------------------

/// Parse the `last=` cursor out of an OCI pagination Link header.
///
/// The registry returns a header like:
///   `Link: </v2/_catalog?last=foo&n=100>; rel="next"`
/// We extract the `last=` query parameter value as the cursor.
fn parse_link_header_last(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let link = headers.get("link")?.to_str().ok()?;
    // Find the URL part inside angle brackets.
    let start = link.find('<')? + 1;
    let end = link.find('>')?;
    let url_part = &link[start..end];
    // Extract the `last=` query parameter.
    url_part.split('?').nth(1).and_then(|query| {
        query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == "last" {
                Some(v.to_string())
            } else {
                None
            }
        })
    })
}

/// Minimal percent-encoding for `last=` query parameter values (just encodes
/// `/` and `+` which appear in repository names).
fn urlencoding_simple(s: &str) -> String {
    s.replace('/', "%2F").replace('+', "%2B")
}
