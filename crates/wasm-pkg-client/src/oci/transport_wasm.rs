//! [`OciTransport`] implementation backed by `wstd::http::Client` for use in
//! WebAssembly component targets.
//!
//! Implements the [OCI Distribution Spec][1] over `wstd::http`.
//!
//! [1]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream};
use serde::Deserialize;
use wasm_pkg_common::Error;
use wstd::http as wstd_http;

use super::config::OciProtocol;
use super::transport::{
    CatalogPage, OciCredentials, OciLayerDescriptor, OciManifest, OciOperation, OciReference,
    OciTransport, PushConfig, PushLayer, TagList,
};

/// Accept header value for OCI image manifests.
const OCI_MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json";
/// Content type for OCI image manifests.
const OCI_MANIFEST_CONTENT_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

// ---------------------------------------------------------------------------
// Serde types for OCI Distribution JSON responses
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TagListResponse {
    #[allow(dead_code)]
    name: Option<String>,
    tags: Option<Vec<String>>,
}

/// OCI Image Manifest (minimal subset we care about).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciImageManifest {
    #[allow(dead_code)]
    schema_version: Option<u32>,
    #[allow(dead_code)]
    media_type: Option<String>,
    #[allow(dead_code)]
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: i64,
}

/// Token response from a Bearer token endpoint.
#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

// ---------------------------------------------------------------------------
// WasmOciTransport
// ---------------------------------------------------------------------------

pub struct WasmOciTransport {
    protocol: OciProtocol,
    client: wstd_http::Client,
    /// Cached bearer tokens keyed by repository (e.g. "wasco-dev/open-ai-api").
    bearer_tokens: Mutex<HashMap<String, String>>,
}

impl WasmOciTransport {
    pub fn new(protocol: OciProtocol) -> Self {
        Self {
            protocol,
            client: wstd_http::Client::new(),
            bearer_tokens: Mutex::new(HashMap::new()),
        }
    }

    fn base_url(&self, registry: &str) -> String {
        let scheme = match self.protocol {
            OciProtocol::Http => "http",
            OciProtocol::Https => "https",
        };
        format!("{scheme}://{registry}")
    }

    /// Build an authenticated request.  If we have a cached bearer token for the
    /// given repository, set the `Authorization: Bearer <token>` header.
    /// If credentials are basic, set the `Authorization: Basic <base64>` header.
    fn authorized_request(
        &self,
        method: wstd_http::Method,
        url: &str,
        credentials: &OciCredentials,
        repository: &str,
    ) -> Result<wstd_http::request::Builder, Error> {
        let mut builder = wstd_http::Request::builder().method(method).uri(url);

        // Prefer a cached bearer token for this repository when available.
        let cached = self.bearer_tokens.lock().unwrap().get(repository).cloned();
        if let Some(token) = cached {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        } else if let OciCredentials::Basic(user, pass) = credentials {
            use base64::Engine;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            builder = builder.header("Authorization", format!("Basic {encoded}"));
        }

        Ok(builder)
    }

    /// Send a request, following redirects (up to 5 hops).
    async fn send(
        &self,
        req: wstd_http::Request<wstd_http::Body>,
    ) -> Result<wstd_http::Response<wstd_http::Body>, Error> {
        let mut resp = self
            .client
            .send(req)
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        let mut redirects = 0;
        while resp.status().is_redirection() && redirects < 5 {
            let location = resp
                .headers()
                .get("location")
                .ok_or_else(|| {
                    Error::RegistryError(anyhow::anyhow!("redirect without Location header"))
                })?
                .to_str()
                .map_err(|e| Error::RegistryError(e.into()))?
                .to_string();

            // Redirect targets (e.g. pre-signed storage URLs) typically don't
            // need auth headers — sending them can cause failures.
            let redirect_req = wstd_http::Request::builder()
                .method(wstd_http::Method::GET)
                .uri(&location)
                .body(wstd_http::Body::empty())
                .map_err(|e| Error::RegistryError(e.into()))?;

            resp = self
                .client
                .send(redirect_req)
                .await
                .map_err(|e| Error::RegistryError(e.into()))?;

            redirects += 1;
        }

        Ok(resp)
    }

    /// Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
    /// header value and exchange the given credentials for a bearer token.
    /// If the challenge does not include a `scope`, one is injected based on
    /// the reference's repository and the requested operation.
    async fn fetch_bearer_token(
        &self,
        www_authenticate: &str,
        credentials: &OciCredentials,
        reference: &OciReference,
        operation: OciOperation,
    ) -> Result<String, Error> {
        let (realm, mut params) = parse_www_authenticate(www_authenticate)?;

        // Replace (or inject) the `scope` param with the correct repository-scoped
        // value. GHCR's /v2/ challenge includes a generic placeholder scope
        // (e.g. "repository:user/image:pull") that results in a 403 when used.
        let actions = match operation {
            OciOperation::Pull => "pull",
            OciOperation::Push => "push,pull",
        };
        let correct_scope = format!("repository:{}:{}", reference.repository, actions);
        if let Some(existing) = params.iter_mut().find(|(k, _)| k == "scope") {
            existing.1 = correct_scope;
        } else {
            params.push(("scope".to_string(), correct_scope));
        }

        // Build the token request URL with query parameters.
        let mut token_url = realm.to_string();
        let mut first = !token_url.contains('?');
        for (k, v) in &params {
            token_url.push(if first { '?' } else { '&' });
            first = false;
            token_url.push_str(k);
            token_url.push('=');
            token_url.push_str(v);
        }

        let mut builder = wstd_http::Request::builder()
            .method(wstd_http::Method::GET)
            .uri(&token_url);

        if let OciCredentials::Basic(user, pass) = credentials {
            use base64::Engine;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            builder = builder.header("Authorization", format!("Basic {encoded}"));
        }

        let req = builder
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let mut resp = self.send(req).await?;

        if !resp.status().is_success() {
            return Err(Error::RegistryError(anyhow::anyhow!(
                "token endpoint returned HTTP {}",
                resp.status()
            )));
        }

        let body = resp
            .body_mut()
            .contents()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        let token_resp: TokenResponse =
            serde_json::from_slice(body).map_err(|e| Error::RegistryError(e.into()))?;

        token_resp.token.or(token_resp.access_token).ok_or_else(|| {
            Error::RegistryError(anyhow::anyhow!(
                "token response contained neither 'token' nor 'access_token'"
            ))
        })
    }
}

#[async_trait]
impl OciTransport for WasmOciTransport {
    async fn auth(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        operation: OciOperation,
    ) -> Result<OciCredentials, Error> {
        // If we already have a cached token for this repository, skip re-auth.
        {
            let tokens = self.bearer_tokens.lock().unwrap();
            if tokens.contains_key(&reference.repository) {
                return Ok(credentials.clone());
            }
        }

        let url = format!("{}/v2/", self.base_url(&reference.registry));

        // Probe with current credentials.
        let req = self
            .authorized_request(
                wstd_http::Method::GET,
                &url,
                credentials,
                &reference.repository,
            )?
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let resp = self.send(req).await?;
        let status = resp.status();

        if status.is_success() {
            return Ok(credentials.clone());
        }

        if status == wstd_http::StatusCode::UNAUTHORIZED {
            // Look for WWW-Authenticate header.
            if let Some(www_auth) = resp.headers().get("www-authenticate") {
                let www_auth = www_auth
                    .to_str()
                    .map_err(|e| Error::RegistryError(e.into()))?;

                if www_auth.to_lowercase().starts_with("bearer ") {
                    let token = self
                        .fetch_bearer_token(www_auth, credentials, reference, operation)
                        .await?;
                    self.bearer_tokens
                        .lock()
                        .unwrap()
                        .insert(reference.repository.clone(), token);
                    return Ok(credentials.clone());
                }
            }

            // If basic auth failed, try anonymous.
            if *credentials != OciCredentials::Anonymous {
                let anon_req = wstd_http::Request::builder()
                    .method(wstd_http::Method::GET)
                    .uri(&url)
                    .body(wstd_http::Body::empty())
                    .map_err(|e| Error::RegistryError(e.into()))?;

                let anon_resp = self.send(anon_req).await?;
                if anon_resp.status().is_success() {
                    return Ok(OciCredentials::Anonymous);
                }

                // Anonymous also got a challenge — try token exchange anonymously.
                if anon_resp.status() == wstd_http::StatusCode::UNAUTHORIZED {
                    if let Some(www_auth) = anon_resp.headers().get("www-authenticate") {
                        let www_auth = www_auth
                            .to_str()
                            .map_err(|e| Error::RegistryError(e.into()))?;

                        if www_auth.to_lowercase().starts_with("bearer ") {
                            let token = self
                                .fetch_bearer_token(
                                    www_auth,
                                    &OciCredentials::Anonymous,
                                    reference,
                                    operation,
                                )
                                .await?;
                            self.bearer_tokens
                                .lock()
                                .unwrap()
                                .insert(reference.repository.clone(), token);
                            return Ok(OciCredentials::Anonymous);
                        }
                    }
                }
            }

            return Err(Error::RegistryError(anyhow::anyhow!(
                "authentication failed for registry {}",
                reference.registry
            )));
        }

        Err(Error::RegistryError(anyhow::anyhow!(
            "unexpected HTTP {} from /v2/ endpoint",
            status
        )))
    }

    async fn list_tags(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<TagList, Error> {
        let mut url = format!(
            "{}/v2/{}/tags/list",
            self.base_url(&reference.registry),
            reference.repository
        );

        // Append optional pagination query parameters.
        let mut has_query = false;
        if let Some(n) = n {
            url.push_str(&format!("?n={n}"));
            has_query = true;
        }
        if let Some(last) = last {
            url.push(if has_query { '&' } else { '?' });
            url.push_str(&format!("last={last}"));
        }

        let req = self
            .authorized_request(
                wstd_http::Method::GET,
                &url,
                credentials,
                &reference.repository,
            )?
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let mut resp = self.send(req).await?;

        if !resp.status().is_success() {
            return Err(oci_error_from_status(resp.status(), "listing tags"));
        }

        let body = resp
            .body_mut()
            .contents()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        let tag_list: TagListResponse =
            serde_json::from_slice(body).map_err(|e| Error::RegistryError(e.into()))?;

        Ok(TagList {
            tags: tag_list.tags.unwrap_or_default(),
        })
    }

    async fn pull_manifest_and_config(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
    ) -> Result<(OciManifest, String), Error> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            self.base_url(&reference.registry),
            reference.repository,
            reference.tag
        );

        let req = self
            .authorized_request(
                wstd_http::Method::GET,
                &url,
                credentials,
                &reference.repository,
            )?
            .header("Accept", OCI_MANIFEST_ACCEPT)
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let mut resp = self.send(req).await?;

        if resp.status() == wstd_http::StatusCode::NOT_FOUND {
            return Err(Error::PackageNotFound);
        }

        if !resp.status().is_success() {
            return Err(oci_error_from_status(resp.status(), "pulling manifest"));
        }

        // The digest is typically returned in the Docker-Content-Digest header.
        let digest = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_default();

        let body = resp
            .body_mut()
            .contents()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        let manifest: OciImageManifest =
            serde_json::from_slice(body).map_err(|e| Error::RegistryError(e.into()))?;

        let layers = manifest
            .layers
            .into_iter()
            .map(|d| OciLayerDescriptor {
                media_type: d.media_type,
                digest: d.digest,
                size: d.size,
            })
            .collect();

        Ok((OciManifest { layers }, digest))
    }

    async fn pull_blob_stream(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        digest: &str,
    ) -> Result<BoxStream<'static, Result<Bytes, std::io::Error>>, Error> {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            self.base_url(&reference.registry),
            reference.repository,
            digest
        );

        let req = self
            .authorized_request(
                wstd_http::Method::GET,
                &url,
                credentials,
                &reference.repository,
            )?
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let mut resp = self.send(req).await?;

        if !resp.status().is_success() {
            return Err(oci_error_from_status(resp.status(), "pulling blob"));
        }

        // Collect the full body into memory and return it as a single-item stream.
        // wstd::http::Body is tied to WASI resource lifetimes and cannot be
        // returned as a long-lived stream, so we buffer here.
        let body_bytes = resp
            .body_mut()
            .contents()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?
            .to_vec();

        Ok(Box::pin(stream::once(async move {
            Ok(Bytes::from(body_bytes))
        })))
    }

    async fn list_catalog(
        &self,
        registry: &str,
        credentials: &OciCredentials,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<CatalogPage, Error> {
        let mut url = format!("{}/v2/_catalog", self.base_url(registry));
        let mut has_query = false;
        if let Some(n) = n {
            url.push_str(&format!("?n={n}"));
            has_query = true;
        }
        if let Some(last) = last {
            url.push(if has_query { '&' } else { '?' });
            // Percent-encode slashes in repository names.
            let encoded = last.replace('/', "%2F");
            url.push_str(&format!("last={encoded}"));
        }

        // _catalog is registry-wide (not repo-scoped), so pass an empty
        // repository string — no cached bearer token will match.
        let req = self
            .authorized_request(wstd_http::Method::GET, &url, credentials, "")?
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let mut resp = self.send(req).await?;

        // Extract Link header cursor before consuming the body.
        let next_last = resp
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_link_last);

        if !resp.status().is_success() {
            return Err(Error::RegistryError(anyhow::anyhow!(
                "HTTP {} from /v2/_catalog on {registry}",
                resp.status()
            )));
        }

        #[derive(Deserialize)]
        struct CatalogResp {
            repositories: Vec<String>,
        }

        let body = resp
            .body_mut()
            .contents()
            .await
            .map_err(|e| Error::RegistryError(e.into()))?;

        let catalog: CatalogResp =
            serde_json::from_slice(body).map_err(|e| Error::RegistryError(e.into()))?;

        Ok(CatalogPage {
            repositories: catalog.repositories,
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
        let base = self.base_url(&reference.registry);
        let repo = &reference.repository;

        // 1. Upload config blob
        let config_digest = sha256_digest(&config.data);
        self.upload_blob(&base, repo, credentials, &config.data, &config_digest)
            .await?;

        // 2. Upload layer blob
        let layer_digest = sha256_digest(&layer.data);
        self.upload_blob(&base, repo, credentials, &layer.data, &layer_digest)
            .await?;

        // 3. Build and upload the manifest
        let manifest = build_manifest_json(
            &config.media_type,
            &config_digest,
            config.data.len() as i64,
            &layer.media_type,
            &layer_digest,
            layer.data.len() as i64,
            layer.annotations.as_ref(),
            annotations.as_ref(),
        );

        let manifest_url = format!("{base}/v2/{repo}/manifests/{}", reference.tag);

        let req = self
            .authorized_request(wstd_http::Method::PUT, &manifest_url, credentials, repo)?
            .header("Content-Type", OCI_MANIFEST_CONTENT_TYPE)
            .body(wstd_http::Body::from(manifest))
            .map_err(|e| Error::RegistryError(e.into()))?;

        let resp = self.send(req).await?;

        if !resp.status().is_success() {
            return Err(oci_error_from_status(resp.status(), "pushing manifest"));
        }

        Ok(())
    }
}

impl WasmOciTransport {
    /// Upload a blob via the monolithic upload path:
    ///   POST /v2/<name>/blobs/uploads/  →  get Location
    ///   PUT  <Location>?digest=<digest>  with body
    async fn upload_blob(
        &self,
        base: &str,
        repo: &str,
        credentials: &OciCredentials,
        data: &[u8],
        digest: &str,
    ) -> Result<(), Error> {
        // Check if blob already exists (HEAD).
        let exists_url = format!("{base}/v2/{repo}/blobs/{digest}");
        let head_req = self
            .authorized_request(wstd_http::Method::HEAD, &exists_url, credentials, repo)?
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let head_resp = self.send(head_req).await?;
        if head_resp.status().is_success() {
            tracing::debug!(digest, "Blob already exists, skipping upload");
            return Ok(());
        }

        // Initiate upload.
        let upload_url = format!("{base}/v2/{repo}/blobs/uploads/");
        let post_req = self
            .authorized_request(wstd_http::Method::POST, &upload_url, credentials, repo)?
            .header("Content-Length", "0")
            .body(wstd_http::Body::empty())
            .map_err(|e| Error::RegistryError(e.into()))?;

        let post_resp = self.send(post_req).await?;

        if post_resp.status() != wstd_http::StatusCode::ACCEPTED {
            return Err(oci_error_from_status(
                post_resp.status(),
                "initiating blob upload",
            ));
        }

        // Get the upload location from the Location header.
        let location = post_resp
            .headers()
            .get("location")
            .ok_or_else(|| {
                Error::RegistryError(anyhow::anyhow!(
                    "blob upload response missing Location header"
                ))
            })?
            .to_str()
            .map_err(|e| Error::RegistryError(e.into()))?
            .to_string();

        // The Location may be absolute or relative. Make it absolute.
        let put_url = if location.starts_with("http://") || location.starts_with("https://") {
            location
        } else {
            format!("{base}{location}")
        };

        // Append the digest query parameter.
        let separator = if put_url.contains('?') { '&' } else { '?' };
        let put_url = format!("{put_url}{separator}digest={digest}");

        let put_req = self
            .authorized_request(wstd_http::Method::PUT, &put_url, credentials, repo)?
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", data.len().to_string())
            .body(wstd_http::Body::from(data.to_vec()))
            .map_err(|e| Error::RegistryError(e.into()))?;

        let put_resp = self.send(put_req).await?;

        if !put_resp.status().is_success() {
            return Err(oci_error_from_status(
                put_resp.status(),
                "completing blob upload",
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn oci_error_from_status(status: wstd_http::StatusCode, action: &str) -> Error {
    if status == wstd_http::StatusCode::NOT_FOUND {
        Error::PackageNotFound
    } else {
        Error::RegistryError(anyhow::anyhow!("HTTP {status} while {action}"))
    }
}

/// Compute a `sha256:<hex>` digest for the given data.
fn sha256_digest(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    format!("sha256:{:x}", hash)
}

/// Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
/// header into the realm URL and a list of key=value pairs.
fn parse_www_authenticate(header: &str) -> Result<(String, Vec<(String, String)>), Error> {
    // Strip the "Bearer " prefix (case-insensitive).
    let rest = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or_else(|| {
            Error::RegistryError(anyhow::anyhow!(
                "expected Bearer WWW-Authenticate challenge, got: {header}"
            ))
        })?;

    let mut realm = String::new();
    let mut params = Vec::new();

    for part in split_challenge_params(rest) {
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim().trim_matches('"').to_string();
            if key == "realm" {
                realm = value;
            } else {
                params.push((key, value));
            }
        }
    }

    if realm.is_empty() {
        return Err(Error::RegistryError(anyhow::anyhow!(
            "WWW-Authenticate Bearer challenge missing realm"
        )));
    }

    Ok((realm, params))
}

/// Split challenge parameters, respecting quoted strings.
/// e.g. `realm="https://auth.example.com/token",service="registry",scope="repository:foo:pull"`
/// Extract the `last=` cursor from an OCI Link header value.
/// Header looks like: `</v2/_catalog?last=foo&n=100>; rel="next"`
fn parse_link_last(link: &str) -> Option<String> {
    let start = link.find('<')? + 1;
    let end = link.find('>')?;
    let url_part = &link[start..end];
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

fn split_challenge_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let part = s[start..i].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    let last = s[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }

    parts
}

/// Build a minimal OCI image manifest JSON.
fn build_manifest_json(
    config_media_type: &str,
    config_digest: &str,
    config_size: i64,
    layer_media_type: &str,
    layer_digest: &str,
    layer_size: i64,
    layer_annotations: Option<&BTreeMap<String, String>>,
    manifest_annotations: Option<&BTreeMap<String, String>>,
) -> Vec<u8> {
    let mut manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_CONTENT_TYPE,
        "config": {
            "mediaType": config_media_type,
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [{
            "mediaType": layer_media_type,
            "digest": layer_digest,
            "size": layer_size,
        }]
    });

    if let Some(ann) = layer_annotations {
        if !ann.is_empty() {
            manifest["layers"][0]["annotations"] = serde_json::json!(ann);
        }
    }

    if let Some(ann) = manifest_annotations {
        if !ann.is_empty() {
            manifest["annotations"] = serde_json::json!(ann);
        }
    }

    serde_json::to_vec(&manifest).expect("manifest serialization should not fail")
}
