//! Pluggable OCI transport trait and transport-agnostic types.
//!
//! This module defines the [`OciTransport`] trait that abstracts OCI registry
//! wire operations (auth, tag listing, manifest/blob pulling, pushing) away
//! from any concrete HTTP client. Two implementations are provided:
//!
//! * `DefaultOciTransport` (behind the `native` feature) — wraps `oci_wasm::WasmClient`
//! * `WasmOciTransport` (behind the `wasm` feature) — uses `wstd::http::Client`

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use wasm_pkg_common::Error;

// ---------------------------------------------------------------------------
// Transport-agnostic types
// ---------------------------------------------------------------------------

/// Credentials for OCI registry authentication.
#[derive(Clone, Debug, PartialEq)]
pub enum OciCredentials {
    Anonymous,
    Basic(String, String),
}

/// Whether the operation is a pull or push (for auth scoping).
#[derive(Clone, Copy, Debug)]
pub enum OciOperation {
    Pull,
    Push,
}

/// A reference to an OCI image (`registry/repository:tag`).
#[derive(Clone, Debug)]
pub struct OciReference {
    pub registry: String,
    pub repository: String,
    pub tag: String,
}

impl OciReference {
    pub fn new(registry: String, repository: String, tag: String) -> Self {
        Self {
            registry,
            repository,
            tag,
        }
    }
}

/// Response from listing tags.
pub struct TagList {
    pub tags: Vec<String>,
}

/// Describes a layer/blob in a manifest.
#[derive(Clone, Debug, Default)]
pub struct OciLayerDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
}

/// A minimal OCI image manifest.
pub struct OciManifest {
    pub layers: Vec<OciLayerDescriptor>,
}

/// An image layer for pushing.
pub struct PushLayer {
    pub data: Vec<u8>,
    pub media_type: String,
    pub annotations: Option<BTreeMap<String, String>>,
}

/// Config blob for pushing.
pub struct PushConfig {
    pub data: Vec<u8>,
    pub media_type: String,
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// Abstracts OCI registry HTTP operations so the underlying HTTP client can be
/// swapped (e.g. `reqwest` vs `wstd::http`).
#[async_trait]
pub trait OciTransport: Send + Sync {
    /// Authenticate against the registry. Returns resolved credentials
    /// (which may differ from input, e.g. if anonymous fallback succeeds).
    async fn auth(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        operation: OciOperation,
    ) -> Result<OciCredentials, Error>;

    /// List tags for the given reference's repository.
    async fn list_tags(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<TagList, Error>;

    /// Pull a manifest and return its layer descriptors plus the manifest digest.
    async fn pull_manifest_and_config(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
    ) -> Result<(OciManifest, String), Error>;

    /// Pull a blob as a byte stream.
    ///
    /// Callers must call [`auth`](OciTransport::auth) before this method.
    /// Implementations may use internally-cached tokens from a prior `auth`
    /// call or may require `credentials` to be passed explicitly.
    async fn pull_blob_stream(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        digest: &str,
    ) -> Result<BoxStream<'static, Result<Bytes, std::io::Error>>, Error>;

    /// Push a wasm artifact (layer + config + annotations) to the registry.
    async fn push(
        &self,
        reference: &OciReference,
        credentials: &OciCredentials,
        layer: PushLayer,
        config: PushConfig,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<(), Error>;
}
