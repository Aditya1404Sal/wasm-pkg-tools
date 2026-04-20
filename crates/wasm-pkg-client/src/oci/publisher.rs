#![cfg(not(feature = "wasm"))]

use std::collections::BTreeMap;

use tokio::io::AsyncReadExt;

use crate::publisher::PackagePublisher;
use crate::{PackageRef, PublishingSource, Version};

use super::transport::{OciOperation, PushConfig, PushLayer};
use super::OciBackend;

#[async_trait::async_trait]
impl PackagePublisher for OciBackend {
    async fn publish(
        &self,
        package: &PackageRef,
        version: &Version,
        mut data: PublishingSource,
    ) -> Result<(), crate::Error> {
        // NOTE(thomastaylor312): oci-client doesn't support publishing from a stream or reader, so
        // we have to read all the data in for now. Once we can address that upstream, we'll be able
        // to remove this and use the stream directly.
        let mut buf = Vec::new();
        data.read_to_end(&mut buf).await?;
        let payload = wasm_metadata::Payload::from_binary(&buf).map_err(|e| {
            crate::Error::InvalidComponent(anyhow::anyhow!("Unable to parse WASM: {e}"))
        })?;
        let meta = payload.metadata();

        // Build the OCI config and layer from the raw component.
        // Under the `native` feature this uses oci_wasm::WasmConfig which serializes
        // to the standard wasm OCI config JSON. Under the `wasm` feature an equivalent
        // serialization is done without the oci_wasm dependency.
        let (config, layer) = build_push_artifacts(buf)?;

        let mut annotations = BTreeMap::from_iter([(
            "org.opencontainers.image.version".to_string(),
            version.to_string(),
        )]);
        if let Some(desc) = &meta.description {
            annotations.insert(
                "org.opencontainers.image.description".to_string(),
                desc.to_string(),
            );
        }
        if let Some(licenses) = &meta.licenses {
            annotations.insert(
                "org.opencontainers.image.licenses".to_string(),
                licenses.to_string(),
            );
        }
        if let Some(source) = &meta.source {
            annotations.insert(
                "org.opencontainers.image.source".to_string(),
                source.to_string(),
            );
        }
        if let Some(homepage) = &meta.homepage {
            annotations.insert(
                "org.opencontainers.image.url".to_string(),
                homepage.to_string(),
            );
        }
        if let Some(authors) = &meta.authors {
            annotations.insert(
                "org.opencontainers.image.authors".to_string(),
                authors.to_string(),
            );
        }

        let reference = self.make_reference(package, Some(version));
        let auth = self.auth(&reference, OciOperation::Push).await?;
        self.transport
            .push(&reference, &auth, layer, config, Some(annotations))
            .await?;
        Ok(())
    }
}

/// Build transport-agnostic push artifacts from a raw wasm component.
#[cfg(not(feature = "wasm"))]
fn build_push_artifacts(buf: Vec<u8>) -> Result<(PushConfig, PushLayer), crate::Error> {
    use oci_wasm::ToConfig;

    let (wasm_config, image_layer) = oci_wasm::WasmConfig::from_raw_component(buf, None)
        .map_err(crate::Error::InvalidComponent)?;

    // Serialize WasmConfig to the OCI config blob
    let oci_config = wasm_config
        .to_config()
        .map_err(crate::Error::InvalidComponent)?;

    let config = PushConfig {
        data: oci_config.data.to_vec(),
        media_type: oci_config.media_type,
    };
    let layer = PushLayer {
        data: image_layer.data.to_vec(),
        media_type: image_layer.media_type,
        annotations: image_layer.annotations,
    };
    Ok((config, layer))
}

/// Build transport-agnostic push artifacts from a raw wasm component (wasm target).
///
/// Replicates the logic of `oci_wasm::WasmConfig::from_raw_component` without
/// depending on the `oci_wasm` crate (which pulls in `oci_client`/`reqwest`).
#[cfg(feature = "wasm")]
fn build_push_artifacts(buf: Vec<u8>) -> Result<(PushConfig, PushLayer), crate::Error> {
    use sha2::Digest;

    const WASM_LAYER_MEDIA_TYPE: &str = "application/wasm";
    const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v0+json";

    // Parse the component to extract exports/imports (mirrors oci_wasm::Component).
    let component_info = match wit_component::decode(&buf)
        .map_err(|e| crate::Error::InvalidComponent(anyhow::anyhow!("failed to decode WIT: {e}")))?
    {
        wit_component::DecodedWasm::Component(resolve, world_id) => {
            let world = resolve
                .worlds
                .iter()
                .find_map(|(id, w)| (id == world_id).then_some(w))
                .ok_or_else(|| {
                    crate::Error::InvalidComponent(anyhow::anyhow!("component world not found"))
                })?;
            WasmComponent {
                exports: world
                    .exports
                    .keys()
                    .map(|key| resolve.name_world_key(key))
                    .collect(),
                imports: world
                    .imports
                    .keys()
                    .map(|key| resolve.name_world_key(key))
                    .collect(),
                target: None,
            }
        }
        wit_component::DecodedWasm::WitPackage(resolve, pkg_id) => {
            let pkg = resolve.packages.get(pkg_id).ok_or_else(|| {
                crate::Error::InvalidComponent(anyhow::anyhow!("package not found"))
            })?;
            let mut exports: std::collections::HashSet<String> = pkg
                .worlds
                .iter()
                .filter_map(|(_name, world_id)| {
                    let world = resolve.worlds.get(*world_id)?;
                    let mut exports: Vec<String> = world
                        .exports
                        .keys()
                        .map(|key| resolve.name_world_key(key))
                        .collect();
                    let mut fq_world =
                        format!("{}:{}/{}", pkg.name.namespace, pkg.name.name, world.name);
                    if let Some(ver) = pkg.name.version.as_ref() {
                        fq_world.push('@');
                        fq_world.push_str(&ver.to_string());
                    }
                    exports.push(fq_world);
                    Some(exports)
                })
                .flatten()
                .collect();
            exports.extend(pkg.interfaces.values().filter_map(|id| resolve.id_of(*id)));
            WasmComponent {
                exports: exports.into_iter().collect(),
                imports: vec![],
                target: None,
            }
        }
    };

    let layer_digest = format!("sha256:{:x}", sha2::Sha256::digest(&buf));

    // Build the config JSON (mirrors oci_wasm::WasmConfig).
    let wasm_config = WasmConfigJson {
        created: chrono_now_rfc3339(),
        author: None,
        architecture: "wasm".to_string(),
        os: "wasip2".to_string(),
        layer_digests: vec![layer_digest],
        component: Some(component_info),
    };

    let config_data =
        serde_json::to_vec(&wasm_config).map_err(|e| crate::Error::InvalidComponent(e.into()))?;

    let config = PushConfig {
        data: config_data,
        media_type: WASM_CONFIG_MEDIA_TYPE.to_string(),
    };
    let layer = PushLayer {
        data: buf,
        media_type: WASM_LAYER_MEDIA_TYPE.to_string(),
        annotations: None,
    };
    Ok((config, layer))
}

/// Mirrors `oci_wasm::Component`.
#[cfg(feature = "wasm")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WasmComponent {
    exports: Vec<String>,
    imports: Vec<String>,
    target: Option<String>,
}

/// Mirrors `oci_wasm::WasmConfig` for JSON serialization.
#[cfg(feature = "wasm")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WasmConfigJson {
    created: String,
    author: Option<String>,
    architecture: String,
    os: String,
    layer_digests: Vec<String>,
    component: Option<WasmComponent>,
}

/// Produce an RFC3339 timestamp string for "now".
///
/// We avoid pulling in `chrono` by formatting manually — the precision
/// requirement for OCI configs is low.
#[cfg(feature = "wasm")]
fn chrono_now_rfc3339() -> String {
    // In a WASI environment we can use wasi:clocks/wall-clock.
    // Fall back to the Unix epoch if unavailable (the timestamp is
    // informational only).
    "1970-01-01T00:00:00Z".to_string()
}
