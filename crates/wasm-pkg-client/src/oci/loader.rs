use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt};
use wasm_pkg_common::{
    package::{PackageRef, Version},
    Error,
};

use crate::{
    loader::PackageLoader,
    release::{Release, VersionInfo},
    ContentStream,
};

use super::transport::OciOperation;
use super::OciBackend;

#[async_trait]
impl PackageLoader for OciBackend {
    async fn list_all_versions(&self, package: &PackageRef) -> Result<Vec<VersionInfo>, Error> {
        let reference = self.make_reference(package, None);

        tracing::debug!(?reference.registry, ?reference.repository, "Listing tags for OCI reference");
        let auth = self.auth(&reference, OciOperation::Pull).await?;
        let resp = self
            .transport
            .list_tags(&reference, &auth, None, None)
            .await?;
        tracing::trace!(tags = ?resp.tags, "List tags response");

        // Return only tags that parse as valid semver versions.
        let versions = resp
            .tags
            .iter()
            .flat_map(|tag| match Version::parse(tag) {
                Ok(version) => Some(VersionInfo {
                    version,
                    yanked: false,
                }),
                Err(err) => {
                    tracing::debug!(?tag, error = ?err, "Ignoring invalid version tag");
                    None
                }
            })
            .collect();
        Ok(versions)
    }

    async fn get_release(&self, package: &PackageRef, version: &Version) -> Result<Release, Error> {
        let reference = self.make_reference(package, Some(version));

        tracing::debug!(?reference.registry, ?reference.repository, ?reference.tag, "Fetching image manifest for OCI reference");
        let auth = self.auth(&reference, OciOperation::Pull).await?;
        let (manifest, _digest) = self
            .transport
            .pull_manifest_and_config(&reference, &auth)
            .await?;
        tracing::trace!(?manifest.layers, "Got manifest");

        let version = version.to_owned();
        let content_digest = manifest
            .layers
            .into_iter()
            .next()
            .ok_or_else(|| {
                Error::InvalidPackageManifest("Returned manifest had no layers".to_string())
            })?
            .digest
            .parse()?;
        Ok(Release {
            version,
            content_digest,
        })
    }

    async fn stream_content_unvalidated(
        &self,
        package: &PackageRef,
        release: &Release,
    ) -> Result<ContentStream, Error> {
        let reference = self.make_reference(package, None);
        let auth = self.auth(&reference, OciOperation::Pull).await?;
        let stream = self
            .transport
            .pull_blob_stream(&reference, &auth, &release.content_digest.to_string())
            .await?;
        Ok(stream.map_err(Into::into).boxed())
    }
}
