use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use astragrid_geo::GeoFeatureSet;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarvestRequest {
    pub url: String,
    pub limit: Option<u32>,
    pub bbox: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarvestResult {
    pub source_url: String,
    pub final_url: String,
    pub feature_set: GeoFeatureSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProfile {
    pub name: String,
    pub request: HarvestRequest,
    #[serde(default)]
    pub cache_path: Option<PathBuf>,
    #[serde(default = "default_attempts")]
    pub retry_attempts: u8,
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileHarvestResult {
    pub profile: String,
    pub final_url: String,
    pub cache_path: Option<PathBuf>,
    pub from_cache: bool,
    pub attempts: u8,
    pub feature_set: GeoFeatureSet,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheEnvelope {
    pub schema: u16,
    pub profile: String,
    pub final_url: String,
    #[serde(with = "time::serde::rfc3339")]
    pub fetched_at: OffsetDateTime,
    pub body: String,
}

pub fn harvest_geojson(request: HarvestRequest) -> Result<HarvestResult, HarvestError> {
    let final_url = build_url(&request);
    let text = fetch_text(&final_url)?;
    let feature_set = GeoFeatureSet::from_geojson_str(&text)?;
    Ok(HarvestResult {
        source_url: request.url,
        final_url,
        feature_set,
    })
}

pub fn harvest_profile(profile: &SourceProfile) -> Result<ProfileHarvestResult, HarvestError> {
    if let Some(cache_path) = &profile.cache_path
        && cache_path.exists()
    {
        let envelope = read_cache(cache_path)?;
        let feature_set = GeoFeatureSet::from_geojson_str(&envelope.body)?;
        return Ok(ProfileHarvestResult {
            profile: profile.name.clone(),
            final_url: envelope.final_url,
            cache_path: Some(cache_path.clone()),
            from_cache: true,
            attempts: 0,
            feature_set,
        });
    }

    let final_url = build_url(&profile.request);
    let attempts = profile.retry_attempts.max(1);
    let mut last_error = None;
    for attempt in 1..=attempts {
        match fetch_text(&final_url) {
            Ok(text) => {
                if let Some(cache_path) = &profile.cache_path {
                    write_cache(
                        cache_path,
                        &CacheEnvelope {
                            schema: 1,
                            profile: profile.name.clone(),
                            final_url: final_url.clone(),
                            fetched_at: OffsetDateTime::now_utc(),
                            body: text.clone(),
                        },
                    )?;
                }
                let feature_set = GeoFeatureSet::from_geojson_str(&text)?;
                return Ok(ProfileHarvestResult {
                    profile: profile.name.clone(),
                    final_url,
                    cache_path: profile.cache_path.clone(),
                    from_cache: false,
                    attempts: attempt,
                    feature_set,
                });
            }
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    thread::sleep(Duration::from_millis(profile.retry_delay_ms));
                }
            }
        }
    }
    Err(last_error.unwrap_or(HarvestError::EmptyAttempts))
}

pub fn build_url(request: &HarvestRequest) -> String {
    let mut url = request.url.clone();
    let joiner = if url.contains('?') { '&' } else { '?' };
    let mut params = Vec::new();
    if let Some(limit) = request.limit {
        params.push(format!("limit={limit}"));
    }
    if let Some(bbox) = &request.bbox {
        params.push(format!(
            "bbox={}",
            utf8_percent_encode(bbox, NON_ALPHANUMERIC)
        ));
    }
    if !params.is_empty() {
        url.push(joiner);
        url.push_str(&params.join("&"));
    }
    url
}

fn fetch_text(url: &str) -> Result<String, HarvestError> {
    let response = ureq::get(url).call()?;
    let mut body = response.into_body();
    Ok(body.read_to_string()?)
}

fn write_cache(path: &Path, envelope: &CacheEnvelope) -> Result<(), HarvestError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(envelope)?)?;
    Ok(())
}

pub fn read_cache(path: &Path) -> Result<CacheEnvelope, HarvestError> {
    let mut bytes = fs::read(path)?;
    strip_utf8_bom(&mut bytes);
    let envelope: CacheEnvelope = serde_json::from_slice(&bytes)?;
    if envelope.schema != 1 {
        return Err(HarvestError::UnsupportedCacheSchema(envelope.schema));
    }
    Ok(envelope)
}

fn strip_utf8_bom(bytes: &mut Vec<u8>) {
    const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
    if bytes.starts_with(UTF8_BOM) {
        bytes.drain(..UTF8_BOM.len());
    }
}

const fn default_attempts() -> u8 {
    3
}

const fn default_retry_delay_ms() -> u64 {
    500
}

#[derive(Debug, thiserror::Error)]
pub enum HarvestError {
    #[error("HTTP harvest failed: {0}")]
    Http(#[from] ureq::Error),
    #[error("HTTP body read failed: {0}")]
    Body(#[from] std::io::Error),
    #[error("harvest JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("GeoJSON ingest failed: {0}")]
    Geo(#[from] astragrid_geo::GeoError),
    #[error("unsupported cache schema {0}")]
    UnsupportedCacheSchema(u16),
    #[error("retry attempts cannot be zero")]
    EmptyAttempts,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_query_url() {
        let url = build_url(&HarvestRequest {
            url: "https://example.test/collections/flood/items".to_owned(),
            limit: Some(50),
            bbox: Some("72.1,31.1,72.3,31.3".to_owned()),
        });

        assert!(url.contains("limit=50"));
        assert!(url.contains("bbox=72%2E1%2C31%2E1%2C72%2E3%2C31%2E3"));
    }

    #[test]
    fn reads_profile_from_cache_without_http() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("river.cache.json");
        write_cache(
            &cache,
            &CacheEnvelope {
                schema: 1,
                profile: "river".to_owned(),
                final_url: "https://example.test/items".to_owned(),
                fetched_at: OffsetDateTime::now_utc(),
                body: r#"{"type":"Feature","id":"river-east","properties":{},"geometry":{"type":"Point","coordinates":[72.2,31.2]}}"#.to_owned(),
            },
        )
        .unwrap();

        let result = harvest_profile(&SourceProfile {
            name: "river".to_owned(),
            request: HarvestRequest {
                url: "https://example.test/items".to_owned(),
                limit: None,
                bbox: None,
            },
            cache_path: Some(cache),
            retry_attempts: 3,
            retry_delay_ms: 0,
        })
        .unwrap();

        assert!(result.from_cache);
        assert_eq!(result.feature_set.summary.feature_count, 1);
    }
}
