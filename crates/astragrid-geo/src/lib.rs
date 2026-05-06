use std::{collections::BTreeMap, str::FromStr};

use geojson::{Feature, GeoJson, Geometry, Value as GeometryValue, feature::Id as GeoJsonId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoFeatureRecord {
    pub id: String,
    pub geometry_type: String,
    pub bbox: Option<BoundingBox>,
    pub properties: Map<String, Value>,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoundingBox {
    pub min_lon: f64,
    pub min_lat: f64,
    pub max_lon: f64,
    pub max_lat: f64,
}

impl BoundingBox {
    fn include_position(&mut self, position: &[f64]) {
        if position.len() < 2 {
            return;
        }
        let lon = position[0];
        let lat = position[1];
        self.min_lon = self.min_lon.min(lon);
        self.min_lat = self.min_lat.min(lat);
        self.max_lon = self.max_lon.max(lon);
        self.max_lat = self.max_lat.max(lat);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIngestSummary {
    pub feature_count: usize,
    pub geometry_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoFeatureSet {
    pub features: Vec<GeoFeatureRecord>,
    pub summary: GeoIngestSummary,
}

impl GeoFeatureSet {
    pub fn from_geojson_str(input: &str) -> Result<Self, GeoError> {
        let geojson = GeoJson::from_str(input)?;
        let features = match geojson {
            GeoJson::FeatureCollection(collection) => collection
                .features
                .into_iter()
                .enumerate()
                .map(|(index, feature)| feature_record(index, feature))
                .collect::<Result<Vec<_>, _>>()?,
            GeoJson::Feature(feature) => vec![feature_record(0, feature)?],
            GeoJson::Geometry(geometry) => vec![geometry_record(0, geometry)?],
        };

        if features.is_empty() {
            return Err(GeoError::EmptyFeatureSet);
        }

        let mut geometry_counts = BTreeMap::new();
        for feature in &features {
            *geometry_counts
                .entry(feature.geometry_type.clone())
                .or_insert(0) += 1;
        }

        Ok(Self {
            summary: GeoIngestSummary {
                feature_count: features.len(),
                geometry_counts,
            },
            features,
        })
    }

    pub fn to_json_lines(&self) -> Result<String, GeoError> {
        let mut output = String::new();
        for feature in &self.features {
            output.push_str(&serde_json::to_string(feature)?);
            output.push('\n');
        }
        Ok(output)
    }
}

fn feature_record(index: usize, feature: Feature) -> Result<GeoFeatureRecord, GeoError> {
    let geometry = feature.geometry.ok_or(GeoError::MissingGeometry(index))?;
    let id = feature
        .id
        .map(geojson_id_to_string)
        .unwrap_or_else(|| format!("feature-{index}"));
    let properties = feature.properties.unwrap_or_default();
    record_from_parts(index, id, geometry, properties)
}

fn geometry_record(index: usize, geometry: Geometry) -> Result<GeoFeatureRecord, GeoError> {
    record_from_parts(
        index,
        format!("geometry-{index}"),
        geometry,
        Map::<String, Value>::new(),
    )
}

fn record_from_parts(
    index: usize,
    id: String,
    geometry: Geometry,
    properties: Map<String, Value>,
) -> Result<GeoFeatureRecord, GeoError> {
    let geometry_type = geometry_type(&geometry.value).to_owned();
    let bbox = geometry_bbox(&geometry).ok_or(GeoError::InvalidGeometry(index))?;
    let digest = feature_digest(&id, &geometry, &properties)?;
    Ok(GeoFeatureRecord {
        id,
        geometry_type,
        bbox: Some(bbox),
        properties,
        digest,
    })
}

fn geojson_id_to_string(id: GeoJsonId) -> String {
    match id {
        GeoJsonId::String(value) => value,
        GeoJsonId::Number(value) => value.to_string(),
    }
}

fn geometry_type(value: &GeometryValue) -> &'static str {
    match value {
        GeometryValue::Point(_) => "Point",
        GeometryValue::MultiPoint(_) => "MultiPoint",
        GeometryValue::LineString(_) => "LineString",
        GeometryValue::MultiLineString(_) => "MultiLineString",
        GeometryValue::Polygon(_) => "Polygon",
        GeometryValue::MultiPolygon(_) => "MultiPolygon",
        GeometryValue::GeometryCollection(_) => "GeometryCollection",
    }
}

fn geometry_bbox(geometry: &Geometry) -> Option<BoundingBox> {
    let mut bbox = BoundingBox {
        min_lon: f64::INFINITY,
        min_lat: f64::INFINITY,
        max_lon: f64::NEG_INFINITY,
        max_lat: f64::NEG_INFINITY,
    };
    include_geometry(&mut bbox, &geometry.value);
    if bbox.min_lon.is_finite()
        && bbox.min_lat.is_finite()
        && bbox.max_lon.is_finite()
        && bbox.max_lat.is_finite()
    {
        Some(bbox)
    } else {
        None
    }
}

fn include_geometry(bbox: &mut BoundingBox, value: &GeometryValue) {
    match value {
        GeometryValue::Point(point) => bbox.include_position(point),
        GeometryValue::MultiPoint(points) | GeometryValue::LineString(points) => {
            for point in points {
                bbox.include_position(point);
            }
        }
        GeometryValue::MultiLineString(lines) | GeometryValue::Polygon(lines) => {
            for line in lines {
                for point in line {
                    bbox.include_position(point);
                }
            }
        }
        GeometryValue::MultiPolygon(polygons) => {
            for polygon in polygons {
                for ring in polygon {
                    for point in ring {
                        bbox.include_position(point);
                    }
                }
            }
        }
        GeometryValue::GeometryCollection(geometries) => {
            for geometry in geometries {
                include_geometry(bbox, &geometry.value);
            }
        }
    }
}

fn feature_digest(
    id: &str,
    geometry: &Geometry,
    properties: &Map<String, Value>,
) -> Result<String, GeoError> {
    let payload = serde_json::json!({
        "id": id,
        "geometry": geometry,
        "properties": properties,
    });
    Ok(blake3::hash(&serde_json::to_vec(&payload)?)
        .to_hex()
        .to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    #[error("GeoJSON parse failed: {0}")]
    GeoJson(Box<geojson::Error>),
    #[error("GeoJSON JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("GeoJSON feature set is empty")]
    EmptyFeatureSet,
    #[error("GeoJSON feature {0} has no geometry")]
    MissingGeometry(usize),
    #[error("GeoJSON feature {0} has invalid or empty geometry")]
    InvalidGeometry(usize),
}

impl From<geojson::Error> for GeoError {
    fn from(value: geojson::Error) -> Self {
        GeoError::GeoJson(Box::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingests_feature_collection_with_bbox_and_digest() {
        let input = r#"{
          "type": "FeatureCollection",
          "features": [
            {
              "type": "Feature",
              "id": "river-east",
              "properties": { "risk": "flood" },
              "geometry": {
                "type": "Polygon",
                "coordinates": [[[72.1,31.1],[72.3,31.1],[72.3,31.3],[72.1,31.1]]]
              }
            }
          ]
        }"#;

        let set = GeoFeatureSet::from_geojson_str(input).unwrap();

        assert_eq!(set.summary.feature_count, 1);
        assert_eq!(set.features[0].geometry_type, "Polygon");
        assert_eq!(set.features[0].bbox.unwrap().min_lon, 72.1);
        assert!(!set.features[0].digest.is_empty());
    }

    #[test]
    fn rejects_feature_without_geometry() {
        let input = r#"{"type":"Feature","geometry":null,"properties":{}}"#;

        assert!(matches!(
            GeoFeatureSet::from_geojson_str(input),
            Err(GeoError::MissingGeometry(0))
        ));
    }
}
