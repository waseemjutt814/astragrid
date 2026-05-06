use astragrid_geo::{BoundingBox, GeoFeatureRecord};
use astragrid_state::{IncidentStatus, MissionState, MissionStateSummary};

const WIDTH: f64 = 1000.0;
const HEIGHT: f64 = 640.0;
const PADDING: f64 = 42.0;

#[derive(Debug, Clone, PartialEq)]
pub struct MapDocument {
    pub title: String,
    pub features: Vec<GeoFeatureRecord>,
    pub bounds: BoundingBox,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MapConsoleDocument {
    pub map: MapDocument,
    pub state_summary: MissionStateSummary,
    pub incidents: Vec<MapIncidentOverlay>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MapIncidentOverlay {
    pub subject: String,
    pub status: IncidentStatus,
    pub priority: String,
    pub feature_present: bool,
}

impl MapDocument {
    pub fn from_json_lines(input: &str, title: impl Into<String>) -> Result<Self, MapError> {
        let mut features = Vec::new();
        for (index, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let feature: GeoFeatureRecord =
                serde_json::from_str(line).map_err(|error| MapError::FeatureLineJson {
                    line: index + 1,
                    error,
                })?;
            if feature.bbox.is_none() {
                return Err(MapError::MissingBoundingBox(feature.id));
            }
            features.push(feature);
        }
        if features.is_empty() {
            return Err(MapError::EmptyFeatureSet);
        }
        let bounds = padded_bounds(union_bounds(&features)?);
        Ok(Self {
            title: title.into(),
            features,
            bounds,
        })
    }

    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        html.push_str(&format!("<title>{}</title>\n", escape_html(&self.title)));
        html.push_str("<style>\n");
        html.push_str(
            "body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;color:#17202a;background:#f7f8f5}\
             header{padding:20px 24px;background:#243b53;color:#fff}\
             h1{margin:0 0 6px;font-size:24px;font-weight:700;letter-spacing:0}\
             p{margin:0;color:#d8e2ec}\
             main{display:grid;grid-template-columns:minmax(0,2fr) minmax(320px,1fr);gap:18px;padding:18px}\
             .panel{background:#fff;border:1px solid #d7dce2;border-radius:6px;overflow:hidden}\
             .map{min-height:420px}\
             svg{display:block;width:100%;height:auto;background:#eef3f7}\
             .frame{fill:#fbfcfd;stroke:#9fb3c8;stroke-width:1.5}\
             .feature-rect{fill:#f4b942;fill-opacity:.26;stroke:#b85c38;stroke-width:2}\
             .feature-point{fill:#2f855a;stroke:#ffffff;stroke-width:2}\
             .grid{stroke:#d8e2ec;stroke-width:1}\
             table{width:100%;border-collapse:collapse}\
             th,td{padding:9px 10px;border-bottom:1px solid #e6eaef;text-align:left;vertical-align:top}\
             th{background:#f0f4f8;color:#243b53;font-size:12px;text-transform:uppercase;letter-spacing:0}\
             code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}\
             .digest{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\
             @media(max-width:860px){main{grid-template-columns:1fr;padding:12px}header{padding:16px}}\n",
        );
        html.push_str("</style>\n</head>\n<body>\n");
        html.push_str(&format!(
            "<header><h1>{}</h1><p>{} features. Bounds lon {:.5}..{:.5}, lat {:.5}..{:.5}.</p></header>\n",
            escape_html(&self.title),
            self.features.len(),
            self.bounds.min_lon,
            self.bounds.max_lon,
            self.bounds.min_lat,
            self.bounds.max_lat
        ));
        html.push_str("<main>\n<section class=\"panel map\">\n");
        html.push_str(&format!(
            "<svg viewBox=\"0 0 {WIDTH:.0} {HEIGHT:.0}\" role=\"img\" aria-label=\"{}\">\n",
            escape_html(&self.title)
        ));
        html.push_str(&grid_svg());
        html.push_str(&format!(
            "<rect class=\"frame\" x=\"{PADDING}\" y=\"{PADDING}\" width=\"{}\" height=\"{}\" rx=\"4\" />\n",
            WIDTH - (PADDING * 2.0),
            HEIGHT - (PADDING * 2.0)
        ));
        for feature in &self.features {
            html.push_str(&self.feature_svg(feature));
        }
        html.push_str("</svg>\n</section>\n<section class=\"panel\">\n<table>\n");
        html.push_str(
            "<thead><tr><th>Feature</th><th>Type</th><th>Digest</th></tr></thead>\n<tbody>\n",
        );
        for feature in &self.features {
            html.push_str(&format!(
                "<tr id=\"{}\"><td>{}</td><td>{}</td><td class=\"digest\"><code>{}</code></td></tr>\n",
                element_id(&feature.id),
                escape_html(&feature.id),
                escape_html(&feature.geometry_type),
                escape_html(&feature.digest)
            ));
        }
        html.push_str("</tbody>\n</table>\n</section>\n</main>\n</body>\n</html>\n");
        html
    }

    fn feature_svg(&self, feature: &GeoFeatureRecord) -> String {
        let bbox = feature.bbox.expect("validated bbox");
        let (x1, y1) = self.project(bbox.min_lon, bbox.max_lat);
        let (x2, y2) = self.project(bbox.max_lon, bbox.min_lat);
        let width = (x2 - x1).abs();
        let height = (y2 - y1).abs();
        let title = format!(
            "{} | {} | {}",
            feature.id, feature.geometry_type, feature.digest
        );
        if width < 5.0 && height < 5.0 {
            let (cx, cy) = self.project(
                (bbox.min_lon + bbox.max_lon) / 2.0,
                (bbox.min_lat + bbox.max_lat) / 2.0,
            );
            format!(
                "<a href=\"#{}\"><circle class=\"feature-point\" cx=\"{cx:.2}\" cy=\"{cy:.2}\" r=\"6\"><title>{}</title></circle></a>\n",
                element_id(&feature.id),
                escape_html(&title)
            )
        } else {
            format!(
                "<a href=\"#{}\"><rect class=\"feature-rect\" x=\"{:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{:.2}\" rx=\"3\"><title>{}</title></rect></a>\n",
                element_id(&feature.id),
                x1.min(x2),
                y1.min(y2),
                width.max(5.0),
                height.max(5.0),
                escape_html(&title)
            )
        }
    }

    fn project(&self, lon: f64, lat: f64) -> (f64, f64) {
        let usable_width = WIDTH - (PADDING * 2.0);
        let usable_height = HEIGHT - (PADDING * 2.0);
        let lon_span = (self.bounds.max_lon - self.bounds.min_lon).max(f64::EPSILON);
        let lat_span = (self.bounds.max_lat - self.bounds.min_lat).max(f64::EPSILON);
        let x = PADDING + ((lon - self.bounds.min_lon) / lon_span * usable_width);
        let y = PADDING + ((self.bounds.max_lat - lat) / lat_span * usable_height);
        (x, y)
    }
}

impl MapConsoleDocument {
    pub fn from_json_lines_and_state(
        input: &str,
        title: impl Into<String>,
        state: &MissionState,
    ) -> Result<Self, MapError> {
        let map = MapDocument::from_json_lines(input, title)?;
        let feature_ids = map
            .features
            .iter()
            .map(|feature| feature.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let incidents = state
            .incidents
            .values()
            .map(|incident| MapIncidentOverlay {
                subject: incident.subject.clone(),
                status: incident.status,
                priority: incident.priority.to_string(),
                feature_present: feature_ids.contains(incident.subject.as_str()),
            })
            .collect();
        Ok(Self {
            map,
            state_summary: state.summary(),
            incidents,
        })
    }

    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        html.push_str(&format!(
            "<title>{}</title>\n",
            escape_html(&self.map.title)
        ));
        html.push_str("<style>\n");
        html.push_str(
            "body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;color:#18212f;background:#f6f7f4}\
             header{padding:18px 22px;background:#19324d;color:#fff}\
             h1{margin:0 0 6px;font-size:24px;letter-spacing:0}\
             p{margin:0;color:#d9e4ef}\
             main{display:grid;grid-template-columns:minmax(0,2fr) minmax(340px,1fr);gap:16px;padding:16px}\
             section{background:#fff;border:1px solid #d9dee7;border-radius:6px;overflow:hidden}\
             .summary{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;padding:12px;border-bottom:1px solid #e7ebf0}\
             .metric{padding:10px;background:#f4f7fa;border:1px solid #e2e8ef;border-radius:4px}\
             .metric b{display:block;font-size:20px;color:#18324d}\
             svg{display:block;width:100%;height:auto;background:#eef3f7}\
             .frame{fill:#fbfcfd;stroke:#9fb3c8;stroke-width:1.5}\
             .feature-rect{fill:#f4b942;fill-opacity:.26;stroke:#b85c38;stroke-width:2}\
             .feature-point{fill:#2f855a;stroke:#ffffff;stroke-width:2}\
             .open-hit{outline:3px solid #c53030}\
             .grid{stroke:#d8e2ec;stroke-width:1}\
             table{width:100%;border-collapse:collapse}\
             th,td{padding:9px 10px;border-bottom:1px solid #e6eaef;text-align:left;vertical-align:top}\
             th{background:#f0f4f8;color:#243b53;font-size:12px;text-transform:uppercase;letter-spacing:0}\
             .status-open{color:#9b2c2c;font-weight:700}.status-closed{color:#2f855a;font-weight:700}\
             @media(max-width:900px){main{grid-template-columns:1fr;padding:12px}.summary{grid-template-columns:repeat(2,1fr)}}\n",
        );
        html.push_str("</style>\n</head>\n<body>\n");
        html.push_str(&format!(
            "<header><h1>{}</h1><p>Mission {}. {} feature(s), {} event(s).</p></header>\n",
            escape_html(&self.map.title),
            escape_html(self.state_summary.mission.as_deref().unwrap_or("unknown")),
            self.map.features.len(),
            self.state_summary.events
        ));
        html.push_str("<main>\n<section>\n");
        html.push_str(&format!(
            "<svg viewBox=\"0 0 {WIDTH:.0} {HEIGHT:.0}\" role=\"img\" aria-label=\"{}\">\n",
            escape_html(&self.map.title)
        ));
        html.push_str(&grid_svg());
        html.push_str(&format!(
            "<rect class=\"frame\" x=\"{PADDING}\" y=\"{PADDING}\" width=\"{}\" height=\"{}\" rx=\"4\" />\n",
            WIDTH - (PADDING * 2.0),
            HEIGHT - (PADDING * 2.0)
        ));
        for feature in &self.map.features {
            html.push_str(&self.map.feature_svg(feature));
        }
        html.push_str("</svg>\n</section>\n<section>\n");
        html.push_str("<div class=\"summary\">\n");
        html.push_str(&metric("Open", self.state_summary.open_incidents));
        html.push_str(&metric("Closed", self.state_summary.closed_incidents));
        html.push_str(&metric("Observations", self.state_summary.observations));
        html.push_str(&metric("Dispatches", self.state_summary.dispatches));
        html.push_str(&metric("Annotations", self.state_summary.annotations));
        html.push_str(&metric("Features", self.map.features.len()));
        html.push_str("</div>\n<table>\n<thead><tr><th>Incident</th><th>Status</th><th>Priority</th><th>Mapped</th></tr></thead>\n<tbody>\n");
        for incident in &self.incidents {
            let status_class = match incident.status {
                IncidentStatus::Open => "status-open",
                IncidentStatus::Closed => "status-closed",
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&incident.subject),
                status_class,
                escape_html(match incident.status {
                    IncidentStatus::Open => "open",
                    IncidentStatus::Closed => "closed",
                }),
                escape_html(&incident.priority),
                if incident.feature_present {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        html.push_str("</tbody>\n</table>\n</section>\n</main>\n</body>\n</html>\n");
        html
    }
}

fn union_bounds(features: &[GeoFeatureRecord]) -> Result<BoundingBox, MapError> {
    let mut bounds = BoundingBox {
        min_lon: f64::INFINITY,
        min_lat: f64::INFINITY,
        max_lon: f64::NEG_INFINITY,
        max_lat: f64::NEG_INFINITY,
    };
    for feature in features {
        let bbox = feature
            .bbox
            .ok_or_else(|| MapError::MissingBoundingBox(feature.id.clone()))?;
        bounds.min_lon = bounds.min_lon.min(bbox.min_lon);
        bounds.min_lat = bounds.min_lat.min(bbox.min_lat);
        bounds.max_lon = bounds.max_lon.max(bbox.max_lon);
        bounds.max_lat = bounds.max_lat.max(bbox.max_lat);
    }
    Ok(bounds)
}

fn padded_bounds(mut bounds: BoundingBox) -> BoundingBox {
    let lon_span = (bounds.max_lon - bounds.min_lon).abs().max(0.01);
    let lat_span = (bounds.max_lat - bounds.min_lat).abs().max(0.01);
    let lon_pad = lon_span * 0.08;
    let lat_pad = lat_span * 0.08;
    bounds.min_lon -= lon_pad;
    bounds.max_lon += lon_pad;
    bounds.min_lat -= lat_pad;
    bounds.max_lat += lat_pad;
    bounds
}

fn grid_svg() -> String {
    let mut svg = String::new();
    for i in 0..=4 {
        let ratio = f64::from(i) / 4.0;
        let x = PADDING + ratio * (WIDTH - PADDING * 2.0);
        let y = PADDING + ratio * (HEIGHT - PADDING * 2.0);
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{x:.2}\" y1=\"{PADDING}\" x2=\"{x:.2}\" y2=\"{}\" />\n",
            HEIGHT - PADDING
        ));
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{PADDING}\" y1=\"{y:.2}\" x2=\"{}\" y2=\"{y:.2}\" />\n",
            WIDTH - PADDING
        ));
    }
    svg
}

fn element_id(input: &str) -> String {
    let mut out = String::from("feature-");
    for character in input.chars() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            out.push(character);
        } else {
            out.push('-');
        }
    }
    out
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn metric(label: &str, value: usize) -> String {
    format!(
        "<div class=\"metric\"><b>{}</b>{}</div>\n",
        value,
        escape_html(label)
    )
}

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("feature record line {line} JSON failed: {error}")]
    FeatureLineJson {
        line: usize,
        error: serde_json::Error,
    },
    #[error("feature set is empty")]
    EmptyFeatureSet,
    #[error("feature {0} has no bounding box")]
    MissingBoundingBox(String),
}

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use super::*;

    fn feature(id: &str, bbox: BoundingBox) -> GeoFeatureRecord {
        GeoFeatureRecord {
            id: id.to_owned(),
            geometry_type: "Point".to_owned(),
            bbox: Some(bbox),
            properties: Map::new(),
            digest: format!("{id}-digest"),
        }
    }

    #[test]
    fn renders_html_map_from_feature_records() {
        let records = [
            feature(
                "river-east",
                BoundingBox {
                    min_lon: 72.1,
                    min_lat: 31.1,
                    max_lon: 72.1,
                    max_lat: 31.1,
                },
            ),
            feature(
                "sector-7",
                BoundingBox {
                    min_lon: 72.2,
                    min_lat: 31.2,
                    max_lon: 72.4,
                    max_lat: 31.4,
                },
            ),
        ];
        let input = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");

        let document = MapDocument::from_json_lines(&input, "Flood Watch").unwrap();
        let html = document.to_html();

        assert_eq!(document.features.len(), 2);
        assert!(html.contains("<svg"));
        assert!(html.contains("river-east"));
        assert!(html.contains("feature-rect"));
        assert!(html.contains("feature-point"));
    }

    #[test]
    fn rejects_empty_feature_records() {
        assert!(matches!(
            MapDocument::from_json_lines("", "empty"),
            Err(MapError::EmptyFeatureSet)
        ));
    }

    #[test]
    fn escapes_feature_text() {
        let input = serde_json::to_string(&GeoFeatureRecord {
            id: "river<script>".to_owned(),
            geometry_type: "Point".to_owned(),
            bbox: Some(BoundingBox {
                min_lon: 1.0,
                min_lat: 2.0,
                max_lon: 1.0,
                max_lat: 2.0,
            }),
            properties: Map::new(),
            digest: "abc".to_owned(),
        })
        .unwrap();

        let html = MapDocument::from_json_lines(&input, "A < B")
            .unwrap()
            .to_html();

        assert!(html.contains("A &lt; B"));
        assert!(html.contains("river&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn renders_console_with_state_overlay() {
        use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};
        use serde_json::json;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "flood-watch",
                Priority::Elevated,
                json!({"mission": "flood-watch"}),
            ))
            .unwrap();
        ledger
            .append(CommandRequest::new(
                Actor::new("lead", Role::IncidentCommander),
                Action::DeclareIncident,
                "river-east",
                Priority::Critical,
                json!({"water_level_m": 5.2}),
            ))
            .unwrap();
        let state = MissionState::from_ledger(&ledger).unwrap();
        let input = serde_json::to_string(&feature(
            "river-east",
            BoundingBox {
                min_lon: 72.1,
                min_lat: 31.1,
                max_lon: 72.1,
                max_lat: 31.1,
            },
        ))
        .unwrap();

        let html = MapConsoleDocument::from_json_lines_and_state(&input, "Flood Watch", &state)
            .unwrap()
            .to_html();

        assert!(html.contains("Flood Watch"));
        assert!(html.contains("river-east"));
        assert!(html.contains("status-open"));
        assert!(html.contains("<b>1</b>Open"));
    }
}
