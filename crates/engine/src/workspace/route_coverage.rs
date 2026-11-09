//! The saved scope and boundaries of a website's route capture.

use craft_anything_evidence::ToolError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u32 = 1;
pub const FILE: &str = "routes-coverage.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RouteResourceLimits {
    pub retained_routes: usize,
    pub frontier_routes: usize,
    pub visited_routes: usize,
    pub capture_json_bytes: u64,
    pub route_manifest_bytes: u64,
    pub url_bytes: usize,
    pub links_per_page: usize,
    pub prompt_routes: usize,
}

impl Default for RouteResourceLimits {
    fn default() -> Self {
        Self {
            retained_routes: 256,
            frontier_routes: 256,
            visited_routes: 4096,
            capture_json_bytes: 8 * 1024 * 1024,
            route_manifest_bytes: 4 * 1024 * 1024,
            url_bytes: 2048,
            links_per_page: 16_384,
            prompt_routes: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RouteCoverage {
    pub version: u32,
    /// Budget for successful captures, not attempts. None removes it; Some(0) captures no other pages.
    pub max_pages: Option<usize>,
    /// None means no depth budget; the start page's links have depth one.
    pub max_depth: Option<usize>,
    pub attempted: usize,
    pub captured: usize,
    pub failed: usize,
    pub redirected_outside_origin: usize,
    pub discovered: usize,
    /// Named reasons that traversal stopped or omitted work, including count/depth, resource
    /// bounds, failed captures and cancellation. An empty list means the discovered queue ended.
    pub boundaries: Vec<String>,
    pub resource_limits: RouteResourceLimits,
}

impl Default for RouteCoverage {
    fn default() -> Self {
        Self {
            version: VERSION,
            max_pages: Some(4),
            max_depth: Some(2),
            attempted: 0,
            captured: 0,
            failed: 0,
            redirected_outside_origin: 0,
            discovered: 0,
            boundaries: Vec::new(),
            resource_limits: RouteResourceLimits::default(),
        }
    }
}

impl RouteCoverage {
    pub fn boundary(&mut self, reason: &str) {
        if !self.boundaries.iter().any(|r| r == reason) {
            self.boundaries.push(reason.to_string());
        }
    }

    /// Read supported versions without treating a future format as complete coverage.
    pub fn from_value(mut value: Value) -> Result<Self, ToolError> {
        let version = value.get("version").map_or(Some(0), Value::as_u64).ok_or_else(|| ToolError::invalid("Route coverage has an invalid version."))?;
        if version > u64::from(VERSION) {
            return Err(ToolError::invalid("Route coverage is from a newer Craft Anything."));
        }
        if version == 0 {
            let object = value.as_object_mut().ok_or_else(|| ToolError::invalid("Route coverage must be an object."))?;
            object.insert("version".into(), Value::from(VERSION));
        }
        serde_json::from_value(value).map_err(|e| ToolError::invalid(format!("Couldn't read route coverage: {e}")))
    }
}

pub fn route_coverage_schema() -> String {
    let schema = schemars::generate::SchemaSettings::draft2020_12().into_generator().into_root_schema_for::<RouteCoverage>();
    serde_json::to_string_pretty(&schema).map(|s| s + "\n").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_versions_keep_zero_and_unlimited_distinct() {
        let old = RouteCoverage::from_value(serde_json::json!({"max_pages": 0})).unwrap();
        assert_eq!((old.version, old.max_pages), (VERSION, Some(0)));
        let current = RouteCoverage { max_pages: None, max_depth: None, ..Default::default() };
        assert_eq!(RouteCoverage::from_value(serde_json::to_value(&current).unwrap()).unwrap(), current);
        assert!(RouteCoverage::from_value(serde_json::json!({"version": VERSION + 1})).is_err());
        assert!(RouteCoverage::from_value(serde_json::json!({"version": -1})).is_err());
    }
}
