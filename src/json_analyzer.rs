//! JSON structured log analyzer.
//!
//! Parses each line as JSON, builds a statistical schema profile
//! (field presence, types, value distributions), and scores records
//! by structural deviation: missing fields, rare values, unusual
//! field combinations, type mismatches.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::anomaly::{mean, median_of, sample_stdev};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fields with more unique values than this are treated as high-cardinality
/// and excluded from value-based scoring.
const HIGH_CARDINALITY_THRESHOLD: usize = 100;

/// Fields present in more than this fraction of records are "common".
const COMMON_FIELD_THRESHOLD: f64 = 0.5;

/// Fields present in fewer than this fraction of records are "rare".
const RARE_FIELD_THRESHOLD: f64 = 0.05;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonType {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

impl std::fmt::Display for JsonType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonType::Null => write!(f, "null"),
            JsonType::Bool => write!(f, "bool"),
            JsonType::Number => write!(f, "number"),
            JsonType::String => write!(f, "string"),
            JsonType::Array => write!(f, "array"),
            JsonType::Object => write!(f, "object"),
        }
    }
}

/// A parsed JSON record (one log line).
#[derive(Debug)]
pub struct JsonRecord {
    pub offset: usize,
    pub length: usize,
    pub value: Option<Value>,
    pub parse_error: bool,
}

impl JsonRecord {
    #[inline]
    pub fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.offset..self.offset + self.length]
    }
}

/// Statistics for a single field across all records.
#[derive(Debug, Clone)]
pub struct FieldProfile {
    pub name: String,
    pub present_count: usize,
    pub presence_rate: f64,
    pub type_counts: HashMap<JsonType, usize>,
    pub dominant_type: JsonType,
    pub value_counts: HashMap<String, usize>,
    pub unique_values: usize,
    pub is_low_cardinality: bool,
}

/// Schema profile built from all records.
#[derive(Debug)]
pub struct SchemaProfile {
    pub total_records: usize,
    pub valid_records: usize,
    pub parse_errors: usize,
    pub fields: HashMap<String, FieldProfile>,
    /// Count of each unique field-name set.
    pub field_set_counts: HashMap<Vec<String>, usize>,
    /// The most common field set.
    pub common_field_set: Vec<String>,
}

/// Scored JSON record with explanations of why it's anomalous.
#[derive(Debug, Clone)]
pub struct JsonRecordScore {
    pub index: usize,
    pub offset: usize,
    pub length: usize,
    pub valid_json: bool,
    pub field_count: usize,
    /// Common fields that are missing from this record.
    pub missing_common: Vec<String>,
    /// Rare fields present in this record.
    pub extra_rare: Vec<String>,
    /// (field, value) pairs with low frequency in the corpus.
    pub rare_values: Vec<(String, String)>,
    /// (field, expected_type, actual_type) mismatches.
    pub type_mismatches: Vec<(String, JsonType, JsonType)>,
    pub anomaly_score: f64,
}

impl JsonRecordScore {
    #[inline]
    pub fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.offset..self.offset + self.length]
    }
}

/// Aggregate report for JSON anomaly analysis.
#[derive(Debug, Clone)]
pub struct JsonAnomalyReport {
    pub total_records: usize,
    pub valid_records: usize,
    pub parse_errors: usize,
    pub total_bytes: usize,
    pub field_count: usize,
    pub mean_score: f64,
    pub median_score: f64,
    pub stdev_score: f64,
    pub threshold: f64,
    pub anomaly_count: usize,
    /// Indices into the scored records, sorted by score descending.
    pub anomaly_indices: Vec<usize>,
}

impl JsonAnomalyReport {
    pub fn anomaly_rate(&self) -> f64 {
        if self.total_records == 0 {
            return 0.0;
        }
        self.anomaly_count as f64 / self.total_records as f64
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn value_type(v: &Value) -> JsonType {
    match v {
        Value::Null => JsonType::Null,
        Value::Bool(_) => JsonType::Bool,
        Value::Number(_) => JsonType::Number,
        Value::String(_) => JsonType::String,
        Value::Array(_) => JsonType::Array,
        Value::Object(_) => JsonType::Object,
    }
}

fn value_to_key(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/// Parse each line of `data` as JSON.
pub fn parse_json_records(data: &[u8], delimiter: u8) -> Vec<JsonRecord> {
    let mut records = Vec::new();
    let mut start = 0;

    for (i, &b) in data.iter().enumerate() {
        if b == delimiter {
            let length = i + 1 - start;
            let line = &data[start..i]; // exclude delimiter for parsing
            let trimmed = trim_ascii(line);
            if !trimmed.is_empty() {
                let (value, err) = match serde_json::from_slice::<Value>(trimmed) {
                    Ok(v) => (Some(v), false),
                    Err(_) => (None, true),
                };
                records.push(JsonRecord {
                    offset: start,
                    length,
                    value,
                    parse_error: err,
                });
            }
            start = i + 1;
        }
    }
    // Trailing line without delimiter
    if start < data.len() {
        let line = &data[start..];
        let trimmed = trim_ascii(line);
        if !trimmed.is_empty() {
            let (value, err) = match serde_json::from_slice::<Value>(trimmed) {
                Ok(v) => (Some(v), false),
                Err(_) => (None, true),
            };
            records.push(JsonRecord {
                offset: start,
                length: data.len() - start,
                value,
                parse_error: err,
            });
        }
    }

    records
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|&b| !b.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &s[start..end]
}

/// Returns true if the first non-empty line of `data` parses as a JSON object.
pub fn looks_like_json(data: &[u8]) -> bool {
    let first_line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let line = trim_ascii(&data[..first_line_end]);
    if line.is_empty() {
        return false;
    }
    matches!(serde_json::from_slice::<Value>(line), Ok(Value::Object(_)))
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Build a schema profile from parsed JSON records.
pub fn build_schema(records: &[JsonRecord]) -> SchemaProfile {
    let total = records.len();
    let mut valid = 0usize;
    let mut fields: HashMap<String, FieldProfile> = HashMap::new();
    let mut field_set_counts: HashMap<Vec<String>, usize> = HashMap::new();

    for rec in records {
        let map = match &rec.value {
            Some(Value::Object(m)) => {
                valid += 1;
                m
            }
            _ => continue,
        };

        // Track field set
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        *field_set_counts.entry(keys).or_insert(0) += 1;

        // Track per-field stats
        for (key, val) in map {
            let profile = fields.entry(key.clone()).or_insert_with(|| FieldProfile {
                name: key.clone(),
                present_count: 0,
                presence_rate: 0.0,
                type_counts: HashMap::new(),
                dominant_type: JsonType::Null,
                value_counts: HashMap::new(),
                unique_values: 0,
                is_low_cardinality: true,
            });
            profile.present_count += 1;
            *profile.type_counts.entry(value_type(val)).or_insert(0) += 1;

            let vkey = value_to_key(val);
            *profile.value_counts.entry(vkey).or_insert(0) += 1;
        }
    }

    // Compute derived stats
    let total_f = total.max(1) as f64;
    for profile in fields.values_mut() {
        profile.presence_rate = profile.present_count as f64 / total_f;
        profile.unique_values = profile.value_counts.len();
        profile.is_low_cardinality = profile.unique_values <= HIGH_CARDINALITY_THRESHOLD;

        // Dominant type = most common type
        profile.dominant_type = profile
            .type_counts
            .iter()
            .max_by_key(|(_, &c)| c)
            .map(|(&t, _)| t)
            .unwrap_or(JsonType::Null);
    }

    // Most common field set
    let common_field_set = field_set_counts
        .iter()
        .max_by_key(|(_, &c)| c)
        .map(|(k, _)| k.clone())
        .unwrap_or_default();

    SchemaProfile {
        total_records: total,
        valid_records: valid,
        parse_errors: total - valid,
        fields,
        field_set_counts,
        common_field_set,
    }
}

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

/// Score each JSON record against the schema profile.
pub fn score_json_records(
    _data: &[u8],
    records: &[JsonRecord],
    schema: &SchemaProfile,
) -> Vec<JsonRecordScore> {
    let total_f = schema.total_records.max(1) as f64;

    // Identify common and rare fields
    let common_fields: Vec<&str> = schema
        .fields
        .iter()
        .filter(|(_, p)| p.presence_rate > COMMON_FIELD_THRESHOLD)
        .map(|(k, _)| k.as_str())
        .collect();

    let n_common = common_fields.len().max(1) as f64;

    let mut scores = Vec::with_capacity(records.len());

    for (idx, rec) in records.iter().enumerate() {
        let map = match &rec.value {
            Some(Value::Object(m)) => m,
            _ => {
                // Not a valid JSON object — maximally anomalous
                scores.push(JsonRecordScore {
                    index: idx,
                    offset: rec.offset,
                    length: rec.length,
                    valid_json: false,
                    field_count: 0,
                    missing_common: common_fields.iter().map(|&s| s.to_string()).collect(),
                    extra_rare: Vec::new(),
                    rare_values: Vec::new(),
                    type_mismatches: Vec::new(),
                    anomaly_score: 1.0,
                });
                continue;
            }
        };

        let keys: HashSet<&str> = map.keys().map(|s| s.as_str()).collect();

        // Missing common fields
        let missing: Vec<String> = common_fields
            .iter()
            .filter(|&&f| !keys.contains(f))
            .map(|&f| f.to_string())
            .collect();

        // Extra rare fields
        let extra: Vec<String> = keys
            .iter()
            .filter(|&&k| {
                schema
                    .fields
                    .get(k)
                    .map(|p| p.presence_rate < RARE_FIELD_THRESHOLD)
                    .unwrap_or(true)
            })
            .map(|&k| k.to_string())
            .collect();

        // Type mismatches
        let mut type_mismatches = Vec::new();
        for (key, val) in map {
            if let Some(profile) = schema.fields.get(key.as_str()) {
                let actual = value_type(val);
                if actual != profile.dominant_type {
                    type_mismatches.push((
                        key.clone(),
                        profile.dominant_type,
                        actual,
                    ));
                }
            }
        }

        // Rare values (only for low-cardinality fields)
        let mut rare_values = Vec::new();
        let mut value_rarity_sum = 0.0;
        let mut value_rarity_n = 0usize;

        for (key, val) in map {
            if let Some(profile) = schema.fields.get(key.as_str()) {
                if profile.is_low_cardinality {
                    let vkey = value_to_key(val);
                    let count = profile.value_counts.get(&vkey).copied().unwrap_or(0);
                    let freq = count as f64 / profile.present_count.max(1) as f64;
                    value_rarity_sum += 1.0 - freq;
                    value_rarity_n += 1;
                    if freq < 0.01 {
                        rare_values.push((key.clone(), vkey));
                    }
                }
            }
        }

        let avg_value_rarity = if value_rarity_n > 0 {
            value_rarity_sum / value_rarity_n as f64
        } else {
            0.0
        };

        // Field set novelty
        let mut keys_sorted: Vec<String> = map.keys().cloned().collect();
        keys_sorted.sort();
        let set_count = schema.field_set_counts.get(&keys_sorted).copied().unwrap_or(0);
        let set_novelty = 1.0 - (set_count as f64 / total_f);

        // Missing score
        let missing_score = missing.len() as f64 / n_common;

        // Extra score
        let extra_score = if keys.is_empty() {
            0.0
        } else {
            extra.len() as f64 / keys.len() as f64
        };

        // Type mismatch score
        let type_score = if map.is_empty() {
            0.0
        } else {
            type_mismatches.len() as f64 / map.len() as f64
        };

        // Weighted combination
        let anomaly_score = 0.30 * missing_score
            + 0.25 * avg_value_rarity
            + 0.25 * set_novelty
            + 0.10 * extra_score
            + 0.10 * type_score;

        scores.push(JsonRecordScore {
            index: idx,
            offset: rec.offset,
            length: rec.length,
            valid_json: true,
            field_count: map.len(),
            missing_common: missing,
            extra_rare: extra,
            rare_values,
            type_mismatches,
            anomaly_score,
        });
    }

    scores
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Build an anomaly report from scored JSON records.
pub fn build_json_report(
    records: &[JsonRecord],
    scored: &[JsonRecordScore],
    schema: &SchemaProfile,
    threshold_used: f64,
    anomaly_indices: Vec<usize>,
) -> JsonAnomalyReport {
    let total_bytes: usize = records.iter().map(|r| r.length).sum();
    let scores: Vec<f64> = scored.iter().map(|s| s.anomaly_score).collect();

    JsonAnomalyReport {
        total_records: records.len(),
        valid_records: schema.valid_records,
        parse_errors: schema.parse_errors,
        total_bytes,
        field_count: schema.fields.len(),
        mean_score: mean(&scores),
        median_score: median_of(&scores),
        stdev_score: sample_stdev(&scores, mean(&scores)),
        threshold: threshold_used,
        anomaly_count: anomaly_indices.len(),
        anomaly_indices,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::{detect_indices, DetectionMethod};

    fn json_lines(lines: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for line in lines {
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        buf
    }

    #[test]
    fn parse_valid_json() {
        let data = json_lines(&[
            r#"{"level":"INFO","msg":"ok"}"#,
            r#"{"level":"ERROR","msg":"fail"}"#,
        ]);
        let recs = parse_json_records(&data, b'\n');
        assert_eq!(recs.len(), 2);
        assert!(!recs[0].parse_error);
        assert!(!recs[1].parse_error);
    }

    #[test]
    fn parse_invalid_json() {
        let data = json_lines(&[
            r#"{"level":"INFO"}"#,
            "not json at all",
            r#"{"level":"ERROR"}"#,
        ]);
        let recs = parse_json_records(&data, b'\n');
        assert_eq!(recs.len(), 3);
        assert!(!recs[0].parse_error);
        assert!(recs[1].parse_error);
        assert!(!recs[2].parse_error);
    }

    #[test]
    fn looks_like_json_detect() {
        assert!(looks_like_json(br#"{"key":"value"}"#));
        assert!(!looks_like_json(b"Feb 16 server sshd: hello"));
        assert!(!looks_like_json(b""));
    }

    #[test]
    fn schema_field_presence() {
        let data = json_lines(&[
            r#"{"a":1,"b":2,"c":3}"#,
            r#"{"a":1,"b":2,"c":3}"#,
            r#"{"a":1,"b":2}"#,
        ]);
        let recs = parse_json_records(&data, b'\n');
        let schema = build_schema(&recs);
        assert_eq!(schema.total_records, 3);
        assert_eq!(schema.valid_records, 3);
        assert_eq!(schema.fields["a"].present_count, 3);
        assert_eq!(schema.fields["c"].present_count, 2);
    }

    #[test]
    fn schema_dominant_type() {
        let data = json_lines(&[
            r#"{"x":"hello"}"#,
            r#"{"x":"world"}"#,
            r#"{"x":42}"#,
        ]);
        let recs = parse_json_records(&data, b'\n');
        let schema = build_schema(&recs);
        assert_eq!(schema.fields["x"].dominant_type, JsonType::String);
    }

    #[test]
    fn missing_field_scores_high() {
        let mut lines: Vec<&str> = Vec::new();
        let normal = r#"{"level":"INFO","service":"app","msg":"ok"}"#;
        for _ in 0..20 {
            lines.push(normal);
        }
        // Missing "service" and "msg"
        lines.push(r#"{"level":"ERROR"}"#);

        let data = json_lines(&lines);
        let recs = parse_json_records(&data, b'\n');
        let schema = build_schema(&recs);
        let scored = score_json_records(&data, &recs, &schema);

        let anomaly = &scored[20];
        assert!(!anomaly.missing_common.is_empty());
        let avg_normal: f64 = scored[..20].iter().map(|s| s.anomaly_score).sum::<f64>() / 20.0;
        assert!(
            anomaly.anomaly_score > avg_normal,
            "anomaly {:.4} should be > avg normal {:.4}",
            anomaly.anomaly_score,
            avg_normal
        );
    }

    #[test]
    fn rare_value_detected() {
        let mut lines: Vec<&str> = Vec::new();
        for _ in 0..200 {
            lines.push(r#"{"level":"INFO","msg":"ok"}"#);
        }
        lines.push(r#"{"level":"FATAL","msg":"segfault"}"#);

        let data = json_lines(&lines);
        let recs = parse_json_records(&data, b'\n');
        let schema = build_schema(&recs);
        let scored = score_json_records(&data, &recs, &schema);

        let anomaly = &scored[200];
        assert!(
            anomaly.rare_values.iter().any(|(f, _)| f == "level"),
            "expected 'level' in rare_values"
        );
    }

    #[test]
    fn type_mismatch_detected() {
        let mut lines: Vec<&str> = Vec::new();
        for _ in 0..20 {
            lines.push(r#"{"status":200,"msg":"ok"}"#);
        }
        // status is string instead of number
        lines.push(r#"{"status":"error","msg":"fail"}"#);

        let data = json_lines(&lines);
        let recs = parse_json_records(&data, b'\n');
        let schema = build_schema(&recs);
        let scored = score_json_records(&data, &recs, &schema);

        let anomaly = &scored[20];
        assert!(
            anomaly.type_mismatches.iter().any(|(f, _, _)| f == "status"),
            "expected type mismatch on 'status'"
        );
    }

    #[test]
    fn integration_with_detect_indices() {
        let mut lines: Vec<&str> = Vec::new();
        for _ in 0..50 {
            lines.push(r#"{"level":"INFO","service":"app","msg":"request handled"}"#);
        }
        lines.push(r#"{"level":"FATAL","error_code":42}"#);

        let data = json_lines(&lines);
        let recs = parse_json_records(&data, b'\n');
        let schema = build_schema(&recs);
        let scored = score_json_records(&data, &recs, &schema);

        let scores: Vec<f64> = scored.iter().map(|s| s.anomaly_score).collect();
        let (_, indices) = detect_indices(&scores, None, DetectionMethod::Top, None, Some(3));

        assert!(indices.contains(&50), "line 50 should be in top-3 anomalies");
    }
}
