//! Anomaly detection and reporting.
//!
//! Takes scored records and applies statistical thresholding to identify
//! lines that deviate from normal patterns found by the LZ77 scanner.

use crate::scorer::RecordAnalysis;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    /// Flag records with anomaly_score above mean + k*stdev.
    Score,
    /// Flag records with coverage below mean - k*stdev.
    Coverage,
    /// Flag the top N% of records by anomaly score.
    Percentile,
    /// Return the top N most anomalous records.
    Top,
}

#[derive(Debug, Clone)]
pub struct AnomalyReport {
    pub total_records: usize,
    pub total_bytes: usize,
    pub dict_entry_count: usize,
    pub mean_coverage: f64,
    pub median_coverage: f64,
    pub stdev_coverage: f64,
    pub threshold: f64,
    pub anomaly_count: usize,
    /// Indices into the original records slice, sorted by score descending.
    pub anomaly_indices: Vec<usize>,
}

impl AnomalyReport {
    pub fn anomaly_rate(&self) -> f64 {
        if self.total_records == 0 {
            return 0.0;
        }
        self.anomaly_count as f64 / self.total_records as f64
    }
}

// ---------------------------------------------------------------------------
// Statistics helpers
// ---------------------------------------------------------------------------

fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().sum::<f64>() / vals.len() as f64
}

fn median_sorted(vals: &mut Vec<f64>) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = vals.len();
    if n % 2 == 0 {
        (vals[n / 2 - 1] + vals[n / 2]) / 2.0
    } else {
        vals[n / 2]
    }
}

fn sample_stdev(vals: &[f64], m: f64) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let var: f64 = vals.iter().map(|&x| (x - m).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    var.sqrt()
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Detect anomalous records using the specified method.
pub fn detect_anomalies(
    records: &[RecordAnalysis],
    dict_entry_count: usize,
    method: DetectionMethod,
    threshold: Option<f64>,
    top_n: Option<usize>,
) -> AnomalyReport {
    let empty = AnomalyReport {
        total_records: 0,
        total_bytes: 0,
        dict_entry_count,
        mean_coverage: 0.0,
        median_coverage: 0.0,
        stdev_coverage: 0.0,
        threshold: 0.0,
        anomaly_count: 0,
        anomaly_indices: Vec::new(),
    };
    if records.is_empty() {
        return empty;
    }

    let total_bytes: usize = records.iter().map(|r| r.length).sum();
    let coverages: Vec<f64> = records.iter().map(|r| r.coverage).collect();
    let scores: Vec<f64> = records.iter().map(|r| r.anomaly_score).collect();

    let mean_cov = mean(&coverages);
    let mut cov_copy = coverages.clone();
    let median_cov = median_sorted(&mut cov_copy);
    let stdev_cov = sample_stdev(&coverages, mean_cov);

    let (threshold_used, mut anomaly_idx) = match method {
        DetectionMethod::Score => {
            let ms = mean(&scores);
            let ss = sample_stdev(&scores, ms);
            let t = threshold.unwrap_or(ms + 1.5 * ss);
            let idx: Vec<usize> = records
                .iter()
                .enumerate()
                .filter(|(_, r)| r.anomaly_score >= t)
                .map(|(i, _)| i)
                .collect();
            (t, idx)
        }
        DetectionMethod::Coverage => {
            let t = threshold.unwrap_or((mean_cov - 1.5 * stdev_cov).max(0.0));
            let idx: Vec<usize> = records
                .iter()
                .enumerate()
                .filter(|(_, r)| r.coverage <= t)
                .map(|(i, _)| i)
                .collect();
            (t, idx)
        }
        DetectionMethod::Percentile => {
            let pct = threshold.unwrap_or(0.05);
            let n = ((records.len() as f64 * pct).ceil() as usize).max(1);
            let mut by_score: Vec<usize> = (0..records.len()).collect();
            by_score.sort_by(|&a, &b| {
                records[b]
                    .anomaly_score
                    .partial_cmp(&records[a].anomaly_score)
                    .unwrap()
            });
            by_score.truncate(n);
            (pct, by_score)
        }
        DetectionMethod::Top => {
            let n = top_n.unwrap_or(10);
            let mut by_score: Vec<usize> = (0..records.len()).collect();
            by_score.sort_by(|&a, &b| {
                records[b]
                    .anomaly_score
                    .partial_cmp(&records[a].anomaly_score)
                    .unwrap()
            });
            by_score.truncate(n);
            let t = by_score
                .last()
                .map(|&i| records[i].anomaly_score)
                .unwrap_or(0.0);
            (t, by_score)
        }
    };

    // Sort anomalies by score descending
    anomaly_idx.sort_by(|&a, &b| {
        records[b]
            .anomaly_score
            .partial_cmp(&records[a].anomaly_score)
            .unwrap()
    });

    AnomalyReport {
        total_records: records.len(),
        total_bytes,
        dict_entry_count,
        mean_coverage: mean_cov,
        median_coverage: median_cov,
        stdev_coverage: stdev_cov,
        threshold: threshold_used,
        anomaly_count: anomaly_idx.len(),
        anomaly_indices: anomaly_idx,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::build_dictionary;
    use crate::scanner::{scan, DEFAULT_WINDOW, MAX_MATCH, MIN_MATCH};
    use crate::scorer::score_records;

    fn full_pipeline(data: &[u8], method: DetectionMethod, top_n: Option<usize>) -> AnomalyReport {
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(data, &ops, 1);
        let recs = score_records(data, &ops, &dict, b'\n');
        detect_anomalies(&recs, dict.len(), method, None, top_n)
    }

    #[test]
    fn empty() {
        let r = full_pipeline(b"", DetectionMethod::Score, None);
        assert_eq!(r.total_records, 0);
        assert_eq!(r.anomaly_count, 0);
    }

    #[test]
    fn top_n_returns_n() {
        let data: Vec<u8> = b"line data content here\n".repeat(30);
        let r = full_pipeline(&data, DetectionMethod::Top, Some(5));
        assert_eq!(r.anomaly_count, 5);
    }

    #[test]
    fn injected_anomaly_detected() {
        let mut data: Vec<u8> = b"2026-02-16 app: normal operation completed\n".repeat(50);
        data.extend_from_slice(b"KERNEL PANIC: fatal error 0xDEADBEEF segfault\n");
        data.extend_from_slice(&b"2026-02-16 app: normal operation completed\n".repeat(50));

        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(&data, &ops, 1);
        let recs = score_records(&data, &ops, &dict, b'\n');
        let report = detect_anomalies(&recs, dict.len(), DetectionMethod::Top, None, Some(5));

        let anomaly_rec_indices: Vec<usize> = report
            .anomaly_indices
            .iter()
            .map(|&i| recs[i].index)
            .collect();
        assert!(
            anomaly_rec_indices.contains(&50),
            "expected line 50 in anomalies, got {anomaly_rec_indices:?}"
        );
    }

    #[test]
    fn anomalies_sorted_by_score() {
        let mut data: Vec<u8> = b"aaa_repeated_data_content_here\n".repeat(40);
        data.extend_from_slice(b"first unique anomaly string!!\n");
        data.extend_from_slice(b"second completely different anomaly data here longer\n");
        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(&data, &ops, 1);
        let recs = score_records(&data, &ops, &dict, b'\n');
        let report = detect_anomalies(&recs, dict.len(), DetectionMethod::Top, None, Some(10));
        let scores: Vec<f64> = report
            .anomaly_indices
            .iter()
            .map(|&i| recs[i].anomaly_score)
            .collect();
        for w in scores.windows(2) {
            assert!(w[0] >= w[1]);
        }
    }
}
