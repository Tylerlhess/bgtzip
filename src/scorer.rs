//! Per-record scoring for anomaly detection.
//!
//! Splits input into records by delimiter, maps LZ77 scan operations onto
//! each record, and computes coverage and profile statistics.

use std::collections::HashMap;

use crate::dictionary::DictEntry;
use crate::scanner::{OpKind, ScanOp};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RecordAnalysis {
    pub index: usize,
    pub offset: usize,
    pub length: usize,
    pub backref_bytes: usize,
    pub literal_bytes: usize,
    /// Fraction of bytes covered by back-references (0.0 = all literal).
    pub coverage: f64,
    /// Dictionary entry IDs referenced by this record (sorted, deduplicated).
    pub ref_entries: Vec<usize>,
    /// Anomaly score — higher means more anomalous.
    pub anomaly_score: f64,
}

impl RecordAnalysis {
    /// Return the byte content of this record.
    #[inline]
    pub fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.offset..self.offset + self.length]
    }
}

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

/// Score each record in `data` using scan operations and the dictionary.
///
/// Returns one `RecordAnalysis` per record with coverage stats and a
/// preliminary anomaly score.
pub fn score_records(
    data: &[u8],
    ops: &[ScanOp],
    dictionary: &[DictEntry],
    delimiter: u8,
) -> Vec<RecordAnalysis> {
    if data.is_empty() {
        return Vec::new();
    }

    // --- Split input into records ---
    let mut records: Vec<(usize, usize)> = Vec::new(); // (offset, length)
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == delimiter {
            records.push((start, i + 1 - start));
            start = i + 1;
        }
    }
    if start < data.len() {
        records.push((start, data.len() - start));
    }
    if records.is_empty() {
        return Vec::new();
    }

    let content_to_entry: HashMap<&[u8], usize> = dictionary
        .iter()
        .map(|e| (e.content.as_slice(), e.entry_id))
        .collect();
    let dict_size = dictionary.len().max(1);

    // --- Build byte-level coverage array ---
    let mut covered = vec![false; data.len()];

    // Pre-compute backref info for the record loop
    struct BrInfo {
        start: usize,
        end: usize,
        entry_id: Option<usize>,
    }
    let mut br_infos: Vec<BrInfo> = Vec::new();

    for op in ops {
        if op.kind == OpKind::Backref {
            let end = (op.position + op.length).min(data.len());
            for i in op.position..end {
                covered[i] = true;
            }
            let eid = content_to_entry.get(op.content(data)).copied();
            br_infos.push(BrInfo {
                start: op.position,
                end,
                entry_id: eid,
            });
        }
    }

    // --- Score each record ---
    let mut analyses = Vec::with_capacity(records.len());
    let mut br_cursor: usize = 0;

    for (rec_idx, &(rec_off, rec_len)) in records.iter().enumerate() {
        let rec_end = rec_off + rec_len;

        // Count backref bytes
        let backref_bytes = (rec_off..rec_end).filter(|&i| covered[i]).count();
        let literal_bytes = rec_len - backref_bytes;
        let cov = if rec_len > 0 {
            backref_bytes as f64 / rec_len as f64
        } else {
            0.0
        };

        // Advance cursor past ops that end before this record
        while br_cursor < br_infos.len() && br_infos[br_cursor].end <= rec_off {
            br_cursor += 1;
        }

        // Collect dictionary entries referenced within this record
        let mut ref_entries: Vec<usize> = Vec::new();
        let mut j = br_cursor;
        while j < br_infos.len() && br_infos[j].start < rec_end {
            if br_infos[j].end > rec_off {
                if let Some(eid) = br_infos[j].entry_id {
                    ref_entries.push(eid);
                }
            }
            j += 1;
        }
        ref_entries.sort_unstable();
        ref_entries.dedup();

        // Anomaly score: 70% coverage, 30% rarity
        let coverage_score = 1.0 - cov;
        let rarity_score = if ref_entries.is_empty() {
            1.0
        } else {
            ref_entries.iter().map(|&eid| eid as f64 / dict_size as f64).sum::<f64>()
                / ref_entries.len() as f64
        };
        let anomaly_score = 0.7 * coverage_score + 0.3 * rarity_score;

        analyses.push(RecordAnalysis {
            index: rec_idx,
            offset: rec_off,
            length: rec_len,
            backref_bytes,
            literal_bytes,
            coverage: cov,
            ref_entries,
            anomaly_score,
        });
    }

    analyses
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::build_dictionary;
    use crate::scanner::{scan, DEFAULT_WINDOW, MAX_MATCH, MIN_MATCH};

    fn pipeline(data: &[u8]) -> Vec<RecordAnalysis> {
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(data, &ops, 1);
        score_records(data, &ops, &dict, b'\n')
    }

    #[test]
    fn empty_input() {
        assert!(pipeline(b"").is_empty());
    }

    #[test]
    fn single_record() {
        let data = b"one line only\n";
        let recs = pipeline(data);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].length, data.len());
    }

    #[test]
    fn record_count() {
        let recs = pipeline(b"line1\nline2\nline3\n");
        assert_eq!(recs.len(), 3);
    }

    #[test]
    fn coverage_bounded() {
        let data: Vec<u8> = (0..20)
            .map(|i| format!("test record number {i} here\n"))
            .collect::<String>()
            .into_bytes();
        for r in pipeline(&data) {
            assert!((0.0..=1.0).contains(&r.coverage));
        }
    }

    #[test]
    fn bytes_add_up() {
        let data: Vec<u8> = b"log entry with some repeated data in it\n".repeat(10);
        for r in pipeline(&data) {
            assert_eq!(r.backref_bytes + r.literal_bytes, r.length);
        }
    }

    #[test]
    fn unique_line_scores_higher() {
        let mut data: Vec<u8> = b"normal log line pattern data\n".repeat(20);
        data.extend_from_slice(b"CRITICAL: unexpected kernel panic at 0xDEAD\n");
        let recs = pipeline(&data);
        let avg_normal: f64 =
            recs[..20].iter().map(|r| r.anomaly_score).sum::<f64>() / 20.0;
        let anomaly = recs.last().unwrap().anomaly_score;
        assert!(anomaly > avg_normal);
    }

    #[test]
    fn offsets_contiguous() {
        let recs = pipeline(b"line 1\nline 2\nline 3\n");
        for i in 1..recs.len() {
            assert_eq!(recs[i].offset, recs[i - 1].offset + recs[i - 1].length);
        }
    }

    #[test]
    fn content_matches_data() {
        let data = b"alpha\nbeta\ngamma\n";
        for r in pipeline(data) {
            assert_eq!(r.content(data), &data[r.offset..r.offset + r.length]);
        }
    }
}
