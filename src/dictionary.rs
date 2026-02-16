//! Dictionary builder for LZ77 analysis.
//!
//! Groups back-references by byte content, counts frequency, and produces
//! a dictionary ordered most-frequent-first (entry 0 = most common pattern).

use std::collections::HashMap;

use crate::scanner::{OpKind, ScanOp};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DictEntry {
    pub entry_id: usize,
    pub content: Vec<u8>,
    pub count: usize,
    /// All positions in the input where this pattern occurs.
    pub positions: Vec<usize>,
}

impl DictEntry {
    #[inline]
    pub fn content_length(&self) -> usize {
        self.content.len()
    }

    #[inline]
    pub fn total_bytes_covered(&self) -> usize {
        self.count * self.content.len()
    }

    pub fn intervals(&self) -> Vec<usize> {
        if self.positions.len() < 2 {
            return Vec::new();
        }
        self.positions.windows(2).map(|w| w[1] - w[0]).collect()
    }

    pub fn median_interval(&self) -> f64 {
        let mut iv = self.intervals();
        if iv.is_empty() {
            return 0.0;
        }
        iv.sort_unstable();
        let n = iv.len();
        if n % 2 == 0 {
            (iv[n / 2 - 1] + iv[n / 2]) as f64 / 2.0
        } else {
            iv[n / 2] as f64
        }
    }

    pub fn mean_interval(&self) -> f64 {
        let iv = self.intervals();
        if iv.is_empty() {
            return 0.0;
        }
        iv.iter().sum::<usize>() as f64 / iv.len() as f64
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build a frequency-ordered dictionary from scan operations.
///
/// Groups backref ops by exact byte content. Each unique pattern that was
/// back-referenced at least `min_count` times becomes an entry. Entries are
/// sorted by count descending (most frequent = `entry_id` 0).
pub fn build_dictionary(data: &[u8], ops: &[ScanOp], min_count: usize) -> Vec<DictEntry> {
    // Count occurrences and collect positions per unique content
    let mut counts: HashMap<&[u8], usize> = HashMap::new();
    let mut positions: HashMap<&[u8], Vec<usize>> = HashMap::new();

    for op in ops {
        if op.kind != OpKind::Backref {
            continue;
        }
        let content = op.content(data);
        *counts.entry(content).or_insert(0) += 1;

        let pos_list = positions.entry(content).or_default();
        pos_list.push(op.position);
        // Also record the match source position
        let src = op.position - op.ref_offset;
        pos_list.push(src);
    }

    // Build entries, filter, sort
    let mut entries: Vec<DictEntry> = counts
        .iter()
        .filter(|(_, &c)| c >= min_count)
        .map(|(&content, &count)| {
            let mut pos = positions[content].clone();
            pos.sort_unstable();
            pos.dedup();
            DictEntry {
                entry_id: 0,
                content: content.to_vec(),
                count,
                positions: pos,
            }
        })
        .collect();

    entries.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.content.len().cmp(&a.content.len()))
    });

    for (i, e) in entries.iter_mut().enumerate() {
        e.entry_id = i;
    }

    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{scan, DEFAULT_WINDOW, MAX_MATCH, MIN_MATCH};

    #[test]
    fn empty_ops() {
        assert!(build_dictionary(b"", &[], 1).is_empty());
    }

    #[test]
    fn no_backrefs_no_entries() {
        let data = b"unique data here";
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        assert!(build_dictionary(data, &ops, 1).is_empty());
    }

    #[test]
    fn frequency_ordering() {
        let a = b"aaaa_pattern_alpha_";
        let b_pat = b"bbbb_pattern_beta__";
        let mut data = Vec::new();
        for _ in 0..10 {
            data.extend_from_slice(a);
        }
        for _ in 0..3 {
            data.extend_from_slice(b_pat);
        }
        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(&data, &ops, 1);
        if dict.len() >= 2 {
            assert!(dict[0].count >= dict[1].count);
        }
    }

    #[test]
    fn entry_ids_sequential() {
        let data: Vec<u8> = b"log line template with data here\n".repeat(20);
        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(&data, &ops, 1);
        for (i, e) in dict.iter().enumerate() {
            assert_eq!(e.entry_id, i);
        }
    }

    #[test]
    fn total_bytes_covered() {
        let data: Vec<u8> = b"bytes_covered_check_".repeat(20);
        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let dict = build_dictionary(&data, &ops, 1);
        for e in &dict {
            assert_eq!(e.total_bytes_covered(), e.count * e.content_length());
        }
    }
}
