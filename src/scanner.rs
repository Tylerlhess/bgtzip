//! LZ77 analysis scanner.
//!
//! Runs LZ77 matching on raw input data and produces a stream of operations
//! (literal runs + back-references) for downstream analysis.

const HASH_BITS: usize = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const HASH_MASK: usize = HASH_SIZE - 1;
const MAX_CHAIN: usize = 64;
const NO_POS: u32 = u32::MAX;

pub const DEFAULT_WINDOW: usize = 32 * 1024;
pub const MIN_MATCH: usize = 4;
pub const MAX_MATCH: usize = 258;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Literal,
    Backref,
}

#[derive(Debug, Clone)]
pub struct ScanOp {
    pub position: usize,
    pub kind: OpKind,
    pub length: usize,
    /// Distance back to match source (0 for literals).
    pub ref_offset: usize,
}

impl ScanOp {
    /// Return the byte content this operation covers.
    #[inline]
    pub fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.position..self.position + self.length]
    }
}

// ---------------------------------------------------------------------------
// Hash-chain match finder
// ---------------------------------------------------------------------------

struct HashChain {
    window_size: usize,
    mask: usize,
    head: Vec<u32>,
    prev: Vec<u32>,
}

impl HashChain {
    fn new(window_size: usize) -> Self {
        debug_assert!(window_size.is_power_of_two());
        Self {
            window_size,
            mask: window_size - 1,
            head: vec![NO_POS; HASH_SIZE],
            prev: vec![NO_POS; window_size],
        }
    }

    #[inline]
    fn hash4(data: &[u8], pos: usize) -> usize {
        let h = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        (h.wrapping_mul(2654435761) >> 17) as usize & HASH_MASK
    }

    #[inline]
    fn slot(&self, pos: usize) -> usize {
        pos & self.mask
    }

    fn insert(&mut self, data: &[u8], pos: usize) {
        if pos + 4 > data.len() {
            return;
        }
        let h = Self::hash4(data, pos);
        let s = self.slot(pos);
        self.prev[s] = self.head[h];
        self.head[h] = pos as u32;
    }

    fn insert_range(&mut self, data: &[u8], start: usize, end: usize) {
        let limit = end.min(data.len().saturating_sub(3));
        for p in start..limit {
            self.insert(data, p);
        }
    }

    fn longest_match(
        &self,
        data: &[u8],
        pos: usize,
        max_len: usize,
    ) -> Option<(usize, usize)> {
        if pos + MIN_MATCH > data.len() {
            return None;
        }

        let h = Self::hash4(data, pos);
        let mut cp = self.head[h];
        let min_pos = pos.saturating_sub(self.window_size);
        let mut best_off: usize = 0;
        let mut best_len: usize = MIN_MATCH - 1;
        let mut steps: usize = 0;

        while cp != NO_POS && (cp as usize) >= min_pos && steps < MAX_CHAIN {
            let c = cp as usize;
            if c >= pos {
                cp = self.prev[self.slot(c)];
                steps += 1;
                continue;
            }

            let limit = max_len.min(data.len() - pos).min(data.len() - c);
            if limit > best_len && data[c + best_len] == data[pos + best_len] {
                let mut len = 0;
                while len < limit && data[c + len] == data[pos + len] {
                    len += 1;
                }
                if len > best_len {
                    best_len = len;
                    best_off = pos - c;
                    if best_len >= max_len {
                        break;
                    }
                }
            }

            cp = self.prev[self.slot(c)];
            steps += 1;
        }

        if best_len >= MIN_MATCH && best_off > 0 {
            Some((best_off, best_len))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Public scan function
// ---------------------------------------------------------------------------

/// Run LZ77 match-finding over `data` and return analysis operations.
///
/// Each byte of the input is covered by exactly one `ScanOp`.
/// Consecutive unmatched bytes are merged into a single literal `ScanOp`.
pub fn scan(data: &[u8], window_size: usize, min_match: usize, max_match: usize) -> Vec<ScanOp> {
    if data.is_empty() {
        return Vec::new();
    }

    let ws = window_size.next_power_of_two();
    let mut chain = HashChain::new(ws);
    let mut ops = Vec::new();
    let mut pos: usize = 0;
    let mut lit_start: Option<usize> = None;

    while pos < data.len() {
        if pos + 4 <= data.len() {
            if let Some((off, len)) = chain.longest_match(data, pos, max_match) {
                if len >= min_match {
                    // Flush pending literal run
                    if let Some(s) = lit_start.take() {
                        ops.push(ScanOp {
                            position: s,
                            kind: OpKind::Literal,
                            length: pos - s,
                            ref_offset: 0,
                        });
                    }
                    ops.push(ScanOp {
                        position: pos,
                        kind: OpKind::Backref,
                        length: len,
                        ref_offset: off,
                    });
                    chain.insert_range(data, pos, pos + len);
                    pos += len;
                    continue;
                }
            }
        }

        if lit_start.is_none() {
            lit_start = Some(pos);
        }
        chain.insert(data, pos);
        pos += 1;
    }

    // Flush final literal run
    if let Some(s) = lit_start {
        ops.push(ScanOp {
            position: s,
            kind: OpKind::Literal,
            length: data.len() - s,
            ref_offset: 0,
        });
    }

    ops
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(scan(b"", DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH).is_empty());
    }

    #[test]
    fn all_literal() {
        let data = b"abcdefgh";
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, OpKind::Literal);
        assert_eq!(ops[0].length, data.len());
    }

    #[test]
    fn full_coverage() {
        let data = b"hello world, hello world, hello world again!\n";
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let covered: usize = ops.iter().map(|o| o.length).sum();
        assert_eq!(covered, data.len());
    }

    #[test]
    fn no_gaps() {
        let data = b"test line one\ntest line two\ntest line three\n";
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let mut pos = 0;
        for op in &ops {
            assert_eq!(op.position, pos, "gap at byte {pos}");
            pos += op.length;
        }
        assert_eq!(pos, data.len());
    }

    #[test]
    fn repeated_string_produces_backref() {
        let chunk = b"the quick brown fox ";
        let mut data = Vec::new();
        data.extend_from_slice(chunk);
        data.extend_from_slice(chunk);
        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let br_bytes: usize = ops
            .iter()
            .filter(|o| o.kind == OpKind::Backref)
            .map(|o| o.length)
            .sum();
        assert!(br_bytes >= 10);
    }

    #[test]
    fn backref_content_matches_source() {
        let data = b"pattern1234 pattern1234 pattern1234";
        let ops = scan(data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        for op in &ops {
            if op.kind == OpKind::Backref {
                let src = op.position - op.ref_offset;
                assert_eq!(
                    &data[src..src + op.length],
                    op.content(data),
                );
            }
        }
    }

    #[test]
    fn large_repetition_high_coverage() {
        let line = b"2026-02-16 08:31:02 myapp[1423]: Connection established from 10.0.0.5\n";
        let data: Vec<u8> = line.repeat(100);
        let ops = scan(&data, DEFAULT_WINDOW, MIN_MATCH, MAX_MATCH);
        let br_bytes: usize = ops
            .iter()
            .filter(|o| o.kind == OpKind::Backref)
            .map(|o| o.length)
            .sum();
        let coverage = br_bytes as f64 / data.len() as f64;
        assert!(coverage > 0.8, "expected >80% coverage, got {coverage:.1}%");
    }
}
