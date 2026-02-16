# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-02-16

### Added

- **JSON structured log analysis** (`json_analyzer` module). When input is
  JSON-lines (one JSON object per line), bgtzip now auto-detects the format
  and uses a structural analyzer instead of the LZ77 byte-pattern scanner.
- Schema profiling: field presence rates, dominant types, value frequency
  distributions, and cardinality classification (low vs high).
- Five weighted anomaly signals for JSON records:
  - Missing common fields (30%) — fields present in >50% of records but absent
  - Value rarity (25%) — uncommon values in low-cardinality fields
  - Field set novelty (25%) — unusual combination of field names
  - Extra rare fields (10%) — fields present in <5% of records
  - Type mismatches (10%) — e.g., number where string is expected
- `--structured` flag on `analyze` and `anomalies` commands to force JSON mode
  (auto-detection can be overridden).
- Anomaly reports for JSON mode show *why* each record is anomalous: missing
  fields, rare values, type mismatches, and rare field names.
- `detect_indices` public function in `anomaly` module — extracted core
  score-based detection logic so both LZ77 and JSON paths share it.
- 10 new unit tests for the JSON analyzer (34 total).

### Changed

- Refactored `anomaly.rs`: statistical helpers (`mean`, `median_of`,
  `sample_stdev`) are now `pub(crate)` so other modules can reuse them.
- `analyze` and `anomalies` CLI commands now auto-detect JSON input by
  checking whether the first line parses as a JSON object.
- Output headers distinguish mode: `Analysis (LZ77)` vs `Analysis (JSON)`,
  `Anomaly Report (LZ77)` vs `Anomaly Report (JSON)`.

## [0.1.0] - 2026-02-16

### Added

- Initial release: post-LZ77 analysis and anomaly detection.
- LZ77 sliding-window hash-chain scanner (`scanner` module).
- Frequency-ordered dictionary builder (`dictionary` module).
- Per-record scoring with coverage and rarity metrics (`scorer` module).
- Statistical anomaly detection: score, coverage, percentile, top-N methods
  (`anomaly` module).
- CLI with `scan`, `dict`, `analyze`, and `anomalies` commands.
- 24 unit tests.
