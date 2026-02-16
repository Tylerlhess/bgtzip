# bgtzip

Post-LZ77 analysis and anomaly detection for log files.

bgtzip detects anomalous lines in log files using two analysis modes:

- **Plain text** — LZ77 byte-pattern matching to score records by structural
  repetition.
- **JSON structured logs** — Schema profiling and field-level analysis to
  detect missing fields, rare values, type mismatches, and unusual field
  combinations.

The format is auto-detected: if the first line parses as a JSON object, the
JSON analyzer is used; otherwise the LZ77 scanner runs.

## How it works

### LZ77 mode (plain text)

1. **Scan** — A sliding-window hash-chain matcher (same algorithm as deflate)
   finds all back-references in the input. No actual compression is
   performed; the matches are used purely for analysis.

2. **Dictionary** — Back-references are grouped by content and sorted by
   frequency. Entry 0 is the most common byte pattern in the file.

3. **Score** — Each record is scored by *coverage* (fraction of bytes covered
   by back-references) and *rarity* (how common the referenced dictionary
   entries are). High coverage + common entries = normal. Low coverage or
   rare entries = potentially anomalous.

4. **Detect** — Statistical thresholding (z-score, percentile, or top-N)
   surfaces the most anomalous records.

### JSON mode (structured logs)

1. **Parse** — Each line is parsed as JSON. Parse failures are flagged.

2. **Schema** — A statistical profile is built: per-field presence rates,
   dominant types, value distributions, and cardinality classification.

3. **Score** — Each record is scored by five weighted signals:
   missing common fields (30%), value rarity (25%), field set novelty (25%),
   extra rare fields (10%), and type mismatches (10%).

4. **Detect** — Same statistical thresholding as LZ77 mode. Reports explain
   *why* each record is anomalous.

## Install

### One-liner (any Linux/macOS machine)

```bash
curl -sSf https://raw.githubusercontent.com/Tylerlhess/bgtzip/master/install.sh | bash
```

This will check for Rust, prompt to install it if missing, then build and
install `bgtzip` into `~/.cargo/bin`.

### From source

```bash
git clone https://github.com/Tylerlhess/bgtzip.git
cd bgtzip
cargo install --path .
```

## Usage

```bash
# Analyze a plain-text log (auto-detects LZ77 mode)
bgtzip analyze /var/log/syslog

# Analyze JSON structured logs (auto-detects JSON mode)
bgtzip analyze app.jsonl

# Force JSON mode
bgtzip analyze mixed.log --structured

# Find the 10 most anomalous lines
bgtzip anomalies server.log --top-n 10

# Anomaly detection with JSON output
bgtzip anomalies server.log --method score --json

# Show the frequency-ordered dictionary (LZ77 mode)
bgtzip dict server.log --top 20

# Raw LZ77 scan summary
bgtzip scan server.log

# Extract anomalous lines to stdout
bgtzip anomalies server.log --top-n 5 --extract
```

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Run LZ77 scanner, print literal vs backref breakdown |
| `dict` | Build and display the frequency-ordered dictionary |
| `analyze` | Full pipeline: scan + dict + per-record scoring + histogram |
| `anomalies` | Detect and display anomalous records |

### Common flags

| Flag | Default | Description |
|------|---------|-------------|
| `--window-size` | 32768 | LZ77 sliding window size in bytes |
| `--min-match` | 4 | Minimum match length in bytes |
| `--min-count` | 2 | Minimum backref count for dictionary inclusion |
| `--structured` | off | Force JSON structured log mode |
| `-v, --verbose` | off | Print timing info to stderr |

### Anomaly detection methods

| Method | Description |
|--------|-------------|
| `score` | Flag records with anomaly score > mean + 1.5σ (default) |
| `coverage` | Flag records with coverage < mean − 1.5σ |
| `percentile` | Flag the top N% by anomaly score |
| `top` | Return the top N most anomalous records |

## Example output

### LZ77 mode (plain text)

```
=== Anomaly Report (LZ77): syslog.log ===
  records:             5000
  mean coverage:     0.9277
  median coverage:   0.9318
  stdev coverage:    0.0617
  threshold:         0.3354
  anomalies:             10  (0.2%)

--- Anomalous Records ---
  [     0]  score=0.9222  cov=0.11  lit=  80  refs= 0  Feb 15 04:18:02 server1 CRON[42153]: ...
  [     1]  score=0.8279  cov=0.25  lit=  46  refs= 0  Feb 14 14:25:57 server1 systemd[1]: ...
```

### JSON mode (structured logs)

```
=== Anomaly Report (JSON): app.jsonl ===
  records:              503
  valid JSON:           502
  parse errors:           1
  schema fields:         11
  mean score:        0.1798
  stdev score:       0.0755
  threshold:         0.4888
  anomalies:              5  (1.0%)

--- Anomalous Records ---
  [   392]  score=1.0000  fields= 0  this is not json at all
           missing: message, timestamp, level, request_id, service
  [   331]  score=0.6590  fields= 4  {"timestamp": 12345, "level": true, ...}
           missing: request_id
           rare values: level=true
           type mismatch: level: expected string, got bool
  [   210]  score=0.6495  fields= 4  {"event_type": "AUDIT", "actor": "admin", ...}
           missing: message, timestamp, level, request_id, service
           rare fields: event_type, action, actor, target
```

## License

[MIT](LICENSE)
