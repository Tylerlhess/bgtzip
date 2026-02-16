# bgtzip

Post-LZ77 analysis and anomaly detection for structured log files.

bgtzip runs an LZ77 match-finding pass over raw text data, builds a
frequency-ordered dictionary of repeated byte patterns, scores each record
(log line) by how well it matches the common patterns, and flags anomalous
lines that deviate from the norm.

## How it works

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

## Install

```
cargo install --path .
```

## Usage

```bash
# Full analysis with coverage histogram and top dictionary entries
bgtzip analyze server.log

# Find the 10 most anomalous lines
bgtzip anomalies server.log --top-n 10

# Anomaly detection with JSON output
bgtzip anomalies server.log --method score --json

# Show the frequency-ordered dictionary
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
| `-v, --verbose` | off | Print timing info to stderr |

### Anomaly detection methods

| Method | Description |
|--------|-------------|
| `score` | Flag records with anomaly score > mean + 1.5σ (default) |
| `coverage` | Flag records with coverage < mean − 1.5σ |
| `percentile` | Flag the top N% by anomaly score |
| `top` | Return the top N most anomalous records |

## Example output

```
=== Anomaly Report: syslog.log ===
  records:             5000
  mean coverage:     0.9277
  median coverage:   0.9318
  stdev coverage:    0.0617
  threshold:         0.3354
  anomalies:             10  (0.2%)

--- Anomalous Records ---
  [     0]  score=0.9222  cov=0.11  lit=  80  refs= 0  Feb 15 04:18:02 server1 CRON[42153]: (root) CMD (/usr/sbin/logrotate ...)
  [     1]  score=0.8279  cov=0.25  lit=  46  refs= 0  Feb 14 14:25:57 server1 systemd[1]: Started Slice apt-daily.
  [     7]  score=0.6352  cov=0.21  lit= 104  refs= 3  Feb 14 12:34:01 server1 kernel: [98345.156242] EXT4-fs IN= OUT=eth0 ...
```

## License

[MIT](LICENSE)
