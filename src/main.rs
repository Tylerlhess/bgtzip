use std::fs;
use std::io::{self, Write};
use std::time::Instant;

use clap::{Args, Parser, Subcommand};

use bgtzip::anomaly::{detect_anomalies, DetectionMethod};
use bgtzip::dictionary::build_dictionary;
use bgtzip::scanner::{scan, OpKind, DEFAULT_WINDOW, MAX_MATCH, MIN_MATCH};
use bgtzip::scorer::score_records;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "bgtzip", about = "Post-LZ77 analysis and anomaly detection")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone)]
struct CommonArgs {
    /// Input file to analyze
    input: String,
    /// LZ77 sliding window size in bytes
    #[arg(long, default_value_t = DEFAULT_WINDOW)]
    window_size: usize,
    /// Minimum match length in bytes
    #[arg(long, default_value_t = MIN_MATCH)]
    min_match: usize,
    /// Print timing info
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run LZ77 scanner and print operation summary
    Scan {
        #[command(flatten)]
        common: CommonArgs,
        /// Show first N operations
        #[arg(long, default_value_t = 0)]
        show_ops: usize,
    },
    /// Build and display frequency-ordered dictionary
    Dict {
        #[command(flatten)]
        common: CommonArgs,
        /// Minimum backref count to include in dictionary
        #[arg(long, default_value_t = 2)]
        min_count: usize,
        /// Show only top N entries
        #[arg(long)]
        top: Option<usize>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Full analysis: scan + dict + per-record scoring
    Analyze {
        #[command(flatten)]
        common: CommonArgs,
        /// Minimum backref count for dictionary
        #[arg(long, default_value_t = 2)]
        min_count: usize,
    },
    /// Detect and display anomalous records
    Anomalies {
        #[command(flatten)]
        common: CommonArgs,
        /// Minimum backref count for dictionary
        #[arg(long, default_value_t = 2)]
        min_count: usize,
        /// Detection method: score, coverage, percentile, top
        #[arg(long, value_parser = ["score", "coverage", "percentile", "top"])]
        method: Option<String>,
        /// Detection threshold (method-dependent)
        #[arg(long)]
        threshold: Option<f64>,
        /// Show top N anomalies (implies method=top)
        #[arg(long)]
        top_n: Option<usize>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Print raw anomalous record content to stdout
        #[arg(long)]
        extract: bool,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_input(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: {path}: {e}");
        std::process::exit(1);
    })
}

fn pct(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64 * 100.0
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_scan(c: CommonArgs, show_ops: usize) -> i32 {
    let data = read_input(&c.input);

    let t0 = Instant::now();
    let ops = scan(&data, c.window_size, c.min_match, MAX_MATCH);
    let elapsed = t0.elapsed().as_secs_f64();

    let n_lit = ops.iter().filter(|o| o.kind == OpKind::Literal).count();
    let n_ref = ops.iter().filter(|o| o.kind == OpKind::Backref).count();
    let lit_bytes: usize = ops.iter().filter(|o| o.kind == OpKind::Literal).map(|o| o.length).sum();
    let ref_bytes: usize = ops.iter().filter(|o| o.kind == OpKind::Backref).map(|o| o.length).sum();
    let total = data.len();

    println!("=== LZ77 Scan: {} ===", c.input);
    println!("  input size:     {total:>10} bytes");
    println!("  scan time:      {elapsed:>10.4}s");
    println!("  operations:     {:>10}", ops.len());
    println!(
        "    literals:     {n_lit:>10}  ({lit_bytes} bytes, {:.1}%)",
        pct(lit_bytes, total)
    );
    println!(
        "    backrefs:     {n_ref:>10}  ({ref_bytes} bytes, {:.1}%)",
        pct(ref_bytes, total)
    );

    if show_ops > 0 {
        println!("\n--- Operations (first {show_ops}) ---");
        for op in ops.iter().take(show_ops) {
            let preview = op.content(&data);
            let trunc = preview.len().min(40);
            let suffix = if preview.len() > 40 { "..." } else { "" };
            let shown = String::from_utf8_lossy(&preview[..trunc]);
            match op.kind {
                OpKind::Backref => println!(
                    "  [{:8}] BACKREF  len={:4}  off={:6}  {shown:?}{suffix}",
                    op.position, op.length, op.ref_offset
                ),
                OpKind::Literal => println!(
                    "  [{:8}] LITERAL  len={:4}  {shown:?}{suffix}",
                    op.position, op.length
                ),
            }
        }
    }

    0
}

fn cmd_dict(c: CommonArgs, min_count: usize, top: Option<usize>, json: bool) -> i32 {
    let data = read_input(&c.input);
    let t0 = Instant::now();
    let ops = scan(&data, c.window_size, c.min_match, MAX_MATCH);
    if c.verbose {
        eprintln!("  scan: {:.4}s", t0.elapsed().as_secs_f64());
    }
    let dict = build_dictionary(&data, &ops, min_count);

    let total_covered: usize = dict.iter().map(|e| e.total_bytes_covered()).sum();
    let limit = top.unwrap_or(dict.len());

    if json {
        let entries: Vec<serde_json::Value> = dict
            .iter()
            .take(limit)
            .map(|e| {
                serde_json::json!({
                    "id": e.entry_id,
                    "count": e.count,
                    "length": e.content_length(),
                    "total_bytes": e.total_bytes_covered(),
                    "median_interval": e.median_interval(),
                    "mean_interval": e.mean_interval(),
                    "content_preview": String::from_utf8_lossy(&e.content[..e.content.len().min(80)]),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries).unwrap());
    } else {
        println!("=== Dictionary: {} ===", c.input);
        println!("  entries:  {}", dict.len());
        if !data.is_empty() {
            println!(
                "  total backref bytes covered: {total_covered} / {} ({:.1}%)",
                data.len(),
                pct(total_covered, data.len())
            );
        }
        println!("\n--- Top {limit} entries ---");
        for e in dict.iter().take(limit) {
            let trunc = e.content.len().min(60);
            let suffix = if e.content.len() > 60 { "..." } else { "" };
            let shown = String::from_utf8_lossy(&e.content[..trunc]);
            println!(
                "  [{:4}]  count={:6}  len={:4}  med_iv={:8.0}  {shown:?}{suffix}",
                e.entry_id,
                e.count,
                e.content_length(),
                e.median_interval()
            );
        }
    }

    0
}

fn cmd_analyze(c: CommonArgs, min_count: usize) -> i32 {
    let data = read_input(&c.input);

    let t0 = Instant::now();
    let ops = scan(&data, c.window_size, c.min_match, MAX_MATCH);
    let t1 = Instant::now();
    let dict = build_dictionary(&data, &ops, min_count);
    let t2 = Instant::now();
    let records = score_records(&data, &ops, &dict, b'\n');
    let t3 = Instant::now();

    if c.verbose {
        eprintln!("  scan:  {:.4}s", (t1 - t0).as_secs_f64());
        eprintln!("  dict:  {:.4}s", (t2 - t1).as_secs_f64());
        eprintln!("  score: {:.4}s", (t3 - t2).as_secs_f64());
    }

    let n_lit = ops.iter().filter(|o| o.kind == OpKind::Literal).count();
    let n_ref = ops.iter().filter(|o| o.kind == OpKind::Backref).count();
    let ref_bytes: usize = ops.iter().filter(|o| o.kind == OpKind::Backref).map(|o| o.length).sum();

    println!("=== Analysis: {} ===", c.input);
    println!("  input size:     {:>10} bytes", data.len());
    println!("  records:        {:>10}", records.len());
    println!("  scan ops:       {:>10}  ({n_lit} literal, {n_ref} backref)", ops.len());
    println!("  backref cover:  {:>9.1}%", pct(ref_bytes, data.len()));
    println!("  dict entries:   {:>10}", dict.len());

    if !records.is_empty() {
        let coverages: Vec<f64> = records.iter().map(|r| r.coverage).collect();
        let sum: f64 = coverages.iter().sum();
        let mean = sum / coverages.len() as f64;
        let mut sorted = coverages.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
        } else {
            sorted[sorted.len() / 2]
        };
        let min_c = sorted.first().copied().unwrap_or(0.0);
        let max_c = sorted.last().copied().unwrap_or(0.0);

        println!("\n--- Coverage Distribution ---");
        println!("  mean:    {mean:.4}");
        println!("  median:  {median:.4}");
        println!("  min:     {min_c:.4}");
        println!("  max:     {max_c:.4}");

        // Histogram
        let mut buckets = [0usize; 10];
        for &c in &coverages {
            let b = (c * 10.0).min(9.0) as usize;
            buckets[b] += 1;
        }
        let max_count = *buckets.iter().max().unwrap_or(&1).max(&1);
        println!("\n--- Coverage Histogram ---");
        for (i, &count) in buckets.iter().enumerate() {
            let lo = i * 10;
            let hi = (i + 1) * 10;
            let bar_len = (count as f64 / max_count as f64 * 40.0) as usize;
            let bar: String = "#".repeat(bar_len);
            println!("  {lo:3}-{hi:3}%: {count:6} {bar}");
        }
    }

    // Top dict entries
    let top = dict.len().min(10);
    if top > 0 {
        println!("\n--- Top {top} Dictionary Entries ---");
        for e in dict.iter().take(top) {
            let trunc = e.content.len().min(50);
            let suffix = if e.content.len() > 50 { "..." } else { "" };
            let shown = String::from_utf8_lossy(&e.content[..trunc]);
            println!(
                "  [{:4}]  count={:6}  len={:4}  {shown:?}{suffix}",
                e.entry_id,
                e.count,
                e.content_length()
            );
        }
    }

    0
}

fn cmd_anomalies(
    c: CommonArgs,
    min_count: usize,
    method_str: Option<String>,
    threshold: Option<f64>,
    top_n: Option<usize>,
    json: bool,
    extract: bool,
) -> i32 {
    let data = read_input(&c.input);

    let t0 = Instant::now();
    let ops = scan(&data, c.window_size, c.min_match, MAX_MATCH);
    let dict = build_dictionary(&data, &ops, min_count);
    let records = score_records(&data, &ops, &dict, b'\n');
    if c.verbose {
        eprintln!("  pipeline: {:.4}s", t0.elapsed().as_secs_f64());
    }

    let method = if top_n.is_some() {
        DetectionMethod::Top
    } else {
        match method_str.as_deref() {
            Some("coverage") => DetectionMethod::Coverage,
            Some("percentile") => DetectionMethod::Percentile,
            Some("top") => DetectionMethod::Top,
            _ => DetectionMethod::Score,
        }
    };

    let report = detect_anomalies(&records, dict.len(), method, threshold, top_n);

    if json {
        let anomalies: Vec<serde_json::Value> = report
            .anomaly_indices
            .iter()
            .map(|&i| {
                let r = &records[i];
                let line = String::from_utf8_lossy(r.content(&data)).trim_end().to_string();
                serde_json::json!({
                    "index": r.index,
                    "offset": r.offset,
                    "length": r.length,
                    "coverage": (r.coverage * 1e6).round() / 1e6,
                    "anomaly_score": (r.anomaly_score * 1e6).round() / 1e6,
                    "literal_bytes": r.literal_bytes,
                    "backref_bytes": r.backref_bytes,
                    "ref_entries": r.ref_entries,
                    "content": line,
                })
            })
            .collect();
        let out = serde_json::json!({
            "total_records": report.total_records,
            "total_bytes": report.total_bytes,
            "dict_entries": report.dict_entry_count,
            "mean_coverage": (report.mean_coverage * 1e6).round() / 1e6,
            "median_coverage": (report.median_coverage * 1e6).round() / 1e6,
            "stdev_coverage": (report.stdev_coverage * 1e6).round() / 1e6,
            "threshold": (report.threshold * 1e6).round() / 1e6,
            "anomaly_count": report.anomaly_count,
            "anomaly_rate": (report.anomaly_rate() * 1e6).round() / 1e6,
            "anomalies": anomalies,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("=== Anomaly Report: {} ===", c.input);
        println!("  records:         {:>8}", report.total_records);
        println!("  mean coverage:   {:>8.4}", report.mean_coverage);
        println!("  median coverage: {:>8.4}", report.median_coverage);
        println!("  stdev coverage:  {:>8.4}", report.stdev_coverage);
        println!("  threshold:       {:>8.4}", report.threshold);
        println!(
            "  anomalies:       {:>8}  ({:.1}%)",
            report.anomaly_count,
            report.anomaly_rate() * 100.0
        );

        if !report.anomaly_indices.is_empty() {
            println!("\n--- Anomalous Records ---");
            for &i in &report.anomaly_indices {
                let r = &records[i];
                let raw = r.content(&data);
                let line = String::from_utf8_lossy(raw).trim_end().to_string();
                let shown = if line.len() > 120 {
                    format!("{}...", &line[..117])
                } else {
                    line
                };
                println!(
                    "  [{:6}]  score={:.4}  cov={:.2}  lit={:4}  refs={:2}  {shown}",
                    r.index,
                    r.anomaly_score,
                    r.coverage,
                    r.literal_bytes,
                    r.ref_entries.len()
                );
            }
        }

        if extract {
            println!("\n--- Extracted Anomalous Lines ---");
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for &i in &report.anomaly_indices {
                let _ = out.write_all(records[i].content(&data));
            }
        }
    }

    0
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Scan { common, show_ops } => cmd_scan(common, show_ops),
        Commands::Dict {
            common,
            min_count,
            top,
            json,
        } => cmd_dict(common, min_count, top, json),
        Commands::Analyze { common, min_count } => cmd_analyze(common, min_count),
        Commands::Anomalies {
            common,
            min_count,
            method,
            threshold,
            top_n,
            json,
            extract,
        } => cmd_anomalies(common, min_count, method, threshold, top_n, json, extract),
    };
    std::process::exit(code);
}
