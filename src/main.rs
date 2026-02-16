use std::fs;
use std::io::{self, Write};
use std::time::Instant;

use clap::{Args, Parser, Subcommand};

use bgtzip::anomaly::{detect_anomalies, detect_indices, DetectionMethod};
use bgtzip::dictionary::build_dictionary;
use bgtzip::json_analyzer::{
    build_json_report, build_schema, looks_like_json, parse_json_records,
    score_json_records,
};
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
        /// Output as JSON format
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
        /// Force JSON structured log mode (auto-detected if omitted)
        #[arg(long)]
        structured: bool,
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
        /// Output as JSON format
        #[arg(long)]
        json: bool,
        /// Print raw anomalous record content to stdout
        #[arg(long)]
        extract: bool,
        /// Force JSON structured log mode (auto-detected if omitted)
        #[arg(long)]
        structured: bool,
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
    if den == 0 { 0.0 } else { num as f64 / den as f64 * 100.0 }
}

fn parse_method(method_str: &Option<String>, top_n: &Option<usize>) -> DetectionMethod {
    if top_n.is_some() {
        DetectionMethod::Top
    } else {
        match method_str.as_deref() {
            Some("coverage") => DetectionMethod::Coverage,
            Some("percentile") => DetectionMethod::Percentile,
            Some("top") => DetectionMethod::Top,
            _ => DetectionMethod::Score,
        }
    }
}

fn is_json_mode(data: &[u8], force: bool) -> bool {
    if force {
        return true;
    }
    looks_like_json(data)
}

// ---------------------------------------------------------------------------
// LZ77 commands (unchanged)
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
    println!("    literals:     {n_lit:>10}  ({lit_bytes} bytes, {:.1}%)", pct(lit_bytes, total));
    println!("    backrefs:     {n_ref:>10}  ({ref_bytes} bytes, {:.1}%)", pct(ref_bytes, total));

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
    if c.verbose { eprintln!("  scan: {:.4}s", t0.elapsed().as_secs_f64()); }
    let dict = build_dictionary(&data, &ops, min_count);

    let total_covered: usize = dict.iter().map(|e| e.total_bytes_covered()).sum();
    let limit = top.unwrap_or(dict.len());

    if json {
        let entries: Vec<serde_json::Value> = dict.iter().take(limit).map(|e| {
            serde_json::json!({
                "id": e.entry_id, "count": e.count, "length": e.content_length(),
                "total_bytes": e.total_bytes_covered(),
                "median_interval": e.median_interval(), "mean_interval": e.mean_interval(),
                "content_preview": String::from_utf8_lossy(&e.content[..e.content.len().min(80)]),
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&entries).unwrap());
    } else {
        println!("=== Dictionary: {} ===", c.input);
        println!("  entries:  {}", dict.len());
        if !data.is_empty() {
            println!("  total backref bytes covered: {total_covered} / {} ({:.1}%)",
                data.len(), pct(total_covered, data.len()));
        }
        println!("\n--- Top {limit} entries ---");
        for e in dict.iter().take(limit) {
            let trunc = e.content.len().min(60);
            let suffix = if e.content.len() > 60 { "..." } else { "" };
            let shown = String::from_utf8_lossy(&e.content[..trunc]);
            println!("  [{:4}]  count={:6}  len={:4}  med_iv={:8.0}  {shown:?}{suffix}",
                e.entry_id, e.count, e.content_length(), e.median_interval());
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Analyze command (LZ77 or JSON)
// ---------------------------------------------------------------------------

fn cmd_analyze(c: CommonArgs, min_count: usize, structured: bool) -> i32 {
    let data = read_input(&c.input);

    if is_json_mode(&data, structured) {
        return cmd_analyze_json(&c, &data);
    }

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

    println!("=== Analysis (LZ77): {} ===", c.input);
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
        } else { sorted[sorted.len() / 2] };

        println!("\n--- Coverage Distribution ---");
        println!("  mean:    {mean:.4}");
        println!("  median:  {median:.4}");
        println!("  min:     {:.4}", sorted.first().unwrap_or(&0.0));
        println!("  max:     {:.4}", sorted.last().unwrap_or(&0.0));

        let mut buckets = [0usize; 10];
        for &c in &coverages { buckets[(c * 10.0).min(9.0) as usize] += 1; }
        let max_count = *buckets.iter().max().unwrap_or(&1).max(&1);
        println!("\n--- Coverage Histogram ---");
        for (i, &count) in buckets.iter().enumerate() {
            let bar = "#".repeat((count as f64 / max_count as f64 * 40.0) as usize);
            println!("  {:3}-{:3}%: {:6} {bar}", i * 10, (i + 1) * 10, count);
        }
    }

    let top = dict.len().min(10);
    if top > 0 {
        println!("\n--- Top {top} Dictionary Entries ---");
        for e in dict.iter().take(top) {
            let trunc = e.content.len().min(50);
            let suffix = if e.content.len() > 50 { "..." } else { "" };
            let shown = String::from_utf8_lossy(&e.content[..trunc]);
            println!("  [{:4}]  count={:6}  len={:4}  {shown:?}{suffix}",
                e.entry_id, e.count, e.content_length());
        }
    }
    0
}

fn cmd_analyze_json(c: &CommonArgs, data: &[u8]) -> i32 {
    let t0 = Instant::now();
    let records = parse_json_records(data, b'\n');
    let t1 = Instant::now();
    let schema = build_schema(&records);
    let t2 = Instant::now();
    let scored = score_json_records(data, &records, &schema);
    let t3 = Instant::now();

    if c.verbose {
        eprintln!("  parse:  {:.4}s", (t1 - t0).as_secs_f64());
        eprintln!("  schema: {:.4}s", (t2 - t1).as_secs_f64());
        eprintln!("  score:  {:.4}s", (t3 - t2).as_secs_f64());
    }

    println!("=== Analysis (JSON): {} ===", c.input);
    println!("  input size:     {:>10} bytes", data.len());
    println!("  records:        {:>10}", records.len());
    println!("  valid JSON:     {:>10}", schema.valid_records);
    println!("  parse errors:   {:>10}", schema.parse_errors);
    println!("  unique fields:  {:>10}", schema.fields.len());
    println!("  field sets:     {:>10}", schema.field_set_counts.len());

    // Field presence table
    let mut fields: Vec<_> = schema.fields.values().collect();
    fields.sort_by(|a, b| b.present_count.cmp(&a.present_count));

    println!("\n--- Field Profiles ---");
    println!("  {:20} {:>6} {:>7} {:>5} {:>6}",
        "field", "count", "rate", "type", "uniq");
    for f in fields.iter().take(20) {
        println!("  {:20} {:>6} {:>6.1}% {:>5} {:>6}{}",
            f.name, f.present_count,
            f.presence_rate * 100.0,
            f.dominant_type,
            f.unique_values,
            if f.is_low_cardinality { "" } else { " (high)" });
    }

    // Top values for low-cardinality fields
    let low_card: Vec<_> = fields.iter()
        .filter(|f| f.is_low_cardinality && f.unique_values > 1 && f.unique_values <= 20)
        .take(5)
        .collect();
    if !low_card.is_empty() {
        println!("\n--- Value Distributions (low-cardinality fields) ---");
        for f in low_card {
            let mut vals: Vec<_> = f.value_counts.iter().collect();
            vals.sort_by(|a, b| b.1.cmp(a.1));
            let shown: Vec<String> = vals.iter().take(5)
                .map(|(v, c)| {
                    let trunc = if v.len() > 20 { format!("{}...", &v[..17]) } else { v.to_string() };
                    format!("{trunc}={c}")
                })
                .collect();
            let more = if vals.len() > 5 { format!(" (+{} more)", vals.len() - 5) } else { String::new() };
            println!("  {}: {}{more}", f.name, shown.join(", "));
        }
    }

    // Score distribution
    if !scored.is_empty() {
        let scores: Vec<f64> = scored.iter().map(|s| s.anomaly_score).collect();
        let sum: f64 = scores.iter().sum();
        let mean = sum / scores.len() as f64;
        println!("\n--- Anomaly Score Distribution ---");
        println!("  mean:   {mean:.4}");

        let mut buckets = [0usize; 10];
        for &s in &scores { buckets[(s * 10.0).min(9.0) as usize] += 1; }
        let max_count = *buckets.iter().max().unwrap_or(&1).max(&1);
        for (i, &count) in buckets.iter().enumerate() {
            let bar = "#".repeat((count as f64 / max_count as f64 * 40.0) as usize);
            println!("  0.{i}-0.{}: {:6} {bar}", i + 1, count);
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Anomalies command (LZ77 or JSON)
// ---------------------------------------------------------------------------

fn cmd_anomalies(
    c: CommonArgs, min_count: usize, method_str: Option<String>,
    threshold: Option<f64>, top_n: Option<usize>,
    json: bool, extract: bool, structured: bool,
) -> i32 {
    let data = read_input(&c.input);
    let method = parse_method(&method_str, &top_n);

    if is_json_mode(&data, structured) {
        return cmd_anomalies_json(&c, &data, method, threshold, top_n, json, extract);
    }

    let t0 = Instant::now();
    let ops = scan(&data, c.window_size, c.min_match, MAX_MATCH);
    let dict = build_dictionary(&data, &ops, min_count);
    let records = score_records(&data, &ops, &dict, b'\n');
    if c.verbose { eprintln!("  pipeline: {:.4}s", t0.elapsed().as_secs_f64()); }

    let report = detect_anomalies(&records, dict.len(), method, threshold, top_n);

    if json {
        let anomalies: Vec<serde_json::Value> = report.anomaly_indices.iter().map(|&i| {
            let r = &records[i];
            serde_json::json!({
                "index": r.index, "offset": r.offset, "length": r.length,
                "coverage": (r.coverage * 1e6).round() / 1e6,
                "anomaly_score": (r.anomaly_score * 1e6).round() / 1e6,
                "literal_bytes": r.literal_bytes, "backref_bytes": r.backref_bytes,
                "ref_entries": r.ref_entries,
                "content": String::from_utf8_lossy(r.content(&data)).trim_end(),
            })
        }).collect();
        let out = serde_json::json!({
            "mode": "lz77", "total_records": report.total_records,
            "anomaly_count": report.anomaly_count,
            "anomaly_rate": (report.anomaly_rate() * 1e6).round() / 1e6,
            "threshold": (report.threshold * 1e6).round() / 1e6,
            "anomalies": anomalies,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("=== Anomaly Report (LZ77): {} ===", c.input);
        println!("  records:         {:>8}", report.total_records);
        println!("  mean coverage:   {:>8.4}", report.mean_coverage);
        println!("  median coverage: {:>8.4}", report.median_coverage);
        println!("  stdev coverage:  {:>8.4}", report.stdev_coverage);
        println!("  threshold:       {:>8.4}", report.threshold);
        println!("  anomalies:       {:>8}  ({:.1}%)",
            report.anomaly_count, report.anomaly_rate() * 100.0);

        if !report.anomaly_indices.is_empty() {
            println!("\n--- Anomalous Records ---");
            for &i in &report.anomaly_indices {
                let r = &records[i];
                let line = String::from_utf8_lossy(r.content(&data)).trim_end().to_string();
                let shown = if line.len() > 120 { format!("{}...", &line[..117]) } else { line };
                println!("  [{:6}]  score={:.4}  cov={:.2}  lit={:4}  refs={:2}  {shown}",
                    r.index, r.anomaly_score, r.coverage, r.literal_bytes, r.ref_entries.len());
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

fn cmd_anomalies_json(
    c: &CommonArgs, data: &[u8], method: DetectionMethod,
    threshold: Option<f64>, top_n: Option<usize>,
    json_out: bool, extract: bool,
) -> i32 {
    let t0 = Instant::now();
    let records = parse_json_records(data, b'\n');
    let schema = build_schema(&records);
    let scored = score_json_records(data, &records, &schema);
    if c.verbose { eprintln!("  pipeline: {:.4}s", t0.elapsed().as_secs_f64()); }

    let scores: Vec<f64> = scored.iter().map(|s| s.anomaly_score).collect();
    let (threshold_used, anomaly_indices) =
        detect_indices(&scores, None, method, threshold, top_n);
    let report = build_json_report(&records, &scored, &schema, threshold_used, anomaly_indices);

    if json_out {
        let anomalies: Vec<serde_json::Value> = report.anomaly_indices.iter().map(|&i| {
            let s = &scored[i];
            serde_json::json!({
                "index": s.index, "offset": s.offset, "length": s.length,
                "anomaly_score": (s.anomaly_score * 1e6).round() / 1e6,
                "field_count": s.field_count,
                "missing_common": s.missing_common,
                "extra_rare": s.extra_rare,
                "rare_values": s.rare_values.iter().map(|(f,v)| format!("{f}={v}")).collect::<Vec<_>>(),
                "type_mismatches": s.type_mismatches.iter()
                    .map(|(f,exp,act)| format!("{f}: expected {exp}, got {act}")).collect::<Vec<_>>(),
                "content": String::from_utf8_lossy(s.content(data)).trim_end(),
            })
        }).collect();
        let out = serde_json::json!({
            "mode": "json", "total_records": report.total_records,
            "valid_records": report.valid_records, "parse_errors": report.parse_errors,
            "field_count": report.field_count,
            "anomaly_count": report.anomaly_count,
            "anomaly_rate": (report.anomaly_rate() * 1e6).round() / 1e6,
            "threshold": (report.threshold * 1e6).round() / 1e6,
            "anomalies": anomalies,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("=== Anomaly Report (JSON): {} ===", c.input);
        println!("  records:         {:>8}", report.total_records);
        println!("  valid JSON:      {:>8}", report.valid_records);
        println!("  parse errors:    {:>8}", report.parse_errors);
        println!("  schema fields:   {:>8}", report.field_count);
        println!("  mean score:      {:>8.4}", report.mean_score);
        println!("  stdev score:     {:>8.4}", report.stdev_score);
        println!("  threshold:       {:>8.4}", report.threshold);
        println!("  anomalies:       {:>8}  ({:.1}%)",
            report.anomaly_count, report.anomaly_rate() * 100.0);

        if !report.anomaly_indices.is_empty() {
            println!("\n--- Anomalous Records ---");
            for &i in &report.anomaly_indices {
                let s = &scored[i];
                let line = String::from_utf8_lossy(s.content(data)).trim_end().to_string();
                let shown = if line.len() > 120 { format!("{}...", &line[..117]) } else { line };
                println!("  [{:6}]  score={:.4}  fields={:2}  {shown}",
                    s.index, s.anomaly_score, s.field_count);

                // Show WHY it's anomalous
                if !s.missing_common.is_empty() {
                    println!("           missing: {}", s.missing_common.join(", "));
                }
                if !s.extra_rare.is_empty() {
                    println!("           rare fields: {}", s.extra_rare.join(", "));
                }
                if !s.rare_values.is_empty() {
                    let vals: Vec<String> = s.rare_values.iter()
                        .map(|(f, v)| {
                            let vt = if v.len() > 20 { format!("{}...", &v[..17]) } else { v.clone() };
                            format!("{f}={vt}")
                        })
                        .collect();
                    println!("           rare values: {}", vals.join(", "));
                }
                if !s.type_mismatches.is_empty() {
                    let mm: Vec<String> = s.type_mismatches.iter()
                        .map(|(f, exp, act)| format!("{f}: expected {exp}, got {act}"))
                        .collect();
                    println!("           type mismatch: {}", mm.join(", "));
                }
            }
        }
        if extract {
            println!("\n--- Extracted Anomalous Lines ---");
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for &i in &report.anomaly_indices {
                let _ = out.write_all(scored[i].content(data));
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
        Commands::Dict { common, min_count, top, json } =>
            cmd_dict(common, min_count, top, json),
        Commands::Analyze { common, min_count, structured } =>
            cmd_analyze(common, min_count, structured),
        Commands::Anomalies {
            common, min_count, method, threshold,
            top_n, json, extract, structured,
        } => cmd_anomalies(common, min_count, method, threshold, top_n, json, extract, structured),
    };
    std::process::exit(code);
}
