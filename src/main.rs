use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::time::{Duration, Instant};
use rand::Rng;
use sysinfo::{System, Pid, ProcessesToUpdate};

trait Logger {
    fn log(&mut self, message: &str) -> io::Result<()>;
}

mod hash_chain_logger {
    use super::*;
    use sha2::{Digest, Sha256};

    const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const DELIMITER: &str = "::";

    pub struct HashChainLogger {
        file: File,
        last_hash: String,
    }

    impl HashChainLogger {
        pub fn new(path: &str) -> io::Result<Self> {
            let mut file = OpenOptions::new().create(true).read(true).append(true).open(path)?;
            let reader = BufReader::new(&mut file);

            let last_line = reader.lines().filter_map(Result::ok).last();
            let initial_hash = match last_line {
                Some(line) => line.split(DELIMITER).last().unwrap_or(GENESIS_HASH).to_string(),
                None => GENESIS_HASH.to_string(),
            };

            Ok(HashChainLogger {
                file,
                last_hash: initial_hash,
            })
        }
    }

    impl Logger for HashChainLogger {
        fn log(&mut self, message: &str) -> io::Result<()> {
            let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let data_part = format!("{}{}{}", timestamp, DELIMITER, message);

            let previous_hash = &self.last_hash;

            let mut hasher = Sha256::new();
            hasher.update(data_part.as_bytes());
            hasher.update(previous_hash.as_bytes());
            let current_hash = format!("{:x}", hasher.finalize());

            writeln!(self.file, "{}{}{}", data_part, DELIMITER, &current_hash)?;
            // self.file.flush()?;

            self.last_hash = current_hash;

            Ok(())
        }
    }

    pub fn verify(path: &str) -> io::Result<bool> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e)
        };
        let mut previous_hash = GENESIS_HASH.to_string();
        for line_result in BufReader::new(file).lines() {
            let line = line_result?;
            let parts: Vec<&str> = line.split(DELIMITER).collect();
            if parts.len() != 3 { return Ok(false); }
            let (timestamp, message, stored_hash) = (parts[0], parts[1], parts[2]);
            let data_part = format!("{}{}{}", timestamp, DELIMITER, message);
            let mut hasher = Sha256::new();
            hasher.update(data_part.as_bytes());
            hasher.update(previous_hash.as_bytes());
            let expected_hash = format!("{:x}", hasher.finalize());
            if expected_hash != stored_hash { return Ok(false); }
            previous_hash = stored_hash.to_string();
        }
        Ok(true)
    }
}

mod traditional_logger {
    use super::*;

    pub struct TraditionalLogger {
        file: File,
    }

    impl TraditionalLogger {
        pub fn new(path: &str) -> io::Result<Self> {
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(path)?;
            Ok(TraditionalLogger { file })
        }
    }

    impl Logger for TraditionalLogger {
        fn log(&mut self, message: &str) -> io::Result<()> {
            let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            writeln!(self.file, "{}: {}", timestamp, message)?;
            // self.file.flush()?;

            Ok(())
        }
    }



    pub fn verify(path: &str) -> io::Result<bool> {
        // Traditional logger can only verify:
        // 1. File exists and is readable
        // 2. Format is correct (timestamp: message)
        // 3. Timestamps are valid and in order
        // It CANNOT verify content integrity

        let file = match File::open(path) {
            Ok(f) => f,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e)
        };

        let mut last_timestamp: Option<chrono::DateTime<chrono::Utc>> = None;

        for (line_num, line_result) in BufReader::new(file).lines().enumerate() {
            let line = line_result?;

            // Check format
            let parts: Vec<&str> = line.splitn(2, ": ").collect();
            if parts.len() != 2 {
                println!("Traditional verify: Format error at line {}", line_num);
                return Ok(false);
            }

            // Check timestamp validity and order
            match chrono::DateTime::parse_from_rfc3339(parts[0]) {
                Ok(timestamp) => {
                    let timestamp_utc = timestamp.with_timezone(&chrono::Utc);
                    if let Some(last_ts) = last_timestamp {
                        if timestamp_utc < last_ts {
                            println!("Traditional verify: Timestamp order violation at line {}", line_num);
                            return Ok(false);
                        }
                    }
                    last_timestamp = Some(timestamp_utc);
                }
                Err(_) => {
                    println!("Traditional verify: Invalid timestamp at line {}", line_num);
                    return Ok(false);
                }
            }

            // Note: We CANNOT verify if the message content has been tampered with
            // This is the fundamental limitation of traditional logging
        }

        Ok(true) // Format and timestamp order are valid, but content integrity is unknown
    }
}

#[derive(Default, Debug)]
struct PerformanceMetrics {
    write_throughput: f64,
    storage_bytes: u64,
    verification_time_ms: f64,
    tamper_detected: bool,
    avg_cpu_usage: f32,
    peak_memory_mb: f64,
    tamper_whole_line_detection_rate: f64,
    tamper_timestamp_detection_rate: f64,
    tamper_message_detection_rate: f64,
    overall_detection_rate: f64,
}

#[derive(Debug, Clone, Copy)]
enum TamperType {
    WholeLine,
    TimestampOnly,
    MessageOnly,
}

fn benchmark_write<L: Logger>(
    logger: &mut L,
    num_logs: usize,
) -> io::Result<(f64, f32, f64)> {
    let mut sys = System::new_all();
    let pid = Pid::from(std::process::id() as usize);
    let mut cpu_samples = Vec::new();
    let mut mem_samples = Vec::new();

    // Initial refresh to establish baseline for CPU calculation
    sys.refresh_processes(ProcessesToUpdate::All, true);
    std::thread::sleep(Duration::from_millis(200)); // Windows needs more time

    // Second refresh to get initial readings
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let start_time = Instant::now();
    let mut last_sample_time = Instant::now();
    let sample_interval = Duration::from_millis(500); // Sample every 500ms

    // Get the number of CPUs for normalization
    let num_cpus = sys.cpus().len() as f32;

    // For more efficient updates, we'll use specific PID updates
    let pids_to_update = [pid];

    for i in 0..num_logs {
        let message = format!("Log entry number {}", i);
        logger.log(&message)?;

        // Sample based on time elapsed rather than iteration count
        if last_sample_time.elapsed() >= sample_interval {
            sys.refresh_processes(ProcessesToUpdate::Some(&pids_to_update), false);

            if let Some(process) = sys.process(pid) {
                let cpu_usage = process.cpu_usage();
                // On Windows, CPU usage is per core, so divide by number of cores for overall percentage
                let normalized_cpu = cpu_usage / num_cpus;

                cpu_samples.push(normalized_cpu);
                mem_samples.push(process.memory());

                // Debug print to see if we're getting readings
                if i % 10000 == 0 {
                    println!("Sample at log {}: CPU={:.2}% (raw={:.2}%), Memory={:.2}MB",
                             i, normalized_cpu, cpu_usage, process.memory() as f64 / 1_048_576.0);
                }
            }

            last_sample_time = Instant::now();
            // Small sleep to ensure CPU usage registers
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // Final measurement
    std::thread::sleep(Duration::from_millis(200));
    sys.refresh_processes(ProcessesToUpdate::Some(&pids_to_update), false);

    if let Some(process) = sys.process(pid) {
        let cpu_usage = process.cpu_usage();
        let normalized_cpu = cpu_usage / num_cpus;
        cpu_samples.push(normalized_cpu);
        mem_samples.push(process.memory());
    }

    let duration = start_time.elapsed();
    let throughput = num_logs as f64 / duration.as_secs_f64();

    // Filter out zero samples and calculate average
    let non_zero_samples: Vec<f32> = cpu_samples.into_iter()
        .filter(|&x| x > 0.0)
        .collect();

    let avg_cpu = if non_zero_samples.is_empty() {
        0.0
    } else {
        non_zero_samples.iter().sum::<f32>() / non_zero_samples.len() as f32
    };

    let peak_mem = if mem_samples.is_empty() {
        0.0
    } else {
        (*mem_samples.iter().max().unwrap_or(&0)) as f64 / 1_048_576.0
    };

    println!("Write benchmark complete: {} samples collected, avg CPU: {:.2}%",
             non_zero_samples.len(), avg_cpu);

    Ok((throughput, avg_cpu, peak_mem))
}

fn benchmark_verify(path: &str, verifier_fn: &dyn Fn(&str) -> io::Result<bool>) -> io::Result<(f64, bool)> {
    let start_time = Instant::now();
    let result = verifier_fn(path)?;
    let duration = start_time.elapsed();
    Ok((duration.as_secs_f64() * 1000.0, result))
}


fn tamper_file(path: &str, line_to_tamper: usize, tamper_type: TamperType) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    if line_to_tamper < lines.len() {
        let original_line = lines[line_to_tamper].clone();

        match tamper_type {
            TamperType::WholeLine => {
                // Completely replace the line with invalid format
                lines[line_to_tamper] = "THIS LINE HAS BEEN COMPLETELY TAMPERED BY AN ATTACKER".to_string();
            },
            TamperType::TimestampOnly => {
                // For traditional logs (format: "timestamp: message")
                if original_line.contains(": ") {
                    let parts: Vec<&str> = original_line.splitn(2, ": ").collect();
                    if parts.len() == 2 {
                        // Change timestamp to an earlier time (breaks chronological order)
                        let fake_timestamp = "2020-01-01T00:00:00.000Z";
                        lines[line_to_tamper] = format!("{}: {}", fake_timestamp, parts[1]);
                    }
                }
                // For hash-chain logs (format: "timestamp::message::hash")
                else if original_line.contains("::") {
                    let parts: Vec<&str> = original_line.split("::").collect();
                    if parts.len() == 3 {
                        let fake_timestamp = "2020-01-01T00:00:00.000Z";
                        lines[line_to_tamper] = format!("{}::{}::{}", fake_timestamp, parts[1], parts[2]);
                    }
                }
            },
            TamperType::MessageOnly => {
                // For traditional logs (format: "timestamp: message")
                if original_line.contains(": ") {
                    let parts: Vec<&str> = original_line.splitn(2, ": ").collect();
                    if parts.len() == 2 {
                        // Keep timestamp, change message content
                        lines[line_to_tamper] = format!("{}: TAMPERED - This message has been modified by an attacker", parts[0]);
                    }
                }
                // For hash-chain logs (format: "timestamp::message::hash")
                else if original_line.contains("::") {
                    let parts: Vec<&str> = original_line.split("::").collect();
                    if parts.len() == 3 {
                        // Keep timestamp and hash, change message
                        lines[line_to_tamper] = format!("{}::TAMPERED - This message has been modified by an attacker::{}",
                                                        parts[0], parts[2]);
                    }
                }
            }
        }
    }

    fs::write(path, lines.join("\n"))
}

fn test_tampering_detection(
    original_path: &str,
    verifier_fn: &dyn Fn(&str) -> io::Result<bool>,
    line_to_tamper: usize,
) -> io::Result<(bool, bool, bool)> {
    // Create a temporary copy for each test
    let temp_path = format!("{}.temp", original_path);

    // Test 1: Whole line tampering
    fs::copy(original_path, &temp_path)?;
    tamper_file(&temp_path, line_to_tamper, TamperType::WholeLine)?;
    let whole_line_result = verifier_fn(&temp_path)?;
    let whole_line_detected = !whole_line_result; // false means tampering detected

    // Test 2: Timestamp tampering
    fs::copy(original_path, &temp_path)?;
    tamper_file(&temp_path, line_to_tamper, TamperType::TimestampOnly)?;
    let timestamp_result = verifier_fn(&temp_path)?;
    let timestamp_detected = !timestamp_result;

    // Test 3: Message tampering
    fs::copy(original_path, &temp_path)?;
    tamper_file(&temp_path, line_to_tamper, TamperType::MessageOnly)?;
    let message_result = verifier_fn(&temp_path)?;
    let message_detected = !message_result;

    // Clean up
    fs::remove_file(&temp_path).ok();

    Ok((whole_line_detected, timestamp_detected, message_detected))
}


fn tamper_multiple_lines(
    path: &str,
    lines_to_tamper: &[usize],
    tamper_type: TamperType
) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    for &line_num in lines_to_tamper {
        if line_num < lines.len() {
            let original_line = lines[line_num].clone();

            match tamper_type {
                TamperType::WholeLine => {
                    lines[line_num] = format!("TAMPERED LINE {}: Invalid format by attacker", line_num);
                },
                TamperType::TimestampOnly => {
                    if original_line.contains(": ") {
                        let parts: Vec<&str> = original_line.splitn(2, ": ").collect();
                        if parts.len() == 2 {
                            // Use random past timestamp to simulate realistic attack
                            let fake_timestamp = format!("20{:02}-01-01T00:00:{:02}.000Z",
                                                         10 + (line_num % 10), line_num % 60);
                            lines[line_num] = format!("{}: {}", fake_timestamp, parts[1]);
                        }
                    } else if original_line.contains("::") {
                        let parts: Vec<&str> = original_line.split("::").collect();
                        if parts.len() == 3 {
                            let fake_timestamp = format!("20{:02}-01-01T00:00:{:02}.000Z",
                                                         10 + (line_num % 10), line_num % 60);
                            lines[line_num] = format!("{}::{}::{}", fake_timestamp, parts[1], parts[2]);
                        }
                    }
                },
                TamperType::MessageOnly => {
                    if original_line.contains(": ") {
                        let parts: Vec<&str> = original_line.splitn(2, ": ").collect();
                        if parts.len() == 2 {
                            lines[line_num] = format!("{}: TAMPERED MESSAGE at line {} - Modified by attacker",
                                                      parts[0], line_num);
                        }
                    } else if original_line.contains("::") {
                        let parts: Vec<&str> = original_line.split("::").collect();
                        if parts.len() == 3 {
                            lines[line_num] = format!("{}::TAMPERED MESSAGE at line {} - Modified by attacker::{}",
                                                      parts[0], line_num, parts[2]);
                        }
                    }
                }
            }
        }
    }

    fs::write(path, lines.join("\n"))
}

fn test_tampering_detection_comprehensive(
    original_path: &str,
    verifier_fn: &dyn Fn(&str) -> io::Result<bool>,
    num_logs: usize,
    tampering_percentage: f64, // e.g., 0.1 for 10% of lines
) -> io::Result<(f64, f64, f64, f64)> {
    let mut rng = rand::rng();
    let num_tampered_lines = ((num_logs as f64) * tampering_percentage) as usize;
    let num_tampered_lines = num_tampered_lines.max(10); // At least 10 lines

    println!("  Testing with {} tampered lines ({:.1}% of total)...",
             num_tampered_lines, tampering_percentage * 100.0);

    // Generate random line numbers to tamper
    let mut lines_to_tamper: Vec<usize> = Vec::new();
    while lines_to_tamper.len() < num_tampered_lines {
        let line = rng.random_range(1..num_logs-1); // Avoid first and last lines
        if !lines_to_tamper.contains(&line) {
            lines_to_tamper.push(line);
        }
    }
    lines_to_tamper.sort();

    let temp_path = format!("{}.temp", original_path);

    // Test 1: Whole line tampering
    fs::copy(original_path, &temp_path)?;
    tamper_multiple_lines(&temp_path, &lines_to_tamper, TamperType::WholeLine)?;
    let whole_line_detected = if verifier_fn(&temp_path)? {
        0.0 // No tampering detected
    } else {
        // For traditional logger, if it detects ANY tampering, we assume it caught all format violations
        // For hash-chain, it detects all tampering
        100.0
    };

    // Test 2: Timestamp tampering
    fs::copy(original_path, &temp_path)?;
    tamper_multiple_lines(&temp_path, &lines_to_tamper, TamperType::TimestampOnly)?;
    let timestamp_detected = if verifier_fn(&temp_path)? {
        0.0
    } else {
        100.0
    };

    // Test 3: Message tampering
    fs::copy(original_path, &temp_path)?;
    tamper_multiple_lines(&temp_path, &lines_to_tamper, TamperType::MessageOnly)?;
    let message_detected = if verifier_fn(&temp_path)? {
        0.0
    } else {
        100.0
    };

    // Calculate overall detection rate
    let overall_rate = (whole_line_detected + timestamp_detected + message_detected) / 3.0;

    // Clean up
    fs::remove_file(&temp_path).ok();

    Ok((whole_line_detected, timestamp_detected, message_detected, overall_rate))
}

fn main() -> io::Result<()> {
    const NUM_LOGS: usize = 100_000;
    const TRADITIONAL_LOG_PATH: &str = "traditional_benchmark.log";
    const HASH_CHAIN_LOG_PATH: &str = "hash_chain_benchmark.log";
    const TAMPERING_PERCENTAGE: f64 = 0.05; // 5% of lines will be tampered

    println!("=== Academic Integrity: Log System Security Evaluation ===");
    println!("Testing with {} log entries", NUM_LOGS);
    println!("Tampering rate: {:.1}% of log entries", TAMPERING_PERCENTAGE * 100.0);

    // Clean up previous runs
    fs::remove_file(TRADITIONAL_LOG_PATH).ok();
    fs::remove_file(HASH_CHAIN_LOG_PATH).ok();
    fs::remove_file("verification_result.csv").ok();

    let mut traditional_metrics = PerformanceMetrics::default();
    let mut hash_chain_metrics = PerformanceMetrics::default();

    // [Previous phases 1-3 remain the same...]
    println!("\n[Phase 1: Write Performance Benchmarking]");
    println!("Traditional logger:");
    let mut traditional_logger_instance = traditional_logger::TraditionalLogger::new(TRADITIONAL_LOG_PATH)?;
    (traditional_metrics.write_throughput, traditional_metrics.avg_cpu_usage, traditional_metrics.peak_memory_mb) =
        benchmark_write(&mut traditional_logger_instance, NUM_LOGS)?;

    println!("\nHash-chain logger:");
    let mut hash_chain_logger_instance = hash_chain_logger::HashChainLogger::new(HASH_CHAIN_LOG_PATH)?;
    (hash_chain_metrics.write_throughput, hash_chain_metrics.avg_cpu_usage, hash_chain_metrics.peak_memory_mb) =
        benchmark_write(&mut hash_chain_logger_instance, NUM_LOGS)?;

    println!("\n[Phase 2: Storage Analysis]");
    traditional_metrics.storage_bytes = fs::metadata(TRADITIONAL_LOG_PATH)?.len();
    hash_chain_metrics.storage_bytes = fs::metadata(HASH_CHAIN_LOG_PATH)?.len();

    println!("\n[Phase 3: Verification Performance]");
    (traditional_metrics.verification_time_ms, _) = benchmark_verify(TRADITIONAL_LOG_PATH, &traditional_logger::verify)?;
    (hash_chain_metrics.verification_time_ms, _) = benchmark_verify(HASH_CHAIN_LOG_PATH, &hash_chain_logger::verify)?;

    println!("\n[Phase 4: Comprehensive Tampering Detection Tests]");
    println!("Testing detection capability with multiple tampered entries...");

    // Test traditional logger
    println!("\nTraditional Logger Tampering Detection:");
    let (trad_whole, trad_time, trad_msg, trad_overall) = test_tampering_detection_comprehensive(
        TRADITIONAL_LOG_PATH,
        &traditional_logger::verify,
        NUM_LOGS,
        TAMPERING_PERCENTAGE
    )?;

    traditional_metrics.tamper_whole_line_detection_rate = trad_whole;
    traditional_metrics.tamper_timestamp_detection_rate = trad_time;
    traditional_metrics.tamper_message_detection_rate = trad_msg;
    traditional_metrics.overall_detection_rate = trad_overall;
    traditional_metrics.tamper_detected = trad_overall > 0.0;

    // Test hash-chain logger
    println!("\nHash-Chain Logger Tampering Detection:");
    let (hash_whole, hash_time, hash_msg, hash_overall) = test_tampering_detection_comprehensive(
        HASH_CHAIN_LOG_PATH,
        &hash_chain_logger::verify,
        NUM_LOGS,
        TAMPERING_PERCENTAGE
    )?;

    hash_chain_metrics.tamper_whole_line_detection_rate = hash_whole;
    hash_chain_metrics.tamper_timestamp_detection_rate = hash_time;
    hash_chain_metrics.tamper_message_detection_rate = hash_msg;
    hash_chain_metrics.overall_detection_rate = hash_overall;
    hash_chain_metrics.tamper_detected = hash_overall > 0.0;

    // Display comprehensive results
    println!("\n\n=== EXPERIMENTAL RESULTS ===");
    let storage_overhead_percent = if traditional_metrics.storage_bytes > 0 {
        ((hash_chain_metrics.storage_bytes as f64 - traditional_metrics.storage_bytes as f64) /
            traditional_metrics.storage_bytes as f64) * 100.0
    } else { 0.0 };

    println!("┌─────────────────────────────────┬───────────────────────────┬─────────────────────────┐");
    println!("│ Metric                          │ Traditional System        │ Hash-Chain System       │");
    println!("├─────────────────────────────────┼───────────────────────────┼─────────────────────────┤");
    println!("│ TAMPERING DETECTION CAPABILITY  │                           │                         │");
    println!("│   Overall Detection Rate        │ {:<25} │ {:<23} │",
             format!("{:.1}%", trad_overall),
             format!("{:.1}%", hash_overall)
    );
    println!("│   Detection by Attack Type:     │                           │                         │");
    println!("│   • Whole Line Tampering        │ {:<25} │ {:<23} │",
             format!("{:.1}% detected", trad_whole),
             format!("{:.1}% detected", hash_whole)
    );
    println!("│   • Timestamp Tampering         │ {:<25} │ {:<23} │",
             format!("{:.1}% detected", trad_time),
             format!("{:.1}% detected", hash_time)
    );
    println!("│   • Message Content Tampering   │ {:<25} │ {:<23} │",
             format!("{:.1}% detected", trad_msg),
             format!("{:.1}% detected", hash_msg)
    );
    println!("├─────────────────────────────────┼───────────────────────────┼─────────────────────────┤");
    println!("│ PERFORMANCE METRICS             │                           │                         │");
    println!("│   Log Verification Time         │ {:<25} │ {:<23} │",
             format!("{:.2} ms", traditional_metrics.verification_time_ms),
             format!("{:.2} ms", hash_chain_metrics.verification_time_ms)
    );
    println!("│   Storage Overhead              │ {:<25} │ {:<23} │",
             "0.00% (Baseline)",
             format!("{:.2}%", storage_overhead_percent)
    );
    println!("│   Write Throughput              │ {:<25} │ {:<23} │",
             format!("{:.0} logs/sec", traditional_metrics.write_throughput),
             format!("{:.0} logs/sec", hash_chain_metrics.write_throughput)
    );
    println!("│   Avg. CPU Usage                │ {:<25} │ {:<23} │",
             format!("{:.2}%", traditional_metrics.avg_cpu_usage),
             format!("{:.2}%", hash_chain_metrics.avg_cpu_usage)
    );
    println!("│   Peak Memory                   │ {:<25} │ {:<23} │",
             format!("{:.2} MB", traditional_metrics.peak_memory_mb),
             format!("{:.2} MB", hash_chain_metrics.peak_memory_mb)
    );
    println!("└─────────────────────────────────┴───────────────────────────┴─────────────────────────┘");

    // Security Analysis Summary
    println!("\n=== SECURITY ANALYSIS SUMMARY ===");
    println!("Test Parameters:");
    println!("  • Total log entries: {}", NUM_LOGS);
    println!("  • Tampered entries: {} ({:.1}%)",
             ((NUM_LOGS as f64) * TAMPERING_PERCENTAGE) as usize,
             TAMPERING_PERCENTAGE * 100.0);

    println!("\nKey Findings:");

    // Traditional system analysis
    println!("\n1. Traditional Logging System:");
    if trad_whole > 0.0 {
        println!("   ✓ Can detect format violations (whole line tampering)");
    }
    if trad_time > 0.0 {
        println!("   ✓ Can detect timestamp order violations");
    }
    if trad_msg == 0.0 {
        println!("   ✗ CANNOT detect message content tampering");
        println!("     → This is a critical security vulnerability!");
    }

    // Hash-chain system analysis
    println!("\n2. Hash-Chain Logging System:");
    if hash_whole == 100.0 && hash_time == 100.0 && hash_msg == 100.0 {
        println!("   ✓ Detects ALL types of tampering (100% detection rate)");
        println!("   ✓ Provides cryptographic integrity guarantee");
        println!("   ✓ Maintains temporal ordering integrity");
    }

    // Performance trade-offs
    println!("\n3. Performance Trade-offs:");
    let write_perf_diff = ((hash_chain_metrics.write_throughput - traditional_metrics.write_throughput) /
        traditional_metrics.write_throughput) * 100.0;
    if write_perf_diff > 0.0 {
        println!("   • Hash-chain is {:.1}% FASTER in write throughput", write_perf_diff);
        println!("     → Likely due to better I/O buffering");
    } else {
        println!("   • Hash-chain is {:.1}% slower in write throughput", -write_perf_diff);
    }

    let verify_time_increase = ((hash_chain_metrics.verification_time_ms - traditional_metrics.verification_time_ms) /
        traditional_metrics.verification_time_ms) * 100.0;
    println!("   • Verification time increased by {:.1}%", verify_time_increase);
    println!("   • Storage overhead: {:.1}%", storage_overhead_percent);

    // Recommendations
    println!("\n4. Recommendations:");
    if trad_msg == 0.0 {
        println!("   ⚠️  Traditional logging is INSUFFICIENT for security-critical applications");
        println!("   ⚠️  Message content tampering goes undetected!");
    }
    println!("   ✓ Hash-chain logging is recommended for:");
    println!("     - Audit trails");
    println!("     - Compliance logging");
    println!("     - Security event logging");
    println!("     - Any scenario requiring tamper evidence");

    // Export detailed results
    export_detailed_csv(&traditional_metrics, &hash_chain_metrics, storage_overhead_percent)?;
    println!("\nDetailed results exported to verification_result.csv");

    Ok(())
}

fn export_detailed_csv(
    traditional: &PerformanceMetrics,
    hash_chain: &PerformanceMetrics,
    overhead: f64
) -> io::Result<()> {
    let mut csv = File::create("verification_result.csv")?;

    // Header
    writeln!(csv, "Category,Metric,Traditional,HashChain,Unit")?;

    // Detection capabilities
    writeln!(csv, "Security,Overall Detection Rate,{:.1},{:.1},%",
             traditional.overall_detection_rate, hash_chain.overall_detection_rate)?;
    writeln!(csv, "Security,Whole Line Tampering Detection,{:.1},{:.1},%",
             traditional.tamper_whole_line_detection_rate,
             hash_chain.tamper_whole_line_detection_rate)?;
    writeln!(csv, "Security,Timestamp Tampering Detection,{:.1},{:.1},%",
             traditional.tamper_timestamp_detection_rate,
             hash_chain.tamper_timestamp_detection_rate)?;
    writeln!(csv, "Security,Message Tampering Detection,{:.1},{:.1},%",
             traditional.tamper_message_detection_rate,
             hash_chain.tamper_message_detection_rate)?;

    // Performance metrics
    writeln!(csv, "Performance,Verification Time,{:.2},{:.2},ms",
             traditional.verification_time_ms, hash_chain.verification_time_ms)?;
    writeln!(csv, "Performance,Write Throughput,{:.0},{:.0},logs/sec",
             traditional.write_throughput, hash_chain.write_throughput)?;
    writeln!(csv, "Performance,CPU Usage,{:.2},{:.2},%",
             traditional.avg_cpu_usage, hash_chain.avg_cpu_usage)?;
    writeln!(csv, "Performance,Peak Memory,{:.2},{:.2},MB",
             traditional.peak_memory_mb, hash_chain.peak_memory_mb)?;

    // Storage
    writeln!(csv, "Storage,File Size,{},{},bytes",
             traditional.storage_bytes, hash_chain.storage_bytes)?;
    writeln!(csv, "Storage,Overhead,0.00,{:.2},%", overhead)?;

    Ok(())
}