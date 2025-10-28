# Audit Trail Logger (Rust Implementation)

This repository contains the full Rust implementation used for the experiments in the paper
**"A Comparative Analysis of the Effectiveness of Hash-Chain-Based and Traditional Logging Audit Trail Systems in Detecting Data Manipulation."**

The program implements and benchmarks two logging mechanisms:

1. **Traditional Logger**: appends plaintext logs without integrity protection.
2. **Hash-Chain Logger**: appends logs where each entry cryptographically includes the previous entry’s hash, ensuring tamper-evident integrity.

The code measures **tampering detection rate, verification time, throughput, CPU/memory usage, and storage overhead** under controlled modification attacks.

---

## Repository Structure

```
audit_trail_logger/
│
├── Cargo.toml          # Project manifest defining dependencies and metadata
├── Cargo.lock          # Auto-generated lock file
└── src/
    └── main.rs         # Main source file (~720 lines)
```

---

## 1. Features

* Implements **two complete logging systems** in Rust:

  * A **traditional plain-text logger**
  * A **SHA-256-based hash-chain logger**
* Simulates **three attack types**:
  *(1) whole-line deletion/replacement, (2) timestamp modification, (3) message alteration)*
* Computes detailed **performance metrics**:

  * Detection accuracy
  * Verification time (ms)
  * Write throughput (logs/sec)
  * CPU and memory usage
  * Storage overhead (%)
* Outputs all benchmark results into a CSV file (`verification_result.csv`).

---

## 2. Requirements

* **Rust Toolchain** (stable, 1.86 recommended)
  Install from [https://rustup.rs](https://rustup.rs)

### Dependencies

All dependencies are defined in `Cargo.toml`, including:

* `chrono`
* `rand`
* `sha2`
* `sysinfo`

Run the following once after cloning to fetch dependencies:

```bash
cargo build
```

---

## 3. Building and Running

### Clone this repository

```bash
git clone https://github.com/AchLim/audit_trail_logger.git
cd audit_trail_logger
```

### Build in release mode

```bash
cargo build --release
```

### Run the experiment

```bash
cargo run --release
```

The program automatically:

1. Generates synthetic log data (100,000 entries by default)
2. Performs controlled tampering on 5% of entries
3. Compares the two systems across all defined metrics
4. Exports results to `verification_result.csv`

---

## 4. Output

After execution, you will see tabular summaries in the terminal, for example:

```
=== EXPERIMENTAL RESULTS ===
│ Metric                          │ Traditional System        │ Hash-Chain System       │
│   Overall Detection Rate        │ 67.0%                     │ 100.0%                 │
│   Verification Time             │ 24.14 ms                  │ 59.10 ms               │
│   Storage Overhead              │ 0.00%                     │ 135.71%                │
```

A detailed report is saved as `verification_result.csv`, containing all performance and security metrics.

---

## 5. Citation

If you use this implementation in your academic work, please cite the corresponding paper:

> V. Lim et al., *A Comparative Analysis of the Effectiveness of Hash-Chain-Based and Traditional Logging Audit Trail Systems in Detecting Data Manipulation*, 2025.

---

## 6. License

This project is released under the **MIT License**. See `LICENSE` for details.
