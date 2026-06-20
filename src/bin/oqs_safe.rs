use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "oqs-safe")]
#[command(version)]
#[command(about = "Post-Quantum Cryptography migration helper for Rust projects")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit a Rust project for PQC migration readiness
    Audit {
        /// Project path to audit
        path: PathBuf,

        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Exit with code 1 when findings are detected
        #[arg(long)]
        fail_on_findings: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize)]
struct Finding {
    dependency: String,
    category: String,
    severity: String,
    reason: String,
    recommendation: String,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    status: String,
    project_path: String,
    scanned_files: Vec<String>,
    findings: Vec<Finding>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            path,
            format,
            fail_on_findings,
        } => {
            let report = audit_project(&path);

            match format {
                OutputFormat::Text => print_text_report(&report),
                OutputFormat::Json => print_json_report(&report),
            }

            if fail_on_findings && !report.findings.is_empty() {
                std::process::exit(1);
            }
        }
    }
}

fn audit_project(path: &Path) -> AuditReport {
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    let cargo_toml = canonical_path.join("Cargo.toml");
    let cargo_lock = canonical_path.join("Cargo.lock");

    let mut scanned_files = Vec::new();
    let mut content = String::new();

    if cargo_toml.exists() {
        match fs::read_to_string(&cargo_toml) {
            Ok(file_content) => {
                scanned_files.push(cargo_toml.display().to_string());
                content.push_str(&file_content);
                content.push('\n');
            }
            Err(error) => {
                eprintln!(
                    "Warning: failed to read {}: {}",
                    cargo_toml.display(),
                    error
                );
            }
        }
    }

    if cargo_lock.exists() {
        match fs::read_to_string(&cargo_lock) {
            Ok(file_content) => {
                scanned_files.push(cargo_lock.display().to_string());
                content.push_str(&file_content);
                content.push('\n');
            }
            Err(error) => {
                eprintln!(
                    "Warning: failed to read {}: {}",
                    cargo_lock.display(),
                    error
                );
            }
        }
    }

    let dependencies = extract_dependency_names(&content);
    let mut findings = Vec::new();

    for dependency in dependencies {
        if let Some(finding) = finding_for_dependency(&dependency) {
            findings.push(finding);
        }
    }

    let status = if scanned_files.is_empty() {
        "NO_CARGO_FILES_FOUND"
    } else if findings.is_empty() {
        "PASS"
    } else {
        "REVIEW_REQUIRED"
    };

    AuditReport {
        status: status.to_string(),
        project_path: canonical_path.display().to_string(),
        scanned_files,
        findings,
    }
}

fn extract_dependency_names(content: &str) -> BTreeSet<String> {
    let known_crypto_dependencies = [
        "rsa",
        "ring",
        "openssl",
        "openssl-sys",
        "p256",
        "p384",
        "k256",
        "x25519-dalek",
        "ed25519-dalek",
        "secp256k1",
        "ecdsa",
        "elliptic-curve",
    ];

    let mut found = BTreeSet::new();

    for dependency in known_crypto_dependencies {
        let cargo_toml_simple = format!("{dependency} =");
        let cargo_lock_package = format!("name = \"{dependency}\"");
        let quoted_dependency = format!("\"{dependency}\"");

        if content.contains(&cargo_toml_simple)
            || content.contains(&cargo_lock_package)
            || content.contains(&quoted_dependency)
        {
            found.insert(dependency.to_string());
        }
    }

    found
}

fn finding_for_dependency(dependency: &str) -> Option<Finding> {
    let finding = match dependency {
        "rsa" => Finding {
            dependency: dependency.to_string(),
            category: "classical-public-key-crypto".to_string(),
            severity: "high".to_string(),
            reason: "RSA is quantum-vulnerable for public-key encryption and signatures."
                .to_string(),
            recommendation:
                "Add RSA usage to the crypto inventory and plan migration to PQC or hybrid alternatives."
                    .to_string(),
        },
        "ring" => Finding {
            dependency: dependency.to_string(),
            category: "classical-crypto-provider".to_string(),
            severity: "medium".to_string(),
            reason: "ring commonly provides classical TLS and cryptographic primitives.".to_string(),
            recommendation:
                "Review actual ring usage and document whether RSA, ECDSA, ECDH, Ed25519, or X25519 is used."
                    .to_string(),
        },
        "openssl" | "openssl-sys" => Finding {
            dependency: dependency.to_string(),
            category: "classical-crypto-provider".to_string(),
            severity: "medium".to_string(),
            reason: "OpenSSL usage may include RSA, ECDSA, ECDH, Ed25519, or X25519."
                .to_string(),
            recommendation:
                "Review OpenSSL usage, identify public-key algorithms, and record migration requirements."
                    .to_string(),
        },
        "p256" => Finding {
            dependency: dependency.to_string(),
            category: "elliptic-curve-crypto".to_string(),
            severity: "high".to_string(),
            reason: "P-256 elliptic curve cryptography is quantum-vulnerable.".to_string(),
            recommendation:
                "Add P-256 usage to the crypto inventory and evaluate ML-DSA or hybrid migration."
                    .to_string(),
        },
        "p384" => Finding {
            dependency: dependency.to_string(),
            category: "elliptic-curve-crypto".to_string(),
            severity: "high".to_string(),
            reason: "P-384 elliptic curve cryptography is quantum-vulnerable.".to_string(),
            recommendation:
                "Add P-384 usage to the crypto inventory and evaluate ML-DSA or hybrid migration."
                    .to_string(),
        },
        "k256" | "secp256k1" => Finding {
            dependency: dependency.to_string(),
            category: "elliptic-curve-crypto".to_string(),
            severity: "high".to_string(),
            reason: "secp256k1-style elliptic curve cryptography is quantum-vulnerable.".to_string(),
            recommendation:
                "Add secp256k1 usage to the crypto inventory and plan a PQC-aware migration path."
                    .to_string(),
        },
        "x25519-dalek" => Finding {
            dependency: dependency.to_string(),
            category: "classical-key-exchange".to_string(),
            severity: "medium".to_string(),
            reason: "X25519 is classical key exchange and should be hybridized for PQC migration."
                .to_string(),
            recommendation:
                "Use hybrid X25519 + ML-KEM and bind the handshake transcript before deriving session keys."
                    .to_string(),
        },
        "ed25519-dalek" => Finding {
            dependency: dependency.to_string(),
            category: "classical-signature".to_string(),
            severity: "high".to_string(),
            reason: "Ed25519 signatures require PQC migration planning for long-term security."
                .to_string(),
            recommendation:
                "Add Ed25519 usage to the crypto inventory and evaluate ML-DSA for long-lived signatures."
                    .to_string(),
        },
        "ecdsa" => Finding {
            dependency: dependency.to_string(),
            category: "classical-signature".to_string(),
            severity: "high".to_string(),
            reason: "ECDSA signatures are quantum-vulnerable.".to_string(),
            recommendation:
                "Add ECDSA usage to the crypto inventory and evaluate ML-DSA for future migration."
                    .to_string(),
        },
        "elliptic-curve" => Finding {
            dependency: dependency.to_string(),
            category: "elliptic-curve-crypto".to_string(),
            severity: "high".to_string(),
            reason: "Elliptic curve cryptography is quantum-vulnerable for public-key security."
                .to_string(),
            recommendation:
                "Identify the specific curve and usage, then document a PQC or hybrid migration path."
                    .to_string(),
        },
        _ => return None,
    };

    Some(finding)
}

fn print_text_report(report: &AuditReport) {
    println!("PQC Migration Readiness Report");
    println!();
    println!("Project: {}", report.project_path);
    println!("Status: {}", report.status);
    println!();

    if report.scanned_files.is_empty() {
        println!("No Cargo.toml or Cargo.lock file was found at the provided project path.");
        return;
    }

    println!("Scanned files:");
    for scanned_file in &report.scanned_files {
        println!("- {}", scanned_file);
    }

    println!();

    if report.findings.is_empty() {
        println!("No known classical public-key cryptography dependencies were detected.");
        return;
    }

    println!("Findings:");
    for finding in &report.findings {
        println!("- {}", finding.dependency);
        println!("  Category: {}", finding.category);
        println!("  Severity: {}", finding.severity);
        println!("  Reason: {}", finding.reason);
        println!("  Recommendation: {}", finding.recommendation);
    }
}

fn print_json_report(report: &AuditReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("Failed to serialize audit report: {error}");
            std::process::exit(1);
        }
    }
}
