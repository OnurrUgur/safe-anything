use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use safe_anything::{Options, Severity, report};

#[derive(Parser)]
#[command(
    version,
    about = "Find vulnerabilities in any app, and in the AI agent setup that builds it."
)]
struct Cli {
    /// Folder or file to scan
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Print the report as JSON
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// Print the report as SARIF 2.1.0 (GitHub code scanning)
    #[arg(long)]
    sarif: bool,
    /// Skip the dependency check (no network)
    #[arg(long)]
    offline: bool,
    /// Lowest severity to report: low, medium, high, critical
    #[arg(long, default_value = "low", value_parser = parse_severity)]
    severity: Severity,
    /// Exit with 1 when a finding is at least this severe: low, medium, high, critical, never
    #[arg(long, default_value = "high")]
    fail_on: String,
    /// Also report findings in test, spec and fixture files (by default only real tokens and keys count there)
    #[arg(long)]
    include_tests: bool,
    /// List every rule and exit
    #[arg(long)]
    list_rules: bool,
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    Severity::parse(s)
        .ok_or_else(|| format!("unknown severity `{s}` (low, medium, high, critical)"))
}

/// GitHub code scanning reads SARIF paths from the repository root, so they start at the working
/// directory (where the action runs) instead of the scanned folder. This is that folder as a
/// `dir/` prefix, or nothing when it is the working directory or lies outside it.
fn sarif_prefix(root: &Path) -> String {
    let dir = match root.parent() {
        Some(parent) if root.is_file() => parent,
        _ => root,
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(cwd) = std::env::current_dir() else {
        return String::new();
    };
    let plain = std::path::absolute(dir)
        .ok()
        .filter(|p| !p.components().any(|c| c == Component::ParentDir))
        .and_then(|p| p.strip_prefix(&cwd).ok().map(Path::to_path_buf));
    // `..`, or a symlink like macOS's /tmp, needs the real paths.
    let rel = plain.or_else(|| {
        let (dir, cwd) = (dir.canonicalize().ok()?, cwd.canonicalize().ok()?);
        dir.strip_prefix(cwd).ok().map(Path::to_path_buf)
    });
    rel.map(|p| {
        p.components()
            .map(|c| format!("{}/", c.as_os_str().to_string_lossy()))
            .collect()
    })
    .unwrap_or_default()
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("mcp") {
        return match safe_anything::mcp::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    let cli = Cli::parse();
    if cli.list_rules {
        let rules = safe_anything::rules();
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&rules).unwrap());
        } else {
            for r in rules {
                println!(
                    "{:<36} {:<9} {:<9} {}",
                    r.id,
                    r.severity.as_str(),
                    r.cwe,
                    r.message
                );
            }
        }
        return ExitCode::SUCCESS;
    }
    let fail_on = match cli.fail_on.as_str() {
        "never" => None,
        s => match Severity::parse(s) {
            Some(s) => Some(s),
            None => {
                eprintln!("error: unknown --fail-on `{s}` (low, medium, high, critical, never)");
                return ExitCode::from(2);
            }
        },
    };
    let mut options = if cli.offline {
        Options::offline()
    } else {
        Options::online()
    };
    options.include_tests = cli.include_tests;
    let mut report = match safe_anything::scan(&cli.path, &options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    report.findings.retain(|f| f.severity >= cli.severity);
    if cli.sarif {
        let prefix = sarif_prefix(&cli.path);
        for f in &mut report.findings {
            f.path = format!("{prefix}{}", f.path);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&safe_anything::sarif::render(&report)).unwrap()
        );
    } else if cli.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        print!("{}", report::terminal(&report, &report::Style { color }));
    }
    let failed = fail_on.is_some_and(|t| report.findings.iter().any(|f| f.severity >= t));
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
