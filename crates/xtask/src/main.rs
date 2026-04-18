use std::process::{Command, ExitCode};

mod checks;

const STEPS: &[(&str, &[&str])] = &[
    ("fmt", &["cargo", "fmt", "--all", "--check"]),
    (
        "clippy",
        &["cargo", "clippy", "--workspace", "--", "-D", "warnings"],
    ),
    ("test", &["cargo", "test", "--workspace"]),
    ("doc", &["cargo", "doc", "--workspace", "--no-deps"]),
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("ci") => run_ci(),
        Some("lint") => run_lint(),
        Some(name) => match STEPS.iter().find(|(n, _)| *n == name) {
            Some((name, cmd)) => run_step(name, cmd),
            None => {
                eprintln!("unknown command: {name}");
                usage()
            }
        },
        None => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  ci       Run all CI checks (fmt, clippy, test, doc)");
    eprintln!("  lint     Run xtask lint checks (file length, docstring, fn params)");
    for (name, _) in STEPS {
        eprintln!("  {name:<8} Run {name} only");
    }
    ExitCode::FAILURE
}

fn run_ci() -> ExitCode {
    for (name, cmd) in STEPS {
        let code = run_step(name, cmd);
        if code != ExitCode::SUCCESS {
            return code;
        }
    }

    eprintln!("\n✓ All checks passed");
    ExitCode::SUCCESS
}

fn run_step(name: &str, cmd: &[&str]) -> ExitCode {
    eprintln!("\n--- {name} ---");
    let status = Command::new(cmd[0]).args(&cmd[1..]).status();

    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            eprintln!("✗ {name} failed (exit {})", s.code().unwrap_or(-1));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("✗ {name} failed to run: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_lint() -> ExitCode {
    eprintln!("\n--- lint ---");
    let files = checks::walk();
    let violations = checks::run_all(&files);

    if violations.is_empty() {
        eprintln!("✓ lint: no violations ({} files scanned)", files.len());
        ExitCode::SUCCESS
    } else {
        for v in &violations {
            eprintln!("{}:{} — {}", v.path.display(), v.line, v.message);
        }
        eprintln!("\n✗ lint: {} violation(s)", violations.len());
        ExitCode::FAILURE
    }
}
