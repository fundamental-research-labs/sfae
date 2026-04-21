//! Cross-platform CI driver: shells out to a fixed table of cargo steps and runs the in-tree linters.

use std::process::{Command, ExitCode};

mod checks;

/// One named CI step and the shell command it invokes.
struct Step<'a> {
    name: &'a str,
    cmd: &'a [&'a str],
}

const STEPS: &[Step<'static>] = &[
    Step {
        name: "fmt",
        cmd: &["cargo", "fmt", "--all", "--check"],
    },
    Step {
        name: "clippy",
        cmd: &["cargo", "clippy", "--workspace", "--", "-D", "warnings"],
    },
    Step {
        name: "test",
        cmd: &["cargo", "test", "--workspace"],
    },
    Step {
        name: "doc",
        cmd: &["cargo", "doc", "--workspace", "--no-deps"],
    },
    Step {
        name: "lint",
        cmd: &["cargo", "xtask", "lint"],
    },
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("ci") => run_ci(),
        Some("lint") => run_lint(),
        Some(name) => match STEPS.iter().find(|s| s.name == name) {
            Some(step) => run_step(step),
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
    eprintln!("  ci       Run all CI checks (fmt, clippy, test, doc, lint)");
    eprintln!("  lint     Run xtask lint checks (file length, docstring, fn params)");
    for step in STEPS {
        eprintln!("  {:<8} Run {} only", step.name, step.name);
    }
    ExitCode::FAILURE
}

fn run_ci() -> ExitCode {
    for step in STEPS {
        let code = run_step(step);
        if code != ExitCode::SUCCESS {
            return code;
        }
    }

    eprintln!("\n✓ All checks passed");
    ExitCode::SUCCESS
}

fn run_step(step: &Step<'_>) -> ExitCode {
    let Step { name, cmd } = step;
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
