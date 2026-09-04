//! The agentrec command-line interface.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use agentrec::render;
use agentrec::{HookEvent, HookOutcome, Store, handle, load, revert, review_html, verify};

#[derive(Debug, Parser)]
#[command(name = "agentrec", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Record one hook event read as JSON from stdin (invoked by the agent).
    Hook,
    /// Install the recorder's hooks into a Claude Code settings.json.
    Init {
        /// Install into the user settings (~/.claude) instead of this project.
        #[arg(long)]
        user: bool,
    },
    /// List the recorded actions for this project.
    Log,
    /// Show one recorded action in detail.
    Show { seq: u64 },
    /// Show the before/after diff of a recorded file change.
    Diff { seq: u64 },
    /// Verify the tamper-evident hash chain.
    Verify,
    /// Undo a recorded file change, restoring the file to its earlier content.
    Revert {
        seq: u64,
        /// Show what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Write a self-contained HTML view of the timeline and print its path.
    Review {
        /// Open the page in the default browser.
        #[arg(long)]
        open: bool,
    },
    /// Record every file change under a directory made by any tool (no hooks).
    Watch {
        /// Directory to watch (defaults to the current directory).
        path: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // The hook exits 0 for everything except a deliberate guardrail block, which
    // exits 2 so Claude Code refuses the tool call. An internal error never
    // disrupts the agent — it is swallowed and treated as "proceed".
    if matches!(cli.command, Command::Hook) {
        return run_hook();
    }

    match run(&cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("agentrec: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run_hook() -> ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return ExitCode::SUCCESS;
    }
    match HookEvent::from_reader(input.as_bytes()).map(|e| handle(&e)) {
        Ok(Ok(HookOutcome::Blocked(reason))) => {
            // stderr on a PreToolUse hook with exit 2 is shown to the agent.
            eprintln!("agentrec blocked this action — {reason}");
            ExitCode::from(2)
        }
        _ => ExitCode::SUCCESS,
    }
}

fn run(command: &Command) -> Result<()> {
    match command {
        Command::Hook => unreachable!("handled in main"),
        Command::Init { user } => {
            let path = init_hooks(*user)?;
            println!("Installed agentrec hooks into {}", path.display());
            println!("Restart Claude Code (or reload settings) to start recording.");
            Ok(())
        }
        Command::Log => {
            let store = open_store()?;
            let entries = load(&store).context("reading the log")?;
            print!("{}", render::log(&entries, use_color()));
            Ok(())
        }
        Command::Show { seq } => {
            let store = open_store()?;
            let entry = find(&store, *seq)?;
            print!("{}", render::show(&entry, use_color()));
            Ok(())
        }
        Command::Diff { seq } => {
            let store = open_store()?;
            let entry = find(&store, *seq)?;
            print!("{}", render::diff(&store, &entry, use_color())?);
            Ok(())
        }
        Command::Verify => {
            let store = open_store()?;
            let integrity = verify(&store).context("verifying the chain")?;
            print!("{}", render::verify(&integrity, use_color()));
            Ok(())
        }
        Command::Revert { seq, dry_run } => {
            let store = open_store()?;
            let entry = find(&store, *seq)?;
            let outcome = revert(&store, &entry, *dry_run)?;
            print!("{}", render::revert(&outcome, use_color()));
            Ok(())
        }
        Command::Review { open } => {
            let store = open_store()?;
            let entries = load(&store).context("reading the log")?;
            let integrity = verify(&store).context("verifying the chain")?;
            let html = review_html(&store, &entries, &integrity).context("building the page")?;
            let path = store.root().join("review.html");
            std::fs::write(&path, html).with_context(|| format!("writing {}", path.display()))?;
            println!("Wrote {}", path.display());
            if *open {
                open_in_browser(&path);
            }
            Ok(())
        }
        Command::Watch { path } => {
            let root = match path {
                Some(p) => p.clone(),
                None => std::env::current_dir().context("resolving the current directory")?,
            };
            if !root.is_dir() {
                anyhow::bail!("not a directory: {}", root.display());
            }
            agentrec::watch(&root).context("watching the directory")?;
            Ok(())
        }
    }
}

// Best-effort launch of the OS default browser; failure is non-fatal.
fn open_in_browser(path: &std::path::Path) {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    let _ = cmd.arg(path).spawn();
}

fn open_store() -> Result<Store> {
    let cwd = std::env::current_dir().context("resolving the current directory")?;
    Store::open(&cwd.to_string_lossy()).with_context(|| {
        format!(
            "no recording for {} yet — run `agentrec init` and use your agent",
            cwd.display()
        )
    })
}

fn find(store: &Store, seq: u64) -> Result<agentrec::LogEntry> {
    load(store)?
        .into_iter()
        .find(|e| e.seq == seq)
        .with_context(|| format!("no entry #{seq}"))
}

// --- hook installation ---

fn init_hooks(user: bool) -> Result<PathBuf> {
    let dir = if user {
        home_dir().join(".claude")
    } else {
        std::env::current_dir()?.join(".claude")
    };
    std::fs::create_dir_all(&dir).context("creating the .claude directory")?;
    let path = dir.join("settings.json");

    let mut root: Value = if path.is_file() {
        let text = std::fs::read_to_string(&path).context("reading settings.json")?;
        serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !root.is_object() {
        root = json!({});
    }

    let exe = std::env::current_exe().context("locating the agentrec binary")?;
    let command = format!("\"{}\" hook", exe.display());

    let hooks = root
        .as_object_mut()
        .expect("root is an object")
        .entry("hooks")
        .or_insert_with(|| json!({}));
    // PreToolUse fires for every tool: file tools get a before-snapshot, and Bash
    // (and any tool) is assessed by the guardrail. PostToolUse records the result.
    ensure_hook(hooks, "PreToolUse", None, &command);
    ensure_hook(hooks, "PostToolUse", None, &command);

    let text = serde_json::to_string_pretty(&root).context("serializing settings.json")?;
    std::fs::write(&path, format!("{text}\n")).context("writing settings.json")?;
    Ok(path)
}

// Ensure `hooks[event]` contains a group that runs `command`, without disturbing
// any hooks the user already configured.
fn ensure_hook(hooks: &mut Value, event: &str, matcher: Option<&str>, command: &str) {
    let groups = hooks
        .as_object_mut()
        .expect("hooks is an object")
        .entry(event)
        .or_insert_with(|| json!([]));
    let Some(array) = groups.as_array_mut() else {
        return;
    };

    let already = array.iter().any(|g| {
        g.get("hooks").and_then(Value::as_array).is_some_and(|hs| {
            hs.iter()
                .any(|h| h.get("command").and_then(Value::as_str) == Some(command))
        })
    });
    if already {
        return;
    }

    let mut group = json!({ "hooks": [ { "type": "command", "command": command } ] });
    if let Some(m) = matcher {
        group
            .as_object_mut()
            .unwrap()
            .insert("matcher".to_owned(), json!(m));
    }
    array.push(group);
}

fn home_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home)
}

fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}
