//! Renders the timeline as a single, self-contained HTML page.
//!
//! Everything — markup, styles, and the small amount of script — is inlined, and
//! all content is escaped and embedded at generation time. The page loads no
//! fonts, scripts, or styles from the network, so reviewing a recording never
//! sends anything anywhere. It is written to disk and opened locally.

use std::fmt::Write as _;

use similar::{ChangeTag, TextDiff};

use crate::error::Error;
use crate::store::{LogEntry, Store};
use crate::timeline::Integrity;

// Cap the diff shown per file so one huge change can't bloat the page.
const MAX_DIFF_LINES: usize = 400;

/// Builds the complete HTML review page for a recorded timeline.
pub fn review_html(
    store: &Store,
    entries: &[LogEntry],
    integrity: &Integrity,
) -> Result<String, Error> {
    let mut body = String::new();
    for entry in entries {
        card(&mut body, store, entry)?;
    }
    if entries.is_empty() {
        body.push_str("<p class=\"empty\">No actions recorded yet.</p>");
    }

    let (banner_class, banner_text) = match integrity {
        Integrity::Ok { entries } => (
            "ok",
            format!("Tamper-evident chain intact · {entries} actions"),
        ),
        Integrity::Broken { seq, reason } => (
            "bad",
            format!("TAMPERED — chain breaks at #{seq}: {}", esc(reason)),
        ),
    };

    let counts = tally(entries);
    Ok(page(banner_class, &banner_text, &counts, &body))
}

fn card(out: &mut String, store: &Store, entry: &LogEntry) -> Result<(), Error> {
    let kind = if entry.file.is_some() {
        "file"
    } else if entry.command.is_some() {
        "command"
    } else {
        "other"
    };
    let _ = write!(
        out,
        "<div class=\"card {kind}\"><div class=\"meta\">\
         <span class=\"seq\">#{}</span><span class=\"tool\">{}</span>\
         <span class=\"summary\">{}</span></div>",
        entry.seq,
        esc(&entry.tool),
        esc(&entry.summary),
    );

    if let Some(file) = &entry.file {
        let before = blob_text(store, file.before.as_deref())?;
        let after = blob_text(store, file.after.as_deref())?;
        out.push_str("<pre class=\"diff\">");
        diff_html(out, &before, &after);
        out.push_str("</pre>");
    }
    if let Some(cmd) = &entry.command {
        let _ = write!(out, "<pre class=\"cmd\">$ {}</pre>", esc(&cmd.command));
        if let Some(exit) = cmd.exit {
            let cls = if exit == 0 { "exit-ok" } else { "exit-bad" };
            let _ = write!(out, "<div class=\"{cls}\">exit {exit}</div>");
        }
        if let Some(output) = &cmd.output {
            let _ = write!(out, "<pre class=\"output\">{}</pre>", esc(output));
        }
    }

    out.push_str("</div>");
    Ok(())
}

fn diff_html(out: &mut String, before: &str, after: &str) {
    let diff = TextDiff::from_lines(before, after);
    let mut shown = 0usize;
    for change in diff.iter_all_changes() {
        if shown >= MAX_DIFF_LINES {
            out.push_str("<span class=\"trunc\">… diff truncated</span>\n");
            break;
        }
        let (cls, sign) = match change.tag() {
            ChangeTag::Delete => ("del", '-'),
            ChangeTag::Insert => ("add", '+'),
            ChangeTag::Equal => ("eq", ' '),
        };
        let line = change.value().trim_end_matches('\n');
        let _ = writeln!(out, "<span class=\"{cls}\">{sign} {}</span>", esc(line));
        shown += 1;
    }
    if shown == 0 {
        out.push_str("<span class=\"eq\">(no textual change)</span>");
    }
}

fn tally(entries: &[LogEntry]) -> String {
    let files = entries.iter().filter(|e| e.file.is_some()).count();
    let commands = entries.iter().filter(|e| e.command.is_some()).count();
    format!("{files} file changes · {commands} commands")
}

fn blob_text(store: &Store, hash: Option<&str>) -> Result<String, Error> {
    match hash {
        Some(h) => Ok(String::from_utf8_lossy(&store.get_blob(h)?).into_owned()),
        None => Ok(String::new()),
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn page(banner_class: &str, banner_text: &str, counts: &str, body: &str) -> String {
    // Kept as one inlined document: no external fonts, scripts, or styles.
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentrec review</title>
<style>
:root {{
  --bg:#f6f7f9; --fg:#1a1c20; --card:#ffffff; --border:#e3e6ea; --muted:#6b7280;
  --accent:#3b5bdb; --ok:#2f9e44; --bad:#e03131;
  --add-fg:#137333; --add-bg:#e6ffed; --del-fg:#b31d28; --del-bg:#ffeef0;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg:#0e1014; --fg:#e6e8eb; --card:#161a21; --border:#262b36; --muted:#9aa0aa;
    --accent:#7aa2f7; --ok:#4ade80; --bad:#f87171;
    --add-fg:#7ee2a8; --add-bg:#0f2a1a; --del-fg:#f8a5a5; --del-bg:#2a1216;
  }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:920px; margin:0 auto; padding:24px 16px 64px; }}
h1 {{ font-size:18px; margin:0 0 2px; }}
.sub {{ color:var(--muted); font-size:13px; }}
.banner {{ margin:16px 0; padding:10px 14px; border-radius:8px; font-weight:600;
  border:1px solid var(--border); }}
.banner.ok {{ color:var(--ok); }}
.banner.bad {{ color:var(--bad); border-color:var(--bad); }}
.filters {{ margin:0 0 16px; display:flex; gap:8px; }}
.filters button {{ font:inherit; cursor:pointer; padding:5px 12px; border-radius:999px;
  border:1px solid var(--border); background:var(--card); color:var(--fg); }}
.filters button.active {{ border-color:var(--accent); color:var(--accent); }}
.card {{ background:var(--card); border:1px solid var(--border); border-left:3px solid var(--muted);
  border-radius:8px; padding:12px 14px; margin:12px 0; overflow:hidden; }}
.card.file {{ border-left-color:var(--accent); }}
.card.command {{ border-left-color:var(--muted); }}
.meta {{ display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; }}
.seq {{ color:var(--muted); font-variant-numeric:tabular-nums; }}
.tool {{ font-weight:700; }}
.summary {{ color:var(--muted); }}
pre {{ margin:10px 0 0; padding:10px; border-radius:6px; overflow-x:auto;
  font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:rgba(127,127,127,.06); }}
.diff span {{ display:block; white-space:pre-wrap; word-break:break-word; }}
.diff .add {{ color:var(--add-fg); background:var(--add-bg); }}
.diff .del {{ color:var(--del-fg); background:var(--del-bg); }}
.diff .eq {{ color:var(--muted); }}
.diff .trunc {{ color:var(--muted); font-style:italic; }}
.cmd {{ font-weight:600; }}
.exit-ok {{ color:var(--ok); font-size:12px; margin-top:6px; }}
.exit-bad {{ color:var(--bad); font-size:12px; margin-top:6px; }}
.output {{ color:var(--muted); }}
.empty {{ color:var(--muted); }}
.foot {{ margin-top:28px; color:var(--muted); font-size:12px; }}
body.hide-file .card.file {{ display:none; }}
body.hide-command .card.command {{ display:none; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>agentrec review</h1>
  <div class="sub">{counts}</div>
  <div class="banner {banner_class}">{banner_text}</div>
  <div class="filters">
    <button data-f="all" class="active">All</button>
    <button data-f="file">Files</button>
    <button data-f="command">Commands</button>
  </div>
  {body}
  <div class="foot">Generated locally by agentrec — nothing left your machine.</div>
</div>
<script>
(function() {{
  var btns = document.querySelectorAll('.filters button');
  btns.forEach(function(b) {{
    b.addEventListener('click', function() {{
      btns.forEach(function(x) {{ x.classList.remove('active'); }});
      b.classList.add('active');
      var f = b.getAttribute('data-f');
      document.body.classList.toggle('hide-file', f === 'command');
      document.body.classList.toggle('hide-command', f === 'file');
    }});
  }});
}})();
</script>
</body>
</html>
"#
    )
}
