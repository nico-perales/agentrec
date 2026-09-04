//! Network-intent extraction: the hosts a recorded action reaches out to.
//!
//! agentrec observes via hooks and never runs anything, so it can't capture the
//! packets a process actually sends. What it CAN do, honestly and offline, is read
//! the hosts a command or an edited file *references* — the `http(s)://…` URLs it
//! contacts, the `git@host:` remote it pushes to. This is intent from the text,
//! not an observed connection: a compiled binary or an obfuscated script could
//! reach somewhere the text never names.

use std::collections::BTreeSet;

/// The distinct hosts referenced in `text` (a command line or file contents).
#[must_use]
pub fn extract_hosts(text: &str) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    collect_scheme_hosts(text, &mut hosts);
    collect_scp_hosts(text, &mut hosts);
    hosts.into_iter().collect()
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

// Hosts from `scheme://host…` URLs (http, https, ws, ftp, git, ssh, …).
fn collect_scheme_hosts(text: &str, out: &mut BTreeSet<String>) {
    let mut base = 0;
    while let Some(rel) = text[base..].find("://") {
        let start = base + rel + 3;
        let host: String = text[start..]
            .chars()
            .take_while(|&c| is_host_char(c))
            .collect();
        base = start.max(base + rel + 3);
        let host = host.trim_matches('.').to_ascii_lowercase();
        if host == "localhost" || (!host.is_empty() && host.contains('.')) {
            out.insert(host);
        }
    }
}

// Hosts from the `host:path` form of an `scp`/`git` remote, e.g.
// `git@github.com:me/repo`. Requiring the `:` after the host keeps ordinary
// email addresses (`user@example.com`) out.
fn collect_scp_hosts(text: &str, out: &mut BTreeSet<String>) {
    for (i, _) in text.match_indices('@') {
        let after = &text[i + 1..];
        let host: String = after.chars().take_while(|&c| is_host_char(c)).collect();
        if after[host.len()..].starts_with(':') {
            let host = host.trim_matches('.').to_ascii_lowercase();
            if host.contains('.') {
                out.insert(host);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::extract_hosts;

    #[test]
    fn extracts_url_hosts() {
        assert_eq!(
            extract_hosts("curl https://api.example.com/v1/x -o out"),
            vec!["api.example.com"]
        );
        assert_eq!(
            extract_hosts("wget http://a.io/x && wget http://b.io/y"),
            vec!["a.io", "b.io"]
        );
    }

    #[test]
    fn extracts_git_remote_host() {
        assert_eq!(
            extract_hosts("git push git@github.com:me/repo.git"),
            vec!["github.com"]
        );
    }

    #[test]
    fn deduplicates_and_lowercases() {
        assert_eq!(
            extract_hosts("curl https://API.Example.com/a https://api.example.com/b"),
            vec!["api.example.com"]
        );
    }

    #[test]
    fn ignores_plain_commands_and_emails() {
        assert!(extract_hosts("cargo build --release").is_empty());
        assert!(extract_hosts("git commit -m 'thanks foo@bar.com'").is_empty());
    }

    #[test]
    fn keeps_localhost() {
        assert_eq!(
            extract_hosts("curl http://localhost:8080/health"),
            vec!["localhost"]
        );
    }
}
