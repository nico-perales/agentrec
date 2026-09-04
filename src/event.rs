//! Parses a Claude Code hook event.
//!
//! Claude Code invokes a hook command per tool call, piping a JSON object on
//! stdin. The fields we rely on are stable (`hook_event_name`, `tool_name`,
//! `tool_input`, `cwd`, `session_id`); everything else is read defensively from a
//! loose `Value`, since the exact response shape varies by tool and version.

use std::io::Read;

use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;

// File-mutating tools whose target we snapshot for before/after diffing.
const FILE_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

#[derive(Debug, Clone, Deserialize)]
pub struct HookEvent {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(default)]
    pub tool_response: Value,
    #[serde(default)]
    pub tool_use_id: Option<String>,
}

impl HookEvent {
    pub fn from_reader(reader: impl Read) -> Result<Self, Error> {
        serde_json::from_reader(reader).map_err(Error::Event)
    }

    #[must_use]
    pub fn is_pre(&self) -> bool {
        self.hook_event_name == "PreToolUse"
    }

    #[must_use]
    pub fn is_post(&self) -> bool {
        self.hook_event_name == "PostToolUse"
    }

    #[must_use]
    pub fn is_file_tool(&self) -> bool {
        FILE_TOOLS.contains(&self.tool_name.as_str())
    }

    #[must_use]
    pub fn file_path(&self) -> Option<&str> {
        self.tool_input.get("file_path").and_then(Value::as_str)
    }

    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.tool_input.get("command").and_then(Value::as_str)
    }

    // The new text a file-mutating tool would write, available in the event even
    // at PreToolUse (before it hits disk): Write's `content`, Edit's `new_string`,
    // or MultiEdit's joined `new_string`s. Used to judge an edit's network intent.
    #[must_use]
    pub fn written_text(&self) -> Option<String> {
        if let Some(s) = self.tool_input.get("content").and_then(Value::as_str) {
            return Some(s.to_owned());
        }
        if let Some(s) = self.tool_input.get("new_string").and_then(Value::as_str) {
            return Some(s.to_owned());
        }
        if let Some(edits) = self.tool_input.get("edits").and_then(Value::as_array) {
            let joined: Vec<&str> = edits
                .iter()
                .filter_map(|e| e.get("new_string").and_then(Value::as_str))
                .collect();
            if !joined.is_empty() {
                return Some(joined.join("\n"));
            }
        }
        None
    }

    // A stable key linking a PreToolUse snapshot to its PostToolUse record.
    #[must_use]
    pub fn correlation_key(&self) -> String {
        if let Some(id) = &self.tool_use_id {
            return id.clone();
        }
        let path = self.file_path().unwrap_or("");
        format!("{}::{}::{path}", self.session_id, self.tool_name)
    }

    // Best-effort stdout/stderr text from a Bash tool_response.
    #[must_use]
    pub fn response_output(&self) -> Option<String> {
        match &self.tool_response {
            Value::String(s) => Some(s.clone()),
            Value::Object(map) => {
                let mut parts = Vec::new();
                for key in ["stdout", "stderr", "output", "result"] {
                    if let Some(Value::String(s)) = map.get(key) {
                        if !s.is_empty() {
                            parts.push(s.clone());
                        }
                    }
                }
                (!parts.is_empty()).then(|| parts.join("\n"))
            }
            _ => None,
        }
    }

    // Best-effort exit code from a Bash tool_response.
    #[must_use]
    pub fn response_exit(&self) -> Option<i64> {
        let map = self.tool_response.as_object()?;
        for key in ["exit_code", "exitCode", "code", "returnCode"] {
            if let Some(v) = map.get(key).and_then(Value::as_i64) {
                return Some(v);
            }
        }
        None
    }
}
