//! `zkagent-mcp` — stdio entry point.
//!
//! Reads newline-delimited JSON-RPC from stdin, writes responses to stdout.
//! **stdout is the protocol channel**: nothing else may ever be printed there,
//! or every connected harness breaks at once. Diagnostics go to stderr.

#![deny(unsafe_code)]

use std::io::{self, BufRead, Write};

use serde_json::Value;

use zkagent_mcp::Server;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // One server for the life of the process: it holds the parsed proving key,
    // so the second and later prove calls skip the ~258 ms decompress.
    let server = Server::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("zkagent-mcp: stdin read failed: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                // A malformed line gets a parse error, not a crash.
                let error = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                });
                write_line(&mut out, &error);
                continue;
            }
        };

        if let Some(response) = server.handle(&request) {
            write_line(&mut out, &response);
        }
    }
}

fn write_line(out: &mut impl Write, value: &Value) {
    let text = serde_json::to_string(value).unwrap_or_else(|e| {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":-32603,\"message\":\"{e}\"}}}}"
        )
    });
    // A broken pipe means the harness went away. Not an error worth shouting about.
    if writeln!(out, "{text}").is_err() {
        return;
    }
    let _ = out.flush();
}
