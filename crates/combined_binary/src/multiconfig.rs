//! Merged configuration files.
//!
//! Instead of one TOML file per protocol, a single file can hold a table per
//! protocol, so that shared settings live in one place:
//!
//! ```toml
//! [udp.network]
//! address_ipv4 = "0.0.0.0:6969"
//!
//! [http.network]
//! address_ipv4 = "0.0.0.0:8080"
//! ```
//!
//! The protocol is still chosen on the command line, one process per protocol.
//! Only the section belonging to that protocol is ever deserialized, which is
//! what lets a single file be shared between a Linux host running every
//! protocol and a Windows host running only UDP.

use ::anyhow::{anyhow, Context, Result};

use aquatic_toml_config::toml::{self, Value};

/// Protocols that may appear as top-level tables in a merged config file.
pub const PROTOCOLS: [&str; 3] = ["udp", "http", "ws"];

/// Result of inspecting a config file.
#[derive(Debug)]
pub enum Resolved {
    /// Merged file: the configuration table of the requested protocol.
    Section(Value),
    /// Single-protocol file: the caller loads it through the regular CLI path.
    Legacy,
}

/// Read a config file as text, tolerating a BOM and non UTF-8 bytes in
/// comments. Mirrors the behaviour of the single-protocol loader.
pub fn read_file(path: &str) -> Result<String> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Couldn't read config file {}", path))?;

    let data = String::from_utf8_lossy(&bytes);
    let data = data.strip_prefix('\u{feff}').unwrap_or(&data);

    Ok(data.to_string())
}

/// Parse a config file and return the configuration belonging to `protocol`.
///
/// A file with `[udp]`, `[http]` or `[ws]` tables is a merged file: the
/// matching table is extracted and every other table is left untouched. Any
/// other layout is a single-protocol file and is left to the regular CLI path,
/// which keeps the behaviour of earlier releases unchanged.
pub fn resolve(path: &str, protocol: &str) -> Result<Resolved> {
    let text = read_file(path)?;

    let value: Value = toml::from_str(&text)
        .with_context(|| format!("Couldn't parse config file {}", path))?;

    if value.as_table().is_none() {
        return Err(anyhow!(
            "Config file {} must contain a table of settings",
            path
        ));
    }

    if !is_merged(&value) {
        return Ok(Resolved::Legacy);
    }

    if !has_section(&value, protocol) {
        return Err(anyhow!(
            "Config file {} has no [{}] section",
            path,
            protocol
        ));
    }

    Ok(Resolved::Section(protocol_section(&value, protocol)?))
}

/// Whether the document holds at least one protocol table.
fn is_merged(value: &Value) -> bool {
    PROTOCOLS
        .iter()
        .any(|protocol| has_section(value, *protocol))
}

fn has_section(value: &Value, protocol: &str) -> bool {
    value
        .as_table()
        .map_or(false, |table| table.contains_key(protocol))
}

/// Copy a protocol section out of a merged document.
fn protocol_section(value: &Value, protocol: &str) -> Result<Value> {
    let section = value
        .as_table()
        .and_then(|table| table.get(protocol))
        .and_then(|section| section.as_table())
        .cloned()
        .ok_or_else(|| anyhow!("[{}] must be a table", protocol))?;

    Ok(Value::Table(section))
}

/// Build one protocol block of the merged template: the protocol's default
/// configuration with every section renamed to `[<protocol>.<section>]`.
pub fn section(protocol: &str, body: &str, overrides: &[(&str, &str)]) -> String {
    let mut text = String::new();

    text.push_str(&format!("[{}]\n", protocol));

    for line in body.lines() {
        let line = apply_override(line, overrides);

        if line.starts_with('[') {
            text.push_str(&format!("[{}.{}\n", protocol, &line[1..]));
        } else {
            text.push_str(&line);
            text.push('\n');
        }
    }

    text
}

/// Replace a whole generated line, if it matches. Returns the line unchanged
/// when the default serialization no longer looks like the expected text, so a
/// changed upstream default degrades to "template uses the default" instead of
/// producing a broken file.
fn apply_override(line: &str, overrides: &[(&str, &str)]) -> String {
    let trimmed = line.trim_end();

    for (from, to) in overrides {
        if trimmed == *from {
            return (*to).to_string();
        }
    }

    line.to_string()
}

/// Concatenate a header and the protocol blocks into one document.
pub fn merge_blocks(header: &str, blocks: &[(&str, String)]) -> String {
    let mut output = String::from(header);

    for (_, block) in blocks {
        output.push('\n');
        output.push_str(block.trim_end());
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(name);

        std::fs::write(&path, contents).unwrap();

        path
    }

    const MERGED: &str = r#"
[udp.network]
address_ipv4 = "0.0.0.0:6969"

[http.network]
address_ipv4 = "0.0.0.0:8080"
"#;

    #[test]
    fn test_merged_section_is_extracted() {
        let path = write_temp("aquatic_merged_extract.toml", MERGED);

        match resolve(path.to_str().unwrap(), "udp").unwrap() {
            Resolved::Section(value) => {
                let network = value.as_table().unwrap().get("network").unwrap();

                assert_eq!(
                    network.as_table().unwrap().get("address_ipv4"),
                    Some(&Value::String("0.0.0.0:6969".to_string()))
                );
            }
            Resolved::Legacy => panic!("expected a merged config"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_missing_section_names_the_file_and_protocol() {
        let path = write_temp("aquatic_merged_missing.toml", MERGED);

        let err = resolve(path.to_str().unwrap(), "ws").unwrap_err();
        let message = format!("{:#}", err);

        assert!(message.contains("has no [ws] section"));
        assert!(message.contains("aquatic_merged_missing.toml"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_single_protocol_file_is_left_to_the_regular_path() {
        let path = write_temp(
            "aquatic_legacy_passthrough.toml",
            "socket_workers = 2\n[network]\n",
        );

        match resolve(path.to_str().unwrap(), "udp").unwrap() {
            Resolved::Legacy => (),
            Resolved::Section(_) => panic!("expected a single-protocol config"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_section_renames_nested_tables() {
        let body = "socket_workers = 1\n\n# Network\n[network]\nuse_ipv4 = true\n";

        let text = section("udp", body, &[("use_ipv4 = true", "use_ipv4 = false")]);

        assert_eq!(text.lines().next(), Some("[udp]"));
        assert!(text.contains("[udp.network]"));
        assert!(text.contains("use_ipv4 = false"));
        assert!(!text.contains("enabled"));
    }
}
