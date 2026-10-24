use std::path::Path;

use anyhow::Context;

/// Read a line-oriented list file used by the ban/allow list loaders.
///
/// List files are commonly edited on Windows servers or annotated by
/// operators. A UTF-8 BOM, CRLF line endings, a trailing `# comment` or a
/// single comment written in a non-UTF-8 code page must not make the whole
/// file fail to load: doing so would silently disable every entry in it.
///
/// Returns `(1-based line number, trimmed entry)` pairs. Blank lines and
/// comment-only lines are omitted.
pub fn read_list_file(path: &Path) -> anyhow::Result<Vec<(usize, String)>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read list file {}", path.display()))?;
    let content = String::from_utf8_lossy(&bytes);

    let mut entries = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let line = line.trim_start_matches('\u{feff}');
        let line = match line.split_once('#') {
            Some((entry, _)) => entry,
            None => line,
        };
        let line = line.trim();

        if !line.is_empty() {
            entries.push((index + 1, line.to_string()));
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_list_file_tolerates_common_edits() {
        let path = std::env::temp_dir().join("aquatic_list_file_common_test.txt");

        std::fs::write(
            &path,
            "\u{feff}first\r\n\
             \r\n\
             # full-line comment\r\n\
             second # inline comment\r\n\
             \t third \t\r\n",
        )
        .unwrap();

        let entries = read_list_file(&path).unwrap();

        assert_eq!(
            entries,
            vec![
                (1, "first".to_string()),
                (4, "second".to_string()),
                (5, "third".to_string()),
            ]
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_list_file_tolerates_non_utf8() {
        let path = std::env::temp_dir().join("aquatic_list_file_non_utf8_test.txt");

        // GBK for "扫描器" followed by a valid entry.
        std::fs::write(&path, b"\xc9\xa8\xc3\xe8\xc6\xf7\nentry\n").unwrap();

        let entries = read_list_file(&path).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1], (2, "entry".to_string()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_list_file_missing_file_is_an_error() {
        let path = std::env::temp_dir().join("aquatic_list_file_missing_test.txt");
        let _ = std::fs::remove_file(&path);

        assert!(read_list_file(&path).is_err());
    }
}
