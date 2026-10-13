//! Direct diff generator for comparing two FRITZ!Box configuration backups.
//!
//! Provides line-by-line unified diffs for text `.cfg` files, property change detection,
//! and binary file size/content comparison.

use std::fmt::Write as _;

use crate::{markers::CrcState, ConfigBackup, FileContent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiffOp {
    Equal,
    Delete,
    Insert,
}

/// Computes the sequence of edit operations between two slices of lines using LCS.
/// Optimizes execution by stripping identical common prefixes and suffixes first.
fn compute_line_diff<'a>(lines_a: &[&'a str], lines_b: &[&'a str]) -> Vec<(DiffOp, &'a str)> {
    let mut prefix_len = 0;
    while prefix_len < lines_a.len()
        && prefix_len < lines_b.len()
        && lines_a[prefix_len] == lines_b[prefix_len]
    {
        prefix_len += 1;
    }

    let mut suffix_len = 0;
    while suffix_len < (lines_a.len() - prefix_len)
        && suffix_len < (lines_b.len() - prefix_len)
        && lines_a[lines_a.len() - 1 - suffix_len] == lines_b[lines_b.len() - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let a_mid = &lines_a[prefix_len..lines_a.len() - suffix_len];
    let b_mid = &lines_b[prefix_len..lines_b.len() - suffix_len];

    let mut result = Vec::with_capacity(lines_a.len() + lines_b.len());
    for &line in &lines_a[..prefix_len] {
        result.push((DiffOp::Equal, line));
    }

    let len_a = a_mid.len();
    let len_b = b_mid.len();
    if len_a > 0 || len_b > 0 {
        let mut dp = vec![vec![0u32; len_b + 1]; len_a + 1];
        for idx_a in (0..len_a).rev() {
            for idx_b in (0..len_b).rev() {
                dp[idx_a][idx_b] = if a_mid[idx_a] == b_mid[idx_b] {
                    1 + dp[idx_a + 1][idx_b + 1]
                } else {
                    dp[idx_a + 1][idx_b].max(dp[idx_a][idx_b + 1])
                };
            }
        }

        let mut idx_a = 0;
        let mut idx_b = 0;
        while idx_a < len_a && idx_b < len_b {
            if a_mid[idx_a] == b_mid[idx_b] {
                result.push((DiffOp::Equal, a_mid[idx_a]));
                idx_a += 1;
                idx_b += 1;
            } else if dp[idx_a + 1][idx_b] >= dp[idx_a][idx_b + 1] {
                result.push((DiffOp::Delete, a_mid[idx_a]));
                idx_a += 1;
            } else {
                result.push((DiffOp::Insert, b_mid[idx_b]));
                idx_b += 1;
            }
        }
        while idx_a < len_a {
            result.push((DiffOp::Delete, a_mid[idx_a]));
            idx_a += 1;
        }
        while idx_b < len_b {
            result.push((DiffOp::Insert, b_mid[idx_b]));
            idx_b += 1;
        }
    }

    for &line in &lines_a[lines_a.len() - suffix_len..] {
        result.push((DiffOp::Equal, line));
    }

    result
}

/// Generates unified diff hunks from a list of edit operations with standard context (3 lines).
fn format_unified_diff(filename: &str, lines_a: &[&str], lines_b: &[&str]) -> Option<String> {
    const CONTEXT: usize = 3;

    let ops = compute_line_diff(lines_a, lines_b);
    let has_changes = ops.iter().any(|(op, _)| *op != DiffOp::Equal);
    if !has_changes {
        return None;
    }

    let mut out = String::new();
    let _ = writeln!(out, "--- {filename}");
    let _ = writeln!(out, "+++ {filename}");

    let mut i = 0;
    while i < ops.len() {
        if ops[i].0 == DiffOp::Equal {
            i += 1;
            continue;
        }

        let hunk_start = i.saturating_sub(CONTEXT);

        // Find the end of this cluster of changes
        let mut hunk_end = i;
        let mut equal_count = 0;
        while hunk_end < ops.len() {
            if ops[hunk_end].0 == DiffOp::Equal {
                equal_count += 1;
                if equal_count > CONTEXT * 2 {
                    break;
                }
            } else {
                equal_count = 0;
            }
            hunk_end += 1;
        }

        let actual_end = if equal_count > CONTEXT * 2 {
            hunk_end - equal_count + CONTEXT
        } else {
            (hunk_end + CONTEXT).min(ops.len())
        };

        // Calculate line numbers
        let mut old_line = 1usize;
        let mut new_line = 1usize;
        for op in &ops[..hunk_start] {
            match op.0 {
                DiffOp::Equal => {
                    old_line += 1;
                    new_line += 1;
                }
                DiffOp::Delete => old_line += 1,
                DiffOp::Insert => new_line += 1,
            }
        }

        let mut old_count = 0;
        let mut new_count = 0;
        for op in &ops[hunk_start..actual_end] {
            match op.0 {
                DiffOp::Equal => {
                    old_count += 1;
                    new_count += 1;
                }
                DiffOp::Delete => old_count += 1,
                DiffOp::Insert => new_count += 1,
            }
        }

        let _ = writeln!(out, "@@ -{old_line},{old_count} +{new_line},{new_count} @@");

        for (op, line) in &ops[hunk_start..actual_end] {
            match op {
                DiffOp::Equal => {
                    let _ = writeln!(out, " {line}");
                }
                DiffOp::Delete => {
                    let _ = writeln!(out, "-{line}");
                }
                DiffOp::Insert => {
                    let _ = writeln!(out, "+{line}");
                }
            }
        }

        i = actual_end;
    }

    Some(out)
}

/// Generates a diff comparing two FRITZ!Box configuration backups.
///
/// If `section_filter` is specified, only the matching configuration file is compared.
/// Otherwise, header properties and all files are compared.
#[must_use]
pub fn diff_backups<S1: CrcState, S2: CrcState>(
    b1: &ConfigBackup<S1>,
    b2: &ConfigBackup<S2>,
    section_filter: Option<&str>,
) -> String {
    let mut output = String::new();

    // 1. Property diff (if not filtering to a specific file section)
    if section_filter.is_none() {
        let mut prop_diffs = Vec::new();
        let p1 = b1.properties();
        let p2 = b2.properties();

        if b1.model() != b2.model() {
            prop_diffs.push(format!("- Model: {}", b1.model()));
            prop_diffs.push(format!("+ Model: {}", b2.model()));
        }

        for (k, v1) in p1 {
            match p2.iter().find(|(k2, _)| k2 == k) {
                Some((_, v2)) if v1 != v2 => {
                    prop_diffs.push(format!("- {k}={v1}"));
                    prop_diffs.push(format!("+ {k}={v2}"));
                }
                None => {
                    prop_diffs.push(format!("- {k}={v1}"));
                }
                _ => {}
            }
        }
        for (k, v2) in p2 {
            if !p1.iter().any(|(k1, _)| k1 == k) {
                prop_diffs.push(format!("+ {k}={v2}"));
            }
        }

        if !prop_diffs.is_empty() {
            let _ = writeln!(output, "--- Header Properties");
            let _ = writeln!(output, "+++ Header Properties");
            for line in prop_diffs {
                let _ = writeln!(output, "{line}");
            }
            let _ = writeln!(output);
        }
    }

    // 2. Files diff
    let f1 = b1.files();
    let f2 = b2.files();

    for file1 in f1 {
        if let Some(sec) = section_filter {
            if !file1.name.eq_ignore_ascii_case(sec) {
                continue;
            }
        }

        match f2.iter().find(|f| f.name == file1.name) {
            None => {
                let _ = writeln!(output, "Deleted file: {}", file1.name);
            }
            Some(file2) => match (&file1.content, &file2.content) {
                (FileContent::Plain(t1), FileContent::Plain(t2)) => {
                    let lines1: Vec<&str> = t1.lines().collect();
                    let lines2: Vec<&str> = t2.lines().collect();
                    if let Some(patch) = format_unified_diff(&file1.name, &lines1, &lines2) {
                        output.push_str(&patch);
                        output.push('\n');
                    }
                }
                (FileContent::Binary(b1_bytes), FileContent::Binary(b2_bytes)) => {
                    if b1_bytes != b2_bytes {
                        let _ = writeln!(
                            output,
                            "Binary file '{}' differs: {} bytes in file1 vs {} bytes in file2",
                            file1.name,
                            b1_bytes.len(),
                            b2_bytes.len()
                        );
                        output.push('\n');
                    }
                }
                (FileContent::Plain(_), FileContent::Binary(_)) => {
                    let _ = writeln!(
                        output,
                        "File '{}' changed from plain text to binary",
                        file1.name
                    );
                    output.push('\n');
                }
                (FileContent::Binary(_), FileContent::Plain(_)) => {
                    let _ = writeln!(
                        output,
                        "File '{}' changed from binary to plain text",
                        file1.name
                    );
                    output.push('\n');
                }
            },
        }
    }

    // Files only in b2
    for file2 in f2 {
        if let Some(sec) = section_filter {
            if !file2.name.eq_ignore_ascii_case(sec) {
                continue;
            }
        }
        if !f1.iter().any(|f| f.name == file2.name) {
            let _ = writeln!(output, "Added file: {}", file2.name);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::File;

    #[test]
    fn test_identical_backups_diff_empty() {
        let b1 = ConfigBackup::from_parts(
            "FRITZ!Box 7590".to_string(),
            vec![("FirmwareVersion".to_string(), "260.07.57".to_string())],
            vec![File {
                name: "ar7.cfg".to_string(),
                content: FileContent::Plain("test = 123;\n".to_string()),
            }],
            0,
        );
        let b2 = b1.clone();
        assert_eq!(diff_backups(&b1, &b2, None), "");
    }

    #[test]
    fn test_property_and_text_file_diff() {
        let b1 = ConfigBackup::from_parts(
            "FRITZ!Box 7590".to_string(),
            vec![("FirmwareVersion".to_string(), "260.07.29".to_string())],
            vec![File {
                name: "wlan.cfg".to_string(),
                content: FileContent::Plain(
                    "ssid = \"HomeWifi\";\npsk = \"old123\";\n".to_string(),
                ),
            }],
            0,
        );

        let b2 = ConfigBackup::from_parts(
            "FRITZ!Box 7590".to_string(),
            vec![("FirmwareVersion".to_string(), "260.07.57".to_string())],
            vec![File {
                name: "wlan.cfg".to_string(),
                content: FileContent::Plain(
                    "ssid = \"HomeWifi\";\npsk = \"new456\";\n".to_string(),
                ),
            }],
            0,
        );

        let diff = diff_backups(&b1, &b2, None);
        assert!(diff.contains("- FirmwareVersion=260.07.29"));
        assert!(diff.contains("+ FirmwareVersion=260.07.57"));
        assert!(diff.contains("-psk = \"old123\";"));
        assert!(diff.contains("+psk = \"new456\";"));
    }

    #[test]
    fn test_section_filtering() {
        let b1 = ConfigBackup::from_parts(
            "FRITZ!Box 7590".to_string(),
            vec![("FirmwareVersion".to_string(), "1".to_string())],
            vec![
                File {
                    name: "ar7.cfg".to_string(),
                    content: FileContent::Plain("a = 1;\n".to_string()),
                },
                File {
                    name: "wlan.cfg".to_string(),
                    content: FileContent::Plain("b = 1;\n".to_string()),
                },
            ],
            0,
        );

        let b2 = ConfigBackup::from_parts(
            "FRITZ!Box 7590".to_string(),
            vec![("FirmwareVersion".to_string(), "2".to_string())],
            vec![
                File {
                    name: "ar7.cfg".to_string(),
                    content: FileContent::Plain("a = 2;\n".to_string()),
                },
                File {
                    name: "wlan.cfg".to_string(),
                    content: FileContent::Plain("b = 2;\n".to_string()),
                },
            ],
            0,
        );

        let diff_wlan = diff_backups(&b1, &b2, Some("wlan.cfg"));
        assert!(!diff_wlan.contains("ar7.cfg"));
        assert!(!diff_wlan.contains("FirmwareVersion"));
        assert!(diff_wlan.contains("wlan.cfg"));
    }
}
