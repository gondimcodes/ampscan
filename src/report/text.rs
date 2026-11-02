//! Text utilities for PDF rendering and formatting

/// Sanitize text for PDF built-in fonts (WinAnsiEncoding).
/// Transliterates Portuguese accented characters to ASCII equivalents.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' => 'a',
            'é' | 'è' | 'ê' => 'e',
            'í' | 'ì' | 'î' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' => 'o',
            'ú' | 'ù' | 'û' => 'u',
            'ç' => 'c',
            'Á' | 'À' | 'Â' | 'Ã' => 'A',
            'É' | 'È' | 'Ê' => 'E',
            'Í' | 'Ì' | 'Î' => 'I',
            'Ó' | 'Ò' | 'Ô' | 'Õ' => 'O',
            'Ú' | 'Ù' | 'Û' => 'U',
            'Ç' => 'C',
            _ => c,
        })
        .collect()
}

/// Simple word wrapping.
pub fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > max_chars {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Wrap a command string for PDF display.
///
/// Two-level strategy:
/// 1. Word wrap at `max_chars` (break at spaces).
/// 2. Character-level break as fallback for tokens with no spaces
///    (e.g., long hex payloads like SLP's `\x02\x01...`).
///
/// Continuation lines are indented by `CONT_INDENT` spaces so it’s visually
/// clear they belong to the same command.
pub fn wrap_command(cmd: &str, max_chars: usize) -> Vec<String> {
    const CONT_INDENT: &str = "    "; // 4-space continuation indent
    let cont_max = max_chars.saturating_sub(CONT_INDENT.len());

    let mut result: Vec<String> = Vec::new();
    let mut current = String::new();

    for word in cmd.split_whitespace() {
        // Decide the effective limit for the current line
        let limit = if result.is_empty() && current.is_empty() {
            max_chars
        } else {
            cont_max
        };

        if word.chars().count() > max_chars {
            // Long token with no spaces (e.g., hex payload): break char by char
            let mut remaining: &str = word;
            while !remaining.is_empty() {
                let avail = if current.is_empty() {
                    limit
                } else {
                    limit.saturating_sub(current.len() + 1)
                };
                if avail == 0
                    || (!current.is_empty()
                        && current.len() + 1 + remaining.chars().take(1).count() > limit)
                {
                    result.push(current.clone());
                    current = CONT_INDENT.to_string();
                }
                let take: usize = remaining.chars().count().min(if current.trim().is_empty() {
                    cont_max
                } else {
                    cont_max.saturating_sub(current.len())
                });
                if take == 0 {
                    break;
                }
                let chunk: String = remaining.chars().take(take).collect();
                let byte_len = chunk.len();
                if !current.trim().is_empty() {
                    current.push(' ');
                }
                current.push_str(&chunk);
                remaining = &remaining[byte_len..];
                if !remaining.is_empty() {
                    result.push(current.clone());
                    current = CONT_INDENT.to_string();
                }
            }
        } else if !current.is_empty() && current.len() + 1 + word.len() > limit {
            // Word doesn't fit on current line — start continuation line
            result.push(current.clone());
            current = format!("{}{}", CONT_INDENT, word);
        } else {
            // Word fits
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
    }

    if !current.trim().is_empty() {
        result.push(current);
    }
    if result.is_empty() {
        result.push(String::new());
    }
    result
}

/// Truncate a string for display, counting Unicode scalar values (not bytes).
/// Only used in tests; kept here close to wrap_text for documentation purposes.
#[cfg(test)]
fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}

#[cfg(test)]
mod truncate_tests {
    use super::truncate_str;

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
        assert_eq!(truncate_str("hello", 10), "hello");
        assert_eq!(truncate_str("", 5), "");
    }
}

#[cfg(test)]
mod wrap_command_tests {
    use super::wrap_command;

    #[test]
    fn test_short_command_no_wrap() {
        let lines = wrap_command("dig +short -t ANY google.com @<IP>", 100);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "dig +short -t ANY google.com @<IP>");
    }

    #[test]
    fn test_word_wrap_at_spaces() {
        let lines = wrap_command("word1 word2 word3 word4", 12);
        assert!(lines.len() > 1, "should wrap into multiple lines");
        for line in lines.iter().skip(1) {
            assert!(
                line.starts_with("    "),
                "continuation must be indented: {:?}",
                line
            );
        }
    }

    #[test]
    fn test_slp_long_hex_token_wraps() {
        let long_token = "a".repeat(120);
        let slp = format!("  printf '{}' | nc -u -w 3 <IP> 427", long_token);
        let lines = wrap_command(&slp, 100);
        assert!(lines.len() > 1, "long token must wrap: got {:?}", lines);
        for line in &lines {
            assert!(
                line.chars().count() <= 100,
                "line too long ({} chars): {:?}",
                line.chars().count(),
                line
            );
        }
    }

    #[test]
    fn test_empty_command() {
        let lines = wrap_command("", 100);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].is_empty());
    }
}
