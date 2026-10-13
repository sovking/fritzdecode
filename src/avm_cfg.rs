//! Parser for AVM FRITZ!OS configuration syntax (`.cfg` files inside `.export`).
//! Converts AVM C-like block syntax into structured `serde_json::Value` (JSON/YAML).

use serde_json::{Map, Number, Value};

/// Parses an AVM `.cfg` text content into a `serde_json::Value` (Object or Array).
#[must_use]
pub fn parse_avm_cfg(input: &str) -> Value {
    let mut parser = AvmParser::new(input);
    let mut map = Map::new();

    while !parser.is_eof() {
        parser.skip_whitespace_and_comments();
        if parser.is_eof() {
            break;
        }

        if let Some((key, val)) = parser.parse_entry() {
            insert_or_append(&mut map, key, val);
        } else {
            // Skip unrecognized character to avoid getting stuck
            parser.next_char();
        }
    }

    Value::Object(map)
}

struct AvmParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _marker: std::marker::PhantomData<&'a str>,
}

impl<'a> AvmParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            _marker: std::marker::PhantomData,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_offset(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn next_char(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn skip_whitespace_and_comments(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += 1;
            } else if c == '/' && self.peek_offset(1) == Some('*') {
                // Multi-line comment /* ... */
                self.pos += 2;
                while !self.is_eof() {
                    if self.peek() == Some('*') && self.peek_offset(1) == Some('/') {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
            } else if c == '/' && self.peek_offset(1) == Some('/') {
                // Single-line comment // ...
                self.pos += 2;
                while !self.is_eof() && self.peek() != Some('\n') {
                    self.pos += 1;
                }
            } else if c == '#' {
                // Shell-style comment
                self.pos += 1;
                while !self.is_eof() && self.peek() != Some('\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn parse_entry(&mut self) -> Option<(String, Value)> {
        self.skip_whitespace_and_comments();
        if self.is_eof() {
            return None;
        }

        let key = self.parse_identifier_or_string()?;
        self.skip_whitespace_and_comments();

        match self.peek() {
            Some('{') => {
                // Section block: key { ... } [ { ... } ... ]
                let val = self.parse_block_or_blocks();
                Some((key, val))
            }
            Some('=') => {
                self.next_char(); // consume '='
                self.skip_whitespace_and_comments();
                let val = self.parse_value_or_list();
                self.skip_whitespace_and_comments();
                if self.peek() == Some(';') {
                    self.next_char();
                }
                Some((key, val))
            }
            _ => None,
        }
    }

    fn parse_block_or_blocks(&mut self) -> Value {
        let mut blocks = Vec::new();

        while self.peek() == Some('{') {
            self.next_char(); // consume '{'
            let mut block_map = Map::new();

            loop {
                self.skip_whitespace_and_comments();
                if self.is_eof() || self.peek() == Some('}') {
                    break;
                }

                if let Some((k, v)) = self.parse_entry() {
                    insert_or_append(&mut block_map, k, v);
                } else {
                    self.next_char();
                }
            }

            if self.peek() == Some('}') {
                self.next_char(); // consume '}'
            }
            self.skip_whitespace_and_comments();

            blocks.push(Value::Object(block_map));
        }

        if blocks.len() == 1 {
            blocks.remove(0)
        } else {
            Value::Array(blocks)
        }
    }

    fn parse_value_or_list(&mut self) -> Value {
        let mut list = Vec::new();

        loop {
            self.skip_whitespace_and_comments();
            if self.is_eof() || self.peek() == Some(';') || self.peek() == Some('}') {
                break;
            }

            let item = self.parse_single_value();
            list.push(item);

            self.skip_whitespace_and_comments();
            if self.peek() == Some(',') {
                self.next_char(); // consume ','
            } else {
                break;
            }
        }

        if list.is_empty() {
            Value::String(String::new())
        } else if list.len() == 1 {
            list.remove(0)
        } else {
            Value::Array(list)
        }
    }

    fn parse_single_value(&mut self) -> Value {
        self.skip_whitespace_and_comments();
        if self.is_eof() {
            return Value::Null;
        }

        if self.peek() == Some('"') {
            Value::String(self.parse_quoted_string())
        } else if self.peek() == Some('{') {
            self.parse_block_or_blocks()
        } else {
            let s = self.parse_unquoted_literal();
            match s.as_str() {
                "yes" | "true" => Value::Bool(true),
                "no" | "false" => Value::Bool(false),
                _ => {
                    if let Ok(num) = s.parse::<i64>() {
                        Value::Number(Number::from(num))
                    } else if let Ok(num) = s.parse::<u64>() {
                        Value::Number(Number::from(num))
                    } else {
                        Value::String(s)
                    }
                }
            }
        }
    }

    fn parse_quoted_string(&mut self) -> String {
        self.next_char(); // consume '"'
        let mut s = String::new();
        while let Some(c) = self.next_char() {
            if c == '"' {
                break;
            } else if c == '\\' {
                if let Some(next) = self.next_char() {
                    match next {
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        other => s.push(other),
                    }
                }
            } else {
                s.push(c);
            }
        }
        s
    }

    fn parse_unquoted_literal(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_whitespace() || c == ';' || c == ',' || c == '}' || c == '{' {
                break;
            }
            s.push(c);
            self.next_char();
        }
        s
    }

    fn parse_identifier_or_string(&mut self) -> Option<String> {
        self.skip_whitespace_and_comments();
        if self.peek() == Some('"') {
            Some(self.parse_quoted_string())
        } else {
            let mut s = String::new();
            while let Some(c) = self.peek() {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    s.push(c);
                    self.next_char();
                } else {
                    break;
                }
            }
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
    }
}

fn insert_or_append(map: &mut Map<String, Value>, key: String, val: Value) {
    if let Some(existing) = map.remove(&key) {
        match existing {
            Value::Array(mut arr) => {
                arr.push(val);
                map.insert(key, Value::Array(arr));
            }
            other => {
                map.insert(key, Value::Array(vec![other, val]));
            }
        }
    } else {
        map.insert(key, val);
    }
}

/// Helper function to convert a parsed `Value` to a YAML string.
///
/// # Errors
/// Returns an error if serialization fails.
pub fn to_yaml_string(val: &Value) -> Result<String, serde_yaml::Error> {
    serde_yaml::to_string(val)
}

/// Helper function to convert a parsed `Value` to a pretty-printed JSON string.
///
/// # Errors
/// Returns an error if serialization fails.
pub fn to_json_string(val: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_avm_cfg() {
        let src = r#"
        meta { encoding = "utf-8"; }
        ar7cfg {
            mode = dsldmode_router;
            active_provider = "eolo";
            igddenabled = yes;
            mtu_cutback = 1500;
            interfaces = "lan", "eth0", "wlan";
        }
        "#;

        let val = parse_avm_cfg(src);
        assert_eq!(val["meta"]["encoding"], "utf-8");
        assert_eq!(val["ar7cfg"]["active_provider"], "eolo");
        assert_eq!(val["ar7cfg"]["igddenabled"], true);
        assert_eq!(val["ar7cfg"]["mtu_cutback"], 1500);
        assert_eq!(val["ar7cfg"]["interfaces"][0], "lan");
        assert_eq!(val["ar7cfg"]["interfaces"][1], "eth0");
    }

    #[test]
    fn test_parse_repeated_blocks() {
        let src = r#"
        sync_groups {
            name = "sync_dsl";
            enabled = no;
        } {
            name = "sync_ata";
            enabled = yes;
        }
        "#;

        let val = parse_avm_cfg(src);
        assert!(val["sync_groups"].is_array());
        assert_eq!(val["sync_groups"][0]["name"], "sync_dsl");
        assert_eq!(val["sync_groups"][0]["enabled"], false);
        assert_eq!(val["sync_groups"][1]["name"], "sync_ata");
        assert_eq!(val["sync_groups"][1]["enabled"], true);
    }
}
