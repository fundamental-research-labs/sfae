use std::path::PathBuf;

use super::Violation;

const LIMIT: usize = 1;

/// Marker comment allowing a single fn declaration to exceed the positional-param
/// limit. Must appear on the line immediately above the `fn` declaration line.
const ALLOW_MARKER: &str = "xtask: allow-multi-param";

pub fn run(files: &[PathBuf]) -> Vec<Violation> {
    let mut out = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        out.extend(FileScan { path, text: &text }.scan());
    }
    out
}

struct FileScan<'a> {
    path: &'a PathBuf,
    text: &'a str,
}

struct LineCheck<'a> {
    line_text: &'a str,
    line_no: usize,
    line_start_byte: usize,
    prev_line: &'a str,
}

impl<'a> FileScan<'a> {
    fn scan(&self) -> Vec<Violation> {
        let mut out = Vec::new();
        let bytes = self.text.as_bytes();
        let mut line_no = 1usize;
        let mut start = 0usize;
        let mut prev_start = 0usize;
        let mut prev_end = 0usize;
        let mut i = 0usize;
        while i <= bytes.len() {
            let at_line_end = i == bytes.len() || bytes[i] == b'\n';
            if at_line_end {
                let line_text = &self.text[start..i];
                let prev_line = if line_no > 1 {
                    &self.text[prev_start..prev_end]
                } else {
                    ""
                };
                if let Some(v) = self.check_line(LineCheck {
                    line_text,
                    line_no,
                    line_start_byte: start,
                    prev_line,
                }) {
                    out.push(v);
                }
                line_no += 1;
                prev_start = start;
                prev_end = i;
                start = i + 1;
            }
            i += 1;
        }
        out
    }

    fn check_line(&self, ctx: LineCheck<'_>) -> Option<Violation> {
        let name_end = match_fn_decl(ctx.line_text)?;
        if ctx.prev_line.contains(ALLOW_MARKER) {
            return None;
        }
        let abs_after_name = ctx.line_start_byte + name_end;
        let tail = self.text.get(abs_after_name..)?;
        let paren_off = find_paren_open(tail)?;
        let from_paren = self.text.get(abs_after_name + paren_off..)?;
        let sig = signature_text(from_paren)?;
        let count = count_args(sig);
        if count > LIMIT {
            Some(Violation {
                path: self.path.clone(),
                line: ctx.line_no,
                message: format!("{} ({count} params)", ctx.line_text.trim()),
            })
        } else {
            None
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn require_space(&mut self) -> bool {
        match self.peek() {
            Some(b' ' | b'\t') => {
                self.skip_space();
                true
            }
            _ => false,
        }
    }

    fn consume_keyword(&mut self, kw: &[u8]) -> bool {
        let end = self.pos + kw.len();
        if end > self.bytes.len() || &self.bytes[self.pos..end] != kw {
            return false;
        }
        if let Some(&b) = self.bytes.get(end) {
            if b.is_ascii_alphanumeric() || b == b'_' {
                return false;
            }
        }
        self.pos = end;
        true
    }

    fn skip_balanced_paren(&mut self) -> bool {
        if self.peek() != Some(b'(') {
            return false;
        }
        self.pos += 1;
        let mut depth = 1usize;
        while depth > 0 {
            match self.peek() {
                Some(b'(') => depth += 1,
                Some(b')') => depth -= 1,
                None => return false,
                _ => {}
            }
            self.pos += 1;
        }
        true
    }

    fn skip_quoted(&mut self) -> bool {
        if self.peek() != Some(b'"') {
            return false;
        }
        self.pos += 1;
        while let Some(b) = self.peek() {
            self.pos += 1;
            if b == b'"' {
                return true;
            }
        }
        false
    }

    fn consume_ident(&mut self) -> bool {
        let start = self.pos;
        match self.peek() {
            Some(b) if b.is_ascii_alphabetic() || b == b'_' => self.pos += 1,
            _ => return false,
        }
        while matches!(self.peek(), Some(b) if b.is_ascii_alphanumeric() || b == b'_') {
            self.pos += 1;
        }
        self.pos > start
    }
}

fn match_fn_decl(line: &str) -> Option<usize> {
    let mut c = Cursor::new(line.as_bytes());
    c.skip_space();

    if c.consume_keyword(b"pub") {
        if c.peek() == Some(b'(') && !c.skip_balanced_paren() {
            return None;
        }
        if !c.require_space() {
            return None;
        }
    }

    loop {
        if c.consume_keyword(b"async")
            || c.consume_keyword(b"const")
            || c.consume_keyword(b"unsafe")
        {
            if !c.require_space() {
                return None;
            }
            continue;
        }
        if c.consume_keyword(b"extern") {
            if !c.require_space() {
                return None;
            }
            if c.peek() == Some(b'"') {
                if !c.skip_quoted() {
                    return None;
                }
                c.skip_space();
            }
            continue;
        }
        break;
    }

    if !c.consume_keyword(b"fn") || !c.require_space() || !c.consume_ident() {
        return None;
    }
    Some(c.pos)
}

fn find_paren_open(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => return Some(i),
            b'<' => {
                let mut depth = 1usize;
                i += 1;
                while i < bytes.len() && depth > 0 {
                    match bytes[i] {
                        b'<' => depth += 1,
                        b'>' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            _ => return None,
        }
    }
    None
}

fn signature_text(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let start = 1usize;
    let mut depth = 1usize;
    let mut i = 1usize;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn count_args(sig: &str) -> usize {
    let bytes = sig.as_bytes();
    let mut args: Vec<&str> = Vec::new();
    let mut depth_p = 0usize;
    let mut depth_a = 0usize;
    let mut depth_b = 0usize;
    let mut last_split = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        match bytes[i] {
            b'(' => depth_p += 1,
            b')' => depth_p = depth_p.saturating_sub(1),
            b'[' => depth_b += 1,
            b']' => depth_b = depth_b.saturating_sub(1),
            b'<' => depth_a += 1,
            b'>' => depth_a = depth_a.saturating_sub(1),
            b',' if depth_p == 0 && depth_a == 0 && depth_b == 0 => {
                args.push(&sig[last_split..i]);
                last_split = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if last_split < bytes.len() {
        args.push(&sig[last_split..]);
    }

    let trimmed: Vec<&str> = args
        .iter()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
        .collect();
    if trimmed.is_empty() {
        return 0;
    }
    let start = usize::from(is_self_arg(trimmed[0]));
    trimmed.len() - start
}

fn is_self_arg(arg: &str) -> bool {
    let s = arg.trim();
    if matches!(s, "self" | "&self" | "&mut self" | "mut self") {
        return true;
    }
    if let Some(rest) = s.strip_prefix('&') {
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix('\'') {
            let rest = rest.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_');
            let rest = rest.trim_start();
            return matches!(rest, "self" | "mut self");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_args_plain() {
        assert_eq!(count_args(""), 0);
        assert_eq!(count_args("a: A"), 1);
        assert_eq!(count_args("a: A, b: B"), 2);
    }

    #[test]
    fn count_args_drops_self_forms() {
        assert_eq!(count_args("self"), 0);
        assert_eq!(count_args("&self"), 0);
        assert_eq!(count_args("&mut self"), 0);
        assert_eq!(count_args("mut self"), 0);
        assert_eq!(count_args("&self, x: A"), 1);
    }

    #[test]
    fn count_args_drops_lifetime_self() {
        assert_eq!(count_args("&'a self"), 0);
        assert_eq!(count_args("&'a mut self"), 0);
        assert_eq!(count_args("&'a self, x: T"), 1);
    }

    #[test]
    fn count_args_handles_generics_internal_commas() {
        assert_eq!(count_args("x: HashMap<String, Vec<u8>>"), 1);
        assert_eq!(count_args("x: HashMap<String, u8>, y: u8"), 2);
        assert_eq!(count_args("f: impl Fn(A, B) -> C, x: u8"), 2);
    }

    #[test]
    fn count_args_five_params() {
        assert_eq!(count_args("a: A, b: B, c: C, d: D, e: E"), 5);
    }

    #[test]
    fn match_fn_decl_plain() {
        assert!(match_fn_decl("fn foo()").is_some());
        assert!(match_fn_decl("    fn foo()").is_some());
    }

    #[test]
    fn match_fn_decl_pub_crate_async() {
        assert!(match_fn_decl("    pub(crate) async fn foo()").is_some());
    }

    #[test]
    fn match_fn_decl_extern_c() {
        assert!(match_fn_decl("extern \"C\" fn foo()").is_some());
    }

    #[test]
    fn match_fn_decl_unsafe() {
        assert!(match_fn_decl("unsafe fn foo()").is_some());
    }

    #[test]
    fn match_fn_decl_trait_default_body() {
        // Same shape as a free fn — trait methods are intentionally not exempt.
        assert!(match_fn_decl("    fn default(&self, x: A, y: B) {}").is_some());
    }

    #[test]
    fn match_fn_decl_skips_closures() {
        assert_eq!(match_fn_decl("let f = |a, b| a + b;"), None);
        assert_eq!(match_fn_decl("// fn fake(a, b)"), None);
    }

    #[test]
    fn end_to_end_multi_line_signature() {
        let text = "fn foo(\n    a: A,\n    b: B,\n    c: C,\n    d: D,\n    e: E,\n) -> R {}\n";
        let path = PathBuf::from("synthetic.rs");
        let scan = FileScan { path: &path, text };
        let v = scan.scan();
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("(5 params)"), "got: {}", v[0].message);
        assert_eq!(v[0].line, 1);
    }

    #[test]
    fn end_to_end_method_with_generics_passes() {
        let text = "impl Foo {\n    fn bar(&self, m: HashMap<String, Vec<u8>>) -> R { todo!() }\n}\n";
        let path = PathBuf::from("synthetic.rs");
        let scan = FileScan { path: &path, text };
        assert!(scan.scan().is_empty());
    }

    #[test]
    fn allow_marker_suppresses_violation() {
        let text =
            "// xtask: allow-multi-param\nfn foo(a: A, b: B, c: C) -> R { todo!() }\n";
        let path = PathBuf::from("synthetic.rs");
        let scan = FileScan { path: &path, text };
        assert!(scan.scan().is_empty());
    }

    #[test]
    fn allow_marker_only_suppresses_next_line() {
        // Marker on line 1 does not suppress violation on line 4.
        let text =
            "// xtask: allow-multi-param\nfn ok(a: A) {}\n\nfn bad(a: A, b: B, c: C) {}\n";
        let path = PathBuf::from("synthetic.rs");
        let scan = FileScan { path: &path, text };
        let v = scan.scan();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, 4);
    }
}
