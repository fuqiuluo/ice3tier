//! Server-Sent Events 的编码和增量解析，按 WHATWG 规范里负载端用得到的那部分：
//! `event`、`data`、`id` 三个字段，冒号开头的注释，三种换行（`\n`、`\r\n`、`\r`），空行派发事件。

use std::fmt::Write as _;

/// 一个派发出来的事件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// `event:` 字段；没有时是 `None`（规范里的 "message"）。
    pub name: Option<String>,
    /// 各行 `data:` 用换行连起来。
    pub data: String,
    pub id: Option<String>,
}

/// 解析出来的一项：事件或者注释。注释只用来证明连接还活着，事件才是答案的内容。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Event(Event),
    Comment(String),
}

/// 增量解析器：字节可以按任意边界分批喂进来。
#[derive(Debug, Default)]
pub struct Parser {
    /// 还没有遇到换行的半行。
    line: Vec<u8>,
    /// 上一批以 `\r` 结尾：下一批开头的 `\n` 属于同一个换行。
    after_cr: bool,
    name: Option<String>,
    data: String,
    has_data: bool,
    id: Option<String>,
}

impl Parser {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂一批字节，把这批里完整的项追加到 `out`。
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Item>) {
        let mut rest = bytes;
        if self.after_cr {
            self.after_cr = false;
            if let Some(stripped) = rest.strip_prefix(b"\n") {
                rest = stripped;
            }
        }
        while let Some(at) = rest.iter().position(|&byte| byte == b'\n' || byte == b'\r') {
            self.line.extend_from_slice(&rest[..at]);
            let line = std::mem::take(&mut self.line);
            self.process_line(&line, out);
            let terminator = rest[at];
            rest = &rest[at + 1..];
            if terminator == b'\r' {
                match rest.first() {
                    Some(b'\n') => rest = &rest[1..],
                    Some(_) => {}
                    None => self.after_cr = true,
                }
            }
        }
        self.line.extend_from_slice(rest);
    }

    fn process_line(&mut self, line: &[u8], out: &mut Vec<Item>) {
        if line.is_empty() {
            self.dispatch(out);
            return;
        }
        let text = String::from_utf8_lossy(line);
        if let Some(comment) = text.strip_prefix(':') {
            out.push(Item::Comment(comment.trim_start().to_owned()));
            return;
        }
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (text.as_ref(), ""),
        };
        match field {
            "event" => self.name = Some(value.to_owned()),
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            "id" => self.id = Some(value.to_owned()),
            // 按规范忽略 retry 及未知字段。
            _ => {}
        }
    }

    fn dispatch(&mut self, out: &mut Vec<Item>) {
        let name = self.name.take();
        let id = self.id.take();
        // 规范：没有 data 的事件不派发。
        if !std::mem::take(&mut self.has_data) {
            return;
        }
        out.push(Item::Event(Event { name, data: std::mem::take(&mut self.data), id }));
    }
}

/// 把一个事件编码追加到 `out`。`data` 里不能有换行（这里的事件都是一行 JSON）。
pub fn write_event(out: &mut String, name: Option<&str>, id: Option<u64>, data: &str) {
    debug_assert!(!data.contains(['\n', '\r']), "多行 data 要拆成多个 data 字段，这里用不到");
    if let Some(id) = id {
        writeln!(out, "id: {id}").expect("写 String 不会失败");
    }
    if let Some(name) = name {
        writeln!(out, "event: {name}").expect("写 String 不会失败");
    }
    writeln!(out, "data: {data}\n").expect("写 String 不会失败");
}

pub fn write_comment(out: &mut String, text: &str) {
    writeln!(out, ": {text}\n").expect("写 String 不会失败");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_in_pieces(bytes: &[u8], piece: usize) -> Vec<Item> {
        let mut parser = Parser::new();
        let mut out = Vec::new();
        for chunk in bytes.chunks(piece) {
            parser.feed(chunk, &mut out);
        }
        out
    }

    fn event(name: Option<&str>, data: &str, id: Option<&str>) -> Item {
        Item::Event(Event { name: name.map(str::to_owned), data: data.to_owned(), id: id.map(str::to_owned) })
    }

    #[test]
    fn encoded_events_parse_back_whatever_the_split() {
        let mut text = String::new();
        write_comment(&mut text, "keep-alive");
        write_event(&mut text, None, Some(0), r#"{"seq":0}"#);
        write_event(&mut text, Some("end"), None, r#"{"count":1}"#);
        write_event(&mut text, None, None, "[DONE]");
        let expected = vec![
            Item::Comment("keep-alive".into()),
            event(None, r#"{"seq":0}"#, Some("0")),
            event(Some("end"), r#"{"count":1}"#, None),
            event(None, "[DONE]", None),
        ];
        for piece in [1, 2, 3, 7, 1000] {
            assert_eq!(parse_in_pieces(text.as_bytes(), piece), expected, "按 {piece} 字节一批喂");
        }
    }

    #[test]
    fn all_three_line_endings_work_even_when_crlf_is_split() {
        let text = b"data: a\r\n\r\ndata: b\r\rdata: c\n\n";
        let expected = vec![event(None, "a", None), event(None, "b", None), event(None, "c", None)];
        for piece in [1, 2, 4, 100] {
            assert_eq!(parse_in_pieces(text, piece), expected, "按 {piece} 字节一批喂");
        }
    }

    #[test]
    fn data_lines_join_with_newlines_and_a_field_without_colon_is_empty() {
        let text = b"data: one\ndata:two\ndata\n\n";
        assert_eq!(parse_in_pieces(text, 100), vec![event(None, "one\ntwo\n", None)]);
    }

    #[test]
    fn blocks_without_data_and_unknown_fields_dispatch_nothing() {
        let text = b"event: ping\nretry: 10\n\nfoo: bar\n\n";
        assert!(parse_in_pieces(text, 100).is_empty());
    }

    #[test]
    fn an_unfinished_event_is_not_dispatched() {
        assert!(parse_in_pieces(b"data: half", 3).is_empty());
        assert!(parse_in_pieces(b"data: half\n", 3).is_empty());
    }
}
