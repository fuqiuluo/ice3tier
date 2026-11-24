//! 上游和负载端共用的东西：每个事件带的序号、写出时刻和累积哈希，以及请求里描述"这条流该怎么回答"的参数。
//!
//! 累积哈希将每个事件与其之前的所有事件关联在一起：接收方按收到的数据重新计算，任何丢失、乱序或单字节篡改都会导致校验不匹配。

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// 墙上时钟的纳秒数。同一台机器上的各个网络命名空间共用一个时钟，所以本机的测试里可以拿它算单向延迟；
/// 跨机器时两边的时钟差多少就错多少，只能看间隔。
pub fn now_ns() -> u64 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    u64::try_from(since_epoch.as_nanos()).unwrap_or(u64::MAX)
}

/// 64 位的 FNV-1a。只用来发现传输中的错误，不防故意伪造。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fnv(u64);

impl Fnv {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    pub const fn new() -> Self {
        Self(Self::OFFSET)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub fn of(bytes: &[u8]) -> u64 {
        let mut hash = Self::new();
        hash.update(bytes);
        hash.value()
    }
}

impl Default for Fnv {
    fn default() -> Self {
        Self::new()
    }
}

/// 一个事件的序号、写出时刻和写完它之后的累积哈希。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub seq: u64,
    pub t_ns: u64,
    pub hash: u64,
}

/// 一串事件的累积哈希。发送方用 [`Chain::seal`] 给事件盖章，接收方用 [`Chain::check`] 按同样的顺序验。
#[derive(Clone, Debug)]
pub struct Chain {
    hash: u64,
    next_seq: u64,
}

impl Chain {
    pub const fn new() -> Self {
        Self { hash: Fnv::OFFSET, next_seq: 0 }
    }

    /// 下一个事件该有的序号，也就是到现在为止的事件数。
    pub const fn count(&self) -> u64 {
        self.next_seq
    }

    pub const fn hash(&self) -> u64 {
        self.hash
    }

    fn mix(hash: u64, seq: u64, t_ns: u64, payload: &[u8]) -> u64 {
        let mut fnv = Fnv(hash);
        fnv.update(&seq.to_le_bytes());
        fnv.update(&t_ns.to_le_bytes());
        fnv.update(payload);
        fnv.value()
    }

    pub fn seal(&mut self, t_ns: u64, payload: &[u8]) -> Stamp {
        let seq = self.next_seq;
        self.hash = Self::mix(self.hash, seq, t_ns, payload);
        self.next_seq += 1;
        Stamp { seq, t_ns, hash: self.hash }
    }

    /// 校验收到的事件。仅通过校验的事件会计入哈希链；校验失败时链状态不变，调用方应将该流判定为损坏。
    ///
    /// # Errors
    ///
    /// 序号与预期不符（丢失或乱序），或根据内容计算的哈希与事件携带的累积哈希不匹配。
    pub fn check(&mut self, stamp: Stamp, payload: &[u8]) -> Result<(), ChainError> {
        if stamp.seq != self.next_seq {
            return Err(ChainError::OutOfOrder { expected: self.next_seq, got: stamp.seq });
        }
        let hash = Self::mix(self.hash, stamp.seq, stamp.t_ns, payload);
        if hash != stamp.hash {
            return Err(ChainError::BadHash { seq: stamp.seq });
        }
        self.hash = hash;
        self.next_seq += 1;
        Ok(())
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("该收到第 {expected} 个事件，收到的是第 {got} 个")]
    OutOfOrder { expected: u64, got: u64 },
    #[error("第 {seq} 个事件的内容与累积哈希不匹配")]
    BadHash { seq: u64 },
}

/// 填充用的文本：只有字母和空格，放进 JSON 字符串不需要转义。
const FILLER: &[u8] = b"the quick brown fox jumps over the lazy dog while a model thinks about tokens ";

/// 第 `seq` 个事件的填充内容，长度 `len`。内容随序号错开，同样长度的事件不完全一样。
pub fn filler(seq: u64, len: usize) -> String {
    let start = usize::try_from(seq % FILLER.len() as u64).expect("余数小于填充文本的长度");
    FILLER.iter().cycle().skip(start).take(len).map(|&byte| char::from(byte)).collect()
}

/// 请求体里的提示词：长度 `len`，内容由流的编号决定。上游按请求里带的哈希核对它是否完整到达。
pub fn prompt(stream: u64, len: usize) -> String {
    filler(stream.wrapping_mul(31), len)
}

/// 答案怎么结束。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum End {
    /// 发完全部事件和终止事件，正常关闭。
    #[default]
    Done,
    /// 发完 `end_after` 个事件后重置连接（RST），模拟上游中途出错。
    Abort,
    /// 发完 `end_after` 个事件后不再发任何东西，连接一直开着，直到对方关闭。
    Stall,
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Done => "done",
            Self::Abort => "abort",
            Self::Stall => "stall",
        })
    }
}

/// 答案中途的一次停顿（比如模型在调用工具）：发完第 `after` 个事件之后停 `ms` 毫秒。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pause {
    pub after: u32,
    pub ms: u64,
}

/// 上游怎么生成一段流式回答。SSE 的一个请求是一段，WebSocket 的每一轮是一段。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    /// 收到请求之后先"思考"多久，这段时间里不发任何事件。
    pub think_ms: u64,
    /// 思考期间每隔多久发一个保活注释（SSE 的 `: keep-alive`）；0 表示完全静默。WebSocket 不用它，用 ping。
    #[serde(default)]
    pub keepalive_ms: u64,
    /// 事件个数。
    pub tokens: u32,
    /// 每秒多少个事件；0 表示连接收多快就发多快。
    pub rate: u32,
    /// 每个事件里填充内容的字节数，不含序号、时间、哈希这些固定的部分。
    pub event_bytes: u32,
    #[serde(default)]
    pub pauses: Vec<Pause>,
    #[serde(default)]
    pub end: End,
    /// `end` 是 abort 或 stall 时，发完多少个事件之后出事。WebSocket 里按整个会话累计。
    #[serde(default)]
    pub end_after: u32,
}

impl Answer {
    /// 第 `index` 个事件按计划在开始发之后多久发出：均匀的节拍，加上排在它前面的停顿。速率是 0 时只算停顿。
    pub fn due_after_start(&self, index: u32) -> std::time::Duration {
        let paced = match self.rate {
            0 => std::time::Duration::ZERO,
            rate => std::time::Duration::from_secs_f64(f64::from(index) / f64::from(rate)),
        };
        let paused: u64 = self.pauses.iter().filter(|pause| pause.after <= index && pause.after > 0).map(|pause| pause.ms).sum();
        paced + std::time::Duration::from_millis(paused)
    }
}

/// SSE 端点的请求体。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SseRequest {
    /// 流的名字，只用于日志。
    pub stream: String,
    pub answer: Answer,
    /// 提示词的 FNV-1a，十六进制。
    pub prompt_hash: String,
    pub prompt: String,
}

/// WebSocket 会话的描述，客户端在第一条消息里发给上游。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub stream: String,
    /// 每一轮怎么回答。`end_after` 按整个会话累计。
    pub answer: Answer,
    /// 回答的事件用二进制帧（音频那样），否则用文本消息。
    #[serde(default)]
    pub binary: bool,
    /// 上游每隔多久发一个 ping；0 表示不发。
    #[serde(default)]
    pub server_ping_ms: u64,
}

/// WebSocket 上的文本消息。客户端和上游都用它，`type` 字段区分。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WsText {
    /// 客户端：会话开始。
    Session(Session),
    /// 客户端：开始一轮，带着这一轮的提示词。
    Turn { turn: u32, prompt_hash: String, prompt: String },
    /// 客户端：回答进行中插进来的一条消息。带着客户端那一串消息的序号和累积哈希。
    Note { seq: u64, t: u64, h: String, text: String },
    /// 客户端：请上游报一下到现在为止收到并且验过了什么。WebSocket 是有序的，上游处理它的时候，
    /// 客户端在它之前发的东西都已经处理完了，所以回答的计数必须和客户端发出的完全相等。
    Sync,
    /// 上游：回答里的一个事件（文本形式）。
    Delta { turn: u32, seq: u64, t: u64, h: String, delta: String },
    /// 上游：一轮的事件发完了，这一轮发了多少个。
    TurnDone { turn: u32, events: u64 },
    /// 上游：对 `Sync` 的回答。客户端消息和客户端二进制帧的累计数和累积哈希，以及收到的 pong 数。
    Synced { notes: u64, notes_hash: String, binary: u64, binary_hash: String, pongs: u64 },
    /// 上游：客户端消息校验失败或请求无效，随后上游关闭会话。
    Error { detail: String },
}

/// 二进制帧的头：序号、写出时刻、累积哈希，各 8 字节小端，后面是填充。
pub const BINARY_HEADER: usize = 24;

/// 组一个二进制帧：头加 `len` 字节的填充。盖章覆盖的是填充部分。
pub fn binary_frame(chain: &mut Chain, len: usize) -> Vec<u8> {
    let payload = filler(chain.count(), len);
    let stamp = chain.seal(now_ns(), payload.as_bytes());
    let mut frame = Vec::with_capacity(BINARY_HEADER + len);
    frame.extend_from_slice(&stamp.seq.to_le_bytes());
    frame.extend_from_slice(&stamp.t_ns.to_le_bytes());
    frame.extend_from_slice(&stamp.hash.to_le_bytes());
    frame.extend_from_slice(payload.as_bytes());
    frame
}

/// 拆开一个二进制帧；比头还短时返回 `None`。
pub fn parse_binary_frame(frame: &[u8]) -> Option<(Stamp, &[u8])> {
    let (header, payload) = frame.split_at_checked(BINARY_HEADER)?;
    let field = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().expect("头的长度是固定的 24 字节"));
    Some((Stamp { seq: field(0), t_ns: field(8), hash: field(16) }, payload))
}

/// 哈希在 JSON 里的写法：16 位十六进制。
pub fn hex(hash: u64) -> String {
    format!("{hash:016x}")
}

pub fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn chain_accepts_events_in_order_and_ends_with_the_senders_hash() {
        let mut sender = Chain::new();
        let mut receiver = Chain::new();
        for seq in 0..50 {
            let payload = filler(seq, 40);
            let stamp = sender.seal(1_000 + seq, payload.as_bytes());
            receiver.check(stamp, payload.as_bytes()).unwrap();
        }
        assert_eq!(receiver.count(), 50);
        assert_eq!(receiver.hash(), sender.hash());
    }

    #[test]
    fn chain_reports_a_missing_event_as_out_of_order() {
        let mut sender = Chain::new();
        let mut receiver = Chain::new();
        let first = sender.seal(1, b"a");
        let _lost = sender.seal(2, b"b");
        let third = sender.seal(3, b"c");
        receiver.check(first, b"a").unwrap();
        assert_eq!(receiver.check(third, b"c"), Err(ChainError::OutOfOrder { expected: 1, got: 2 }));
    }

    #[test]
    fn chain_reports_a_changed_byte_and_does_not_advance() {
        let mut sender = Chain::new();
        let mut receiver = Chain::new();
        let stamp = sender.seal(7, b"hello");
        assert_eq!(receiver.check(stamp, b"hellp"), Err(ChainError::BadHash { seq: 0 }));
        assert_eq!(receiver.count(), 0);
        receiver.check(stamp, b"hello").unwrap();
    }

    #[test]
    fn chain_notices_a_changed_timestamp() {
        let mut sender = Chain::new();
        let mut receiver = Chain::new();
        let stamp = sender.seal(7, b"x");
        assert!(receiver.check(Stamp { t_ns: 8, ..stamp }, b"x").is_err());
    }

    #[test]
    fn filler_has_the_requested_length_and_needs_no_json_escaping() {
        for len in [0, 1, 79, 80, 1000] {
            let text = filler(len as u64, len);
            assert_eq!(text.len(), len);
            assert!(text.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b' '));
        }
        assert_ne!(filler(0, 30), filler(1, 30));
    }

    #[test]
    fn binary_frames_round_trip_and_verify() {
        let mut sender = Chain::new();
        let mut receiver = Chain::new();
        for _ in 0..5 {
            let frame = binary_frame(&mut sender, 100);
            assert_eq!(frame.len(), BINARY_HEADER + 100);
            let (stamp, payload) = parse_binary_frame(&frame).unwrap();
            receiver.check(stamp, payload).unwrap();
        }
        assert!(parse_binary_frame(&[0; 10]).is_none());
    }

    #[test]
    fn schedule_spreads_events_at_the_rate_and_adds_pauses_after_their_event() {
        let answer = Answer {
            think_ms: 0,
            keepalive_ms: 0,
            tokens: 100,
            rate: 50,
            event_bytes: 10,
            pauses: vec![Pause { after: 10, ms: 2000 }],
            end: End::Done,
            end_after: 0,
        };
        assert_eq!(answer.due_after_start(0), Duration::ZERO);
        assert_eq!(answer.due_after_start(9), Duration::from_millis(180));
        assert_eq!(answer.due_after_start(10), Duration::from_millis(2200));
        let flat = Answer { rate: 0, pauses: vec![], ..answer };
        assert_eq!(flat.due_after_start(99), Duration::ZERO);
    }

    #[test]
    fn ws_messages_are_tagged_by_type() {
        let text = serde_json::to_string(&WsText::Note { seq: 1, t: 2, h: hex(3), text: "x".into() }).unwrap();
        assert!(text.starts_with(r#"{"type":"note""#), "{text}");
        let back: WsText = serde_json::from_str(&text).unwrap();
        assert_eq!(back, WsText::Note { seq: 1, t: 2, h: hex(3), text: "x".into() });
        assert_eq!(parse_hex(&hex(u64::MAX)), Some(u64::MAX));
    }
}
