//! 场景文件：几组流，每组说清楚是什么流、多少条、怎么到达、上游怎么回答、结果应该是什么。
//!
//! ```toml
//! name = "sse_fast_tokens"
//! duration_s = 120       # 整个运行的上限；到时还没结束的流算超时
//! stall_ms = 250         # 两个事件之间的间隔比上游的节拍多出这么多就算一次卡顿
//!
//! [[group]]
//! name = "fast"
//! kind = "sse"           # sse 或 ws
//! count = 300
//! arrival = "all"        # "all"（同时）、{ rate = 50 }（每秒几条）、{ ramp_s = 10 }（到达速率在这么多秒里从 0 线性涨上去）
//! start_s = 0            # 这一组从运行开始之后多久开始到达
//! prompt_bytes = [20000, 1000000]   # 一个数，或者 [最小, 最大]（每条流在范围里取一个）
//! think_ms = 500
//! keepalive_ms = 0       # SSE 思考期间的保活注释间隔，0 表示完全静默
//! tokens = 1000
//! rate = 300             # 每秒事件数，0 表示连接收多快就发多快
//! event_bytes = 30
//! pauses = [{ after = 500, ms = 2000 }]
//! end = "done"           # done、abort、stall
//! end_after = 0          # abort / stall 在第几个事件之后
//! hold_s = 40            # stall：停住之后负载端再拿着它多久才关
//! expect = "reset"       # 可选：覆盖按 end 推出来的期望结果（上游重启这类由外部造成的失败）
//! ```
//!
//! WebSocket 组另外有 `turns`、`binary`、`client_msgs`、`client_binary_ms`、`client_binary_bytes`、`idle_ms`、
//! `client_ping_ms`、`server_ping_ms`，含义见 [`GroupSpec`]。

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::wire::{Answer, End, Pause};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    #[serde(default)]
    pub name: String,
    pub duration_s: f64,
    #[serde(default = "default_stall_ms")]
    pub stall_ms: u64,
    #[serde(rename = "group")]
    pub groups: Vec<GroupSpec>,
}

const fn default_stall_ms() -> u64 {
    250
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Sse,
    Ws,
}

/// 一组流怎么到达。
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum Arrival {
    /// 只能写 "all"：全部同时。
    All(AllAtOnce),
    /// 每秒 `rate` 条，均匀到达。
    Rate { rate: f64 },
    /// 到达速率在 `ramp_s` 秒里从 0 线性涨到最高，整组在这段时间里到齐。
    Ramp { ramp_s: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllAtOnce {
    All,
}

impl Arrival {
    /// 第 `index` 条（共 `count` 条）在这一组开始之后多久到达。
    pub fn offset(self, index: usize, count: usize) -> Duration {
        let fraction = |index: usize| index as f64 / count.max(1) as f64;
        match self {
            Self::All(_) => Duration::ZERO,
            Self::Rate { rate } => Duration::from_secs_f64(index as f64 / rate),
            // 累计到达数和时间的平方成正比，到达速率就是线性增长的。
            Self::Ramp { ramp_s } => Duration::from_secs_f64(ramp_s * fraction(index).sqrt()),
        }
    }
}

/// 提示词的大小：固定，或者每条流在范围里取一个。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum PromptBytes {
    Fixed(u32),
    Range([u32; 2]),
}

impl PromptBytes {
    /// 第 `index` 条流的提示词大小。范围里的取值由编号决定，同一个场景每次运行都一样。
    pub fn for_stream(self, index: u64) -> usize {
        let (low, high) = match self {
            Self::Fixed(bytes) => (bytes, bytes),
            Self::Range([low, high]) => (low.min(high), low.max(high)),
        };
        let span = u64::from(high - low) + 1;
        let picked = u64::from(low) + mix(index) % span;
        usize::try_from(picked).expect("u32 放得进 usize")
    }
}

/// 把编号打散成看起来随机的数（splitmix64 的末段）。
fn mix(index: u64) -> u64 {
    let mut x = index.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// 一条流结束时的样子。期望和实际都用它。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// 收到了全部事件和终止事件，结尾完整。
    Complete,
    /// 连接被重置（RST）。上游中途出错时应该是这样。
    Reset,
    /// 没有终止事件就收到了 FIN（TLS 的话是没有 close_notify 的 FIN）：被截断了，在 TCP 层却像正常结束。
    Truncated,
    /// 上游按要求停住之后，负载端拿着它到了时候，一直没有出错。
    Stalled,
    /// 到了整个运行的时限还没有结束。
    Timeout,
    /// 顺序、完整性、哈希不对，或者上游说请求体在路上坏了。
    Corrupt,
    /// 代理拒绝了（SOCKS5 的错误码、HTTP 的非 2xx）。
    ProxyRefused,
    /// 无法连接代理（直连模式下为无法连接上游），或代理握手失败。
    ConnectFailed,
    TlsFailed,
    /// 上游回了不该回的状态码。
    HttpError,
    /// 其他读写错误。
    Error,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Reset => "reset",
            Self::Truncated => "truncated",
            Self::Stalled => "stalled",
            Self::Timeout => "timeout",
            Self::Corrupt => "corrupt",
            Self::ProxyRefused => "proxy_refused",
            Self::ConnectFailed => "connect_failed",
            Self::TlsFailed => "tls_failed",
            Self::HttpError => "http_error",
            Self::Error => "error",
        }
    }
}

/// 一组流。SSE 和 WebSocket 共用一个结构，不适用的字段对另一种没有作用。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    pub name: String,
    pub kind: Kind,
    pub count: usize,
    #[serde(default = "default_arrival")]
    pub arrival: Arrival,
    #[serde(default)]
    pub start_s: f64,
    #[serde(default = "default_prompt")]
    pub prompt_bytes: PromptBytes,
    #[serde(default)]
    pub think_ms: u64,
    #[serde(default)]
    pub keepalive_ms: u64,
    pub tokens: u32,
    #[serde(default)]
    pub rate: u32,
    #[serde(default = "default_event_bytes")]
    pub event_bytes: u32,
    #[serde(default)]
    pub pauses: Vec<Pause>,
    #[serde(default)]
    pub end: End,
    #[serde(default)]
    pub end_after: u32,
    #[serde(default = "default_hold_s")]
    pub hold_s: f64,
    #[serde(default)]
    pub expect: Option<Outcome>,
    /// WebSocket：几轮问答。
    #[serde(default = "default_turns")]
    pub turns: u32,
    /// WebSocket：上游的事件用二进制帧。
    #[serde(default)]
    pub binary: bool,
    /// WebSocket：每一轮回答进行中客户端插进几条消息，均匀地分布在这一轮的事件之间。
    #[serde(default)]
    pub client_msgs: u32,
    /// WebSocket：客户端从发出一轮的请求到这一轮结束，每隔多久发一个二进制帧；0 表示不发。
    #[serde(default)]
    pub client_binary_ms: u64,
    #[serde(default = "default_event_bytes")]
    pub client_binary_bytes: u32,
    /// WebSocket：两轮之间客户端空闲多久。
    #[serde(default)]
    pub idle_ms: u64,
    #[serde(default)]
    pub client_ping_ms: u64,
    #[serde(default)]
    pub server_ping_ms: u64,
}

const fn default_arrival() -> Arrival {
    Arrival::All(AllAtOnce::All)
}

const fn default_prompt() -> PromptBytes {
    PromptBytes::Fixed(1000)
}

const fn default_event_bytes() -> u32 {
    40
}

const fn default_hold_s() -> f64 {
    40.0
}

const fn default_turns() -> u32 {
    1
}

impl GroupSpec {
    pub fn answer(&self) -> Answer {
        Answer {
            think_ms: self.think_ms,
            keepalive_ms: self.keepalive_ms,
            tokens: self.tokens,
            rate: self.rate,
            event_bytes: self.event_bytes,
            pauses: self.pauses.clone(),
            end: self.end,
            end_after: self.end_after,
        }
    }

    /// 这一组的流应该怎么结束。
    pub fn expected(&self) -> Outcome {
        self.expect.unwrap_or(match self.end {
            End::Done => Outcome::Complete,
            End::Abort => Outcome::Reset,
            End::Stall => Outcome::Stalled,
        })
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(!self.name.is_empty(), "组要有名字");
        ensure!(self.count > 0, "组 {} 的 count 是 0", self.name);
        match self.arrival {
            Arrival::Rate { rate } => ensure!(rate > 0.0, "组 {} 的到达速率要大于 0", self.name),
            Arrival::Ramp { ramp_s } => ensure!(ramp_s >= 0.0, "组 {} 的 ramp_s 不能是负数", self.name),
            Arrival::All(_) => {}
        }
        ensure!(self.start_s >= 0.0 && self.hold_s >= 0.0, "组 {} 的 start_s、hold_s 不能是负数", self.name);
        if self.end != End::Done {
            let total = match self.kind {
                Kind::Sse => u64::from(self.tokens),
                Kind::Ws => u64::from(self.tokens) * u64::from(self.turns),
            };
            ensure!(u64::from(self.end_after) <= total, "组 {} 的 end_after 超过了它一共要发的事件数 {total}", self.name);
        }
        if self.kind == Kind::Ws {
            ensure!(self.turns > 0, "组 {} 的 turns 是 0", self.name);
            ensure!(self.client_msgs <= self.tokens, "组 {} 的 client_msgs 不能多于每轮的事件数", self.name);
            ensure!(self.keepalive_ms == 0, "组 {}：WebSocket 不用 keepalive_ms，用 client_ping_ms / server_ping_ms", self.name);
        }
        Ok(())
    }
}

impl Scenario {
    /// # Errors
    ///
    /// TOML 不对，或者某一组的参数不合理。
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let scenario: Self = toml::from_str(text).map_err(|err| anyhow::anyhow!("{err}"))?;
        ensure!(scenario.duration_s > 0.0, "duration_s 要大于 0");
        ensure!(!scenario.groups.is_empty(), "至少要有一组（[[group]]）");
        for group in &scenario.groups {
            group.validate()?;
        }
        let mut names: Vec<&str> = scenario.groups.iter().map(|group| group.name.as_str()).collect();
        names.sort_unstable();
        if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
            bail!("组名 {} 重复了", pair[0]);
        }
        Ok(scenario)
    }

    /// # Errors
    ///
    /// 读取文件失败或内容无效。
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("读场景文件 {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("场景文件 {} 有错", path.display()))
    }

    /// 所有流的到达时刻（从运行开始算），按时间排好：(时刻, 组号, 组内编号)。
    pub fn schedule(&self) -> Vec<(Duration, usize, usize)> {
        let mut all: Vec<(Duration, usize, usize)> = self
            .groups
            .iter()
            .enumerate()
            .flat_map(|(group, spec)| {
                (0..spec.count)
                    .map(move |index| (Duration::from_secs_f64(spec.start_s) + spec.arrival.offset(index, spec.count), group, index))
            })
            .collect();
        all.sort_by_key(|&(at, ..)| at);
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
        name = "mix"
        duration_s = 60

        [[group]]
        name = "fast"
        kind = "sse"
        count = 4
        tokens = 100
        rate = 50
        prompt_bytes = [10, 20]
        pauses = [{ after = 10, ms = 500 }]

        [[group]]
        name = "cut"
        kind = "sse"
        count = 2
        arrival = { rate = 2 }
        start_s = 1
        tokens = 100
        end = "abort"
        end_after = 30

        [[group]]
        name = "voice"
        kind = "ws"
        count = 4
        arrival = { ramp_s = 4 }
        tokens = 50
        turns = 2
        binary = true
        end = "stall"
        end_after = 60
        expect = "reset"
    "#;

    #[test]
    fn example_parses_with_defaults_and_derived_expectations() {
        let scenario = Scenario::parse(EXAMPLE).unwrap();
        assert_eq!(scenario.stall_ms, 250);
        let [fast, cut, voice] = &scenario.groups[..] else { panic!("应该有三组") };
        assert_eq!(fast.arrival, Arrival::All(AllAtOnce::All));
        assert_eq!(fast.expected(), Outcome::Complete);
        assert_eq!(fast.answer().pauses, vec![Pause { after: 10, ms: 500 }]);
        assert_eq!(cut.expected(), Outcome::Reset);
        assert_eq!(voice.expected(), Outcome::Reset, "expect 覆盖了按 end 推出来的 stalled");
        assert_eq!(voice.kind, Kind::Ws);
        assert!(voice.binary);
    }

    #[test]
    fn schedule_orders_arrivals_across_groups() {
        let scenario = Scenario::parse(EXAMPLE).unwrap();
        let schedule = scenario.schedule();
        assert_eq!(schedule.len(), 10);
        assert!(schedule.windows(2).all(|pair| pair[0].0 <= pair[1].0));
        let cut: Vec<Duration> = schedule.iter().filter(|entry| entry.1 == 1).map(|entry| entry.0).collect();
        assert_eq!(cut, vec![Duration::from_secs(1), Duration::from_millis(1500)]);
        let voice: Vec<Duration> = schedule.iter().filter(|entry| entry.1 == 2).map(|entry| entry.0).collect();
        // 斜坡：前一半时间里只到了四分之一。
        assert_eq!(
            voice,
            vec![
                Duration::ZERO,
                Duration::from_secs(2),
                Duration::from_secs_f64(4.0 * 0.5_f64.sqrt()),
                Duration::from_secs_f64(4.0 * 0.75_f64.sqrt())
            ]
        );
    }

    #[test]
    fn prompt_sizes_stay_in_range_and_repeat_between_runs() {
        let range = PromptBytes::Range([20_000, 1_000_000]);
        let sizes: Vec<usize> = (0..1000).map(|index| range.for_stream(index)).collect();
        assert!(sizes.iter().all(|&size| (20_000..=1_000_000).contains(&size)));
        assert!(sizes.iter().any(|&size| size < 200_000) && sizes.iter().any(|&size| size > 800_000), "范围两头都要取到");
        assert_eq!(sizes[17], range.for_stream(17));
        assert_eq!(PromptBytes::Fixed(5).for_stream(99), 5);
    }

    #[test]
    fn mistakes_are_reported_with_the_group_name() {
        let bad_end = EXAMPLE.replace("end_after = 30", "end_after = 101");
        assert!(format!("{:#}", Scenario::parse(&bad_end).unwrap_err()).contains("cut"));
        let unknown = EXAMPLE.replace("binary = true", "binary = true\ncolour = 1");
        assert!(Scenario::parse(&unknown).is_err());
        let duplicate = EXAMPLE.replace(r#"name = "cut""#, r#"name = "fast""#);
        assert!(format!("{:#}", Scenario::parse(&duplicate).unwrap_err()).contains("重复"));
        let bad_arrival = EXAMPLE.replace("arrival = { rate = 2 }", "arrival = \"later\"");
        assert!(Scenario::parse(&bad_arrival).is_err());
    }
}
