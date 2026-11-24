//! 测量流：主动测试量吞吐用的流。
//!
//! 发起方向对端开一条流，OPEN 的类型是 `0x03`，接受方是节点内建的测量服务，不是出口。格式在上一级模块的文档里：
//!
//! - **方式** 1 是"收"：发起方往流里写，测量服务读完丢掉。发起方写完（或者到了自己的上限）就正常结束发送方向；
//!   测量服务到了它自己的上限就叫停这个方向。之后测量服务写一个 [`MeasureSummary`]（它收到了多少、用了多久、为什么停，
//!   末尾可附带去除预热阶段后的稳态统计）并正常结束。
//! - **方式** 2 是"发"：测量服务往回写，最多写字节上限那么多、最多写时长上限那么久，然后正常结束。发起方不写任何东西。
//! - **测试编号** 和主动测试的探测（[`crate::probe::TestPing`]）里的是同一个。测量服务只接受它知道的、还在时间窗里的测试，
//!   并且只接受指令里那个对端开来的流。
//! - **relay** 是这条流在测的路径：0 个是直连。测量服务把自己发回去的包也固定在倒过来的同一条路径上，这样两个方向量的是同一条路。
//! - **字节上限、时长上限** 是发起方要的；测量服务按自己的上限截断，不管发起方要多少。
//!
//! 测量服务回的是普通的 REPLY；不接受时是一个失败的 REPLY，流随即结束。

use super::{DecodeError, Halt, Reader};
use crate::datagram::{MAX_RELAY_HOPS, RelayPath};
use crate::node::NodeId;
use crate::probe::TestId;

const MODE_SINK: u8 = 1;
const MODE_SOURCE: u8 = 2;

/// 测量流的方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeasureMode {
    /// 发起方发、测量服务收：量的是发起方到对端（"上行"）。
    Sink,
    /// 测量服务发、发起方收：量的是对端到发起方（"下行"）。
    Source,
}

/// 测量流的 OPEN。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenMeasure {
    pub test: TestId,
    pub mode: MeasureMode,
    /// 在测的路径；`None` 是直连。
    pub path: Option<RelayPath>,
    /// 发起方要的字节数上限。
    pub bytes: u64,
    /// 发起方要的时长上限，毫秒。
    pub millis: u32,
}

impl OpenMeasure {
    /// 编码之后最长多少字节：经 4 个 relay 时。
    pub const MAX_LEN: usize = 2 + 8 + 1 + MAX_RELAY_HOPS * NodeId::WIRE_LEN + 8 + 4;

    /// 把头追加到 `buf` 末尾。
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mode = match self.mode {
            MeasureMode::Sink => MODE_SINK,
            MeasureMode::Source => MODE_SOURCE,
        };
        buf.extend_from_slice(&[super::KIND_OPEN_MEASURE, mode]);
        buf.extend_from_slice(&self.test.to_be_bytes());
        let relays = self.path.as_ref().map_or(&[][..], RelayPath::as_slice);
        buf.push(u8::try_from(relays.len()).expect("一条路径最多 4 个 relay"));
        for relay in relays {
            buf.extend_from_slice(&relay.to_be_bytes());
        }
        buf.extend_from_slice(&self.bytes.to_be_bytes());
        buf.extend_from_slice(&self.millis.to_be_bytes());
    }

    /// 类型和方式已经读走，读剩下的部分。
    pub(super) fn after_kind(reader: &mut Reader<'_>, mode: u8) -> Result<Self, Halt> {
        let mode = match mode {
            MODE_SINK => MeasureMode::Sink,
            MODE_SOURCE => MeasureMode::Source,
            other => return Err(DecodeError::UnknownMeasureMode(other).into()),
        };
        let test = u64::from_be_bytes(reader.array()?);
        let count = usize::from(reader.u8()?);
        if count > MAX_RELAY_HOPS {
            return Err(DecodeError::BadPath.into());
        }
        let mut relays = Vec::with_capacity(count);
        for _ in 0..count {
            relays.push(NodeId::from_be_bytes(reader.array()?).ok_or(DecodeError::BadPath)?);
        }
        let path = if relays.is_empty() { None } else { Some(RelayPath::new(&relays).map_err(|_| DecodeError::BadPath)?) };
        let bytes = u64::from_be_bytes(reader.array()?);
        let millis = u32::from_be_bytes(reader.array()?);
        Ok(Self { test, mode, path, bytes, millis })
    }
}

/// 测量服务在"收"的方式下最后写回的一段：它收到了多少、从第一个字节到最后一个字节用了多久、为什么停，
/// 末尾可附带去除预热阶段后的稳态统计（[`MeasureSteady`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasureSummary {
    pub bytes: u64,
    /// 从收到第一个字节到收到最后一个字节，毫秒。
    pub millis: u32,
    pub end: MeasureEnd,
    /// 去除初始预热阶段后的统计数据。传输未完成预热阶段即结束时为 `None`；较早版本不写入该部分，读取方读不到时视为 `None`。
    pub steady: Option<MeasureSteady>,
}

/// 单次传输去除初始预热阶段后的统计：接收字节数与耗时。连接刚开始发送时速率需从低位爬升，
/// 若将预热阶段计入会导致测得吞吐偏低，且偏差程度取决于该连接此前是否已发送过数据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasureSteady {
    pub bytes: u64,
    /// 从起步结束到收到最后一个字节，毫秒。
    pub millis: u32,
}

impl MeasureSteady {
    pub const LEN: usize = 8 + 4;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[..8].copy_from_slice(&self.bytes.to_be_bytes());
        bytes[8..].copy_from_slice(&self.millis.to_be_bytes());
        bytes
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        let [b0, b1, b2, b3, b4, b5, b6, b7, millis @ ..] = *bytes;
        Self { bytes: u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]), millis: u32::from_be_bytes(millis) }
    }
}

/// 一个方向的搬运为什么停。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeasureEnd {
    /// 发的一方自己正常结束了。
    Finished,
    /// 到了字节上限。
    Bytes,
    /// 到了时长上限。
    Time,
}

impl MeasureSummary {
    /// 前部固定字段的长度。末尾可选稳态段长度为 [`MeasureSteady::LEN`]。
    pub const LEN: usize = 8 + 4 + 1;
    pub const MAX_LEN: usize = Self::LEN + MeasureSteady::LEN;

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out.extend_from_slice(&self.millis.to_be_bytes());
        out.push(match self.end {
            MeasureEnd::Finished => 0,
            MeasureEnd::Bytes => 1,
            MeasureEnd::Time => 2,
        });
        if let Some(steady) = self.steady {
            out.extend_from_slice(&steady.to_bytes());
        }
    }

    /// 解析前部固定字段，`steady` 置为 `None`。未知结束原因返回 `None`。
    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Option<Self> {
        let (count, rest) = bytes.split_first_chunk::<8>()?;
        let (millis, rest) = rest.split_first_chunk::<4>()?;
        let end = match rest.first()? {
            0 => MeasureEnd::Finished,
            1 => MeasureEnd::Bytes,
            2 => MeasureEnd::Time,
            _ => return None,
        };
        Some(Self { bytes: u64::from_be_bytes(*count), millis: u32::from_be_bytes(*millis), end, steady: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Decoded, Opening};

    fn node(raw: u32) -> NodeId {
        NodeId::new(raw).unwrap()
    }

    #[test]
    fn a_measurement_open_has_the_documented_layout_and_round_trips() {
        let open = OpenMeasure {
            test: 7,
            mode: MeasureMode::Sink,
            path: RelayPath::new(&[node(8), node(9)]).ok(),
            bytes: 20_000_000,
            millis: 5000,
        };
        let mut buf = Vec::new();
        open.encode(&mut buf);
        assert_eq!(&buf[..11], [0x03, 1, 0, 0, 0, 0, 0, 0, 0, 7, 2]);
        assert_eq!(&buf[11..19], [0, 0, 0, 8, 0, 0, 0, 9]);
        assert_eq!(buf.len(), 2 + 8 + 1 + 8 + 8 + 4);
        assert!(buf.len() <= OpenMeasure::MAX_LEN);
        assert_eq!(Opening::decode(&buf), Ok(Decoded::Complete { value: Opening::Measure(open), len: buf.len() }));

        let direct = OpenMeasure { mode: MeasureMode::Source, path: None, ..open };
        let mut buf = Vec::new();
        direct.encode(&mut buf);
        buf.extend_from_slice(b"no data follows, but the header ends here");
        assert_eq!(Opening::decode(&buf), Ok(Decoded::Complete { value: Opening::Measure(direct), len: 23 }));
        // 读的一方一点一点读：每次要的不超过头里还缺的。
        for cut in 0..23 {
            assert!(matches!(Opening::decode(&buf[..cut]), Ok(Decoded::Incomplete { more }) if more <= 23 - cut), "{cut}");
        }
    }

    #[test]
    fn a_measurement_open_with_a_bad_mode_or_path_is_refused() {
        assert_eq!(Opening::decode(&[0x03, 9]), Err(DecodeError::UnknownMeasureMode(9)));
        let mut too_long = vec![0x03, 1, 0, 0, 0, 0, 0, 0, 0, 7, 5];
        too_long.extend_from_slice(&[0; 40]);
        assert_eq!(Opening::decode(&too_long), Err(DecodeError::BadPath));
        let mut repeated = vec![0x03, 1, 0, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 0, 8, 0, 0, 0, 8];
        repeated.extend_from_slice(&[0; 12]);
        assert_eq!(Opening::decode(&repeated), Err(DecodeError::BadPath));
    }

    #[test]
    fn a_summary_round_trips_with_and_without_the_steady_part() {
        for end in [MeasureEnd::Finished, MeasureEnd::Bytes, MeasureEnd::Time] {
            let plain = MeasureSummary { bytes: 1 << 33, millis: 5000, end, steady: None };
            let mut wire = Vec::new();
            plain.encode(&mut wire);
            assert_eq!(wire.len(), MeasureSummary::LEN);
            assert_eq!(MeasureSummary::from_bytes(wire.as_slice().try_into().unwrap()), Some(plain));

            let steady = MeasureSteady { bytes: 1 << 32, millis: 3750 };
            let mut wire = Vec::new();
            MeasureSummary { steady: Some(steady), ..plain }.encode(&mut wire);
            assert_eq!(wire.len(), MeasureSummary::MAX_LEN);
            let (head, tail) = wire.split_at(MeasureSummary::LEN);
            // 前面那一段和不带的时候一模一样：只认识它的读者照样读得懂。
            assert_eq!(MeasureSummary::from_bytes(head.try_into().unwrap()), Some(plain));
            assert_eq!(MeasureSteady::from_bytes(tail.try_into().unwrap()), steady);
        }
        assert_eq!(MeasureSummary::from_bytes(&[0; 12].into_iter().chain([7]).collect::<Vec<_>>().try_into().unwrap()), None);
    }
}
