//! 更新包来源抽象。

use std::future::Future;

use i3t_model::update::{Platform, Version};

/// 请求指定版本与平台更新包中从 `offset` 开始的数据块。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRequest<'a> {
    pub version: &'a Version,
    pub platform: &'a Platform,
    pub offset: u64,
    /// 本次最多请求的字节数。
    pub len: u32,
}

/// 节点获取更新包的数据源。节点不直接连接发布源，而是经控制链路从 controller 缓存中分块拉取；
/// 本 trait 抽象了该链路在更新层所需的接口。
pub trait PackageSource: Send + Sync {
    /// 拉取 `[offset, offset + len)` 区间的数据块。
    ///
    /// 约定：返回字节数不得超过 `len` 且不得为 0；允许少于 `len`，下载方会继续请求剩余部分。
    /// 返回内容无需预先可信，完整下载后会依据已签名发布清单校验大小与 SHA-256。
    fn fetch(&self, request: ChunkRequest<'_>) -> impl Future<Output = Result<Vec<u8>, SourceError>> + Send;
}

/// 分块拉取失败原因。下载方对两类错误的处理策略不同，因此需区分上报。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// 链路中断、超时等临时性故障：等待后从同一偏移量重试，不视为更新失败。
    #[error("更新包下载中断：{0}")]
    Interrupted(String),
    /// 更新源明确表示无法提供该包（如版本或平台不存在）：继续重试无意义，直接中止本次更新。
    #[error("更新源无法提供该更新包：{0}")]
    Unavailable(String),
}
