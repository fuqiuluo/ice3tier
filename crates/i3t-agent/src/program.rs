//! 这个节点程序自己的情况：版本、程序文件在哪里、能不能自己更新。

use std::path::PathBuf;

use anyhow::Context;
use i3t_model::control::SelfUpdate;
use i3t_model::update::{SelfUpdateBlocker, Version};

/// 正在运行的这个节点程序。进程启动时查一次（[`Program::detect`]），之后一直用这个结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// 版本号。由可执行文件给：报给 controller 的、和发布清单比的都是它。
    pub version: Version,
    /// 程序文件的真实路径。更新时换的就是这个文件。
    pub path: PathBuf,
    /// 不能自己更新的原因；能的话是 `None`。
    pub blocker: Option<SelfUpdateBlocker>,
}

impl Program {
    /// 查出正在运行的程序文件，以及它能不能自己更新。
    ///
    /// 要在进程一启动就调用：程序文件被换过之后，系统报出来的"自己的路径"指向的就不是原来的位置了。
    /// 它会在程序所在的目录里试着建一个文件，所以一个进程只调用一次。
    ///
    /// # Errors
    ///
    /// 无法获取当前可执行文件路径。
    pub fn detect(version: Version) -> anyhow::Result<Self> {
        let path = i3t_update::current_program().context(crate::texts::texts().find_program)?;
        let blocker = i3t_update::self_update_blocker(&path);
        Ok(Self { version, path, blocker })
    }

    /// 报给 controller 的"能不能自己更新"。
    #[must_use]
    pub fn self_update(&self) -> SelfUpdate {
        SelfUpdate::from(self.blocker)
    }
}
