//! 复现 LLM 网关负载的测量工具。
//!
//! - `upstream`：模拟的 LLM API，SSE 和 WebSocket，每个请求按请求里写的参数回答。
//! - `load`：扮演网关，按场景文件经节点的代理入口（或者直连，作为对照）发流，验证每一条，测量，出报告。
//!
//! 每个事件带序号、写出时刻和累积哈希，负载端据此证明顺序、完整性，测出每个事件路上多花的时间。

mod chunked;
mod http;
mod load;
mod net;
mod proxy;
mod sse;
mod tls;
mod upstream;
mod wire;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "LLM 网关负载：模拟的上游 API 和负载端")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 模拟的 LLM API（HTTPS 和明文 HTTP）
    Upstream(upstream::Args),
    /// 按场景文件发流、验证、测量；有流没有按期望结束时退出码是 1
    Load(load::Args),
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("创建 tokio 运行时失败：{err}");
            return ExitCode::from(2);
        }
    };
    let result = runtime.block_on(async {
        match cli.command {
            Command::Upstream(args) => upstream::run(args).await.map(|()| true),
            Command::Load(args) => load::run(args).await,
        }
    });
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("出错：{err:#}");
            ExitCode::from(2)
        }
    }
}
