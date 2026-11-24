//! WebUI 的静态文件从哪里来。
//!
//! 三种来路，装配的时候选一种（[`WebUi`]）：
//!
//! - 编译进可执行文件里的（正式的发布是这样）：可执行文件在构建时把 `web/dist` 里的文件打进去，交到这里来发；
//! - 运行时指定的一个目录（`i3t-controller --static-dir`）：开发 WebUI 时用，或者想换一套界面；
//! - 都没有：这次构建没有带 WebUI。这时回一个说明页，而不是一串 404。
//!
//! 静态文件不需要管理令牌：里面没有任何数据，数据都要经过 `/api/v1`。

use std::path::PathBuf;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use tower_http::services::{ServeDir, ServeFile};

/// 编译进程序里的一个文件。
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// 相对于 WebUI 根目录的路径，用 `/` 分隔，例如 `assets/index-3f2a.js`。
    pub path: &'static str,
    pub bytes: &'static [u8],
}

/// WebUI 的静态文件从哪里来。
#[derive(Debug, Clone, Default)]
pub enum WebUi {
    /// 这次构建没有带 WebUI，也没有指定目录。
    #[default]
    NotIncluded,
    /// 编译进程序里的文件。里面要有 `index.html`；没有的话等同于 [`WebUi::NotIncluded`]。
    Embedded(&'static [Asset]),
    /// 运行时从这个目录取。
    Dir(PathBuf),
}

const INDEX: &str = "index.html";

/// 没有带 WebUI 的构建在 `/` 上回的说明页。
const NOT_INCLUDED_PAGE: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ice3tier controller</title>
<style>
  body { font: 16px/1.6 system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; color: #222; }
  code { background: #f2f2f2; padding: .1em .35em; border-radius: 4px; }
  h1 { font-size: 1.4rem; }
</style>
</head>
<body>
<h1>当前 controller 没有带 WebUI</h1>
<p>controller 正在正常运行，管理 API 位于 <code>/api/v1</code>，命令行工具 <code>i3tctl</code> 可正常使用。当前构建的程序未内嵌 Web 界面。</p>
<p>如需使用 Web 界面，可任选以下方式之一：</p>
<ul>
<li>使用项目发布的 <code>i3t-controller</code>（已内置 Web 界面）；</li>
<li>自行构建：先在源码的 <code>web/</code> 目录下构建出 <code>web/dist</code>，再重新编译 <code>i3t-controller</code>；</li>
<li>若已有构建好的静态文件目录，启动时传入 <code>--static-dir &lt;目录&gt;</code>。</li>
</ul>
</body>
</html>
"#;

impl WebUi {
    /// 把 WebUI 挂到 `router` 上：`router` 里没有匹配的路径都交给它。不是文件的路径回 `index.html`，给单页应用的前端路由用。
    pub(crate) fn attach(&self, router: Router) -> Router {
        match self {
            Self::Dir(dir) => router.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(dir.join(INDEX)))),
            Self::Embedded(assets) if find(assets, INDEX).is_some() => router.fallback_service(get(embedded).with_state(*assets)),
            Self::Embedded(_) | Self::NotIncluded => router.fallback_service(get(not_included)),
        }
    }
}

fn find(assets: &'static [Asset], path: &str) -> Option<&'static Asset> {
    assets.iter().find(|asset| asset.path == path)
}

async fn not_included() -> Html<&'static str> {
    Html(NOT_INCLUDED_PAGE)
}

async fn embedded(State(assets): State<&'static [Asset]>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let Some(asset) = find(assets, path).or_else(|| find(assets, INDEX)) else {
        // 挂上来之前查过有 index.html，走不到这里。
        return StatusCode::NOT_FOUND.into_response();
    };
    // 构建工具给 assets/ 下面的文件名里带了内容的哈希，内容变了名字就变，可以一直缓存。别的文件（index.html）每次都要问。
    let cache = if asset.path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    let headers = [
        (header::CONTENT_TYPE, HeaderValue::from_static(content_type(asset.path))),
        (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
    ];
    (headers, asset.bytes).into_response()
}

/// 按扩展名给出内容类型。只列构建出来的 WebUI 里会有的那些。
fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_cover_what_a_built_web_ui_contains() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("assets/index-3f2a.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("assets/index-9c1b.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("favicon.svg"), "image/svg+xml");
        assert_eq!(content_type("LICENSE"), "application/octet-stream");
    }

    #[test]
    fn the_built_in_page_explains_how_to_get_the_web_ui() {
        assert!(
            NOT_INCLUDED_PAGE.contains("--static-dir") && NOT_INCLUDED_PAGE.contains("web/dist") && NOT_INCLUDED_PAGE.contains("/api/v1")
        );
    }
}
