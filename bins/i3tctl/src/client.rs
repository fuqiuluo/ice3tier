//! 管理 API 的客户端：发请求，把出错的应答变成一句给人看的话。

use anyhow::{Context, anyhow, bail};
use i3t_model::admin::{API_PREFIX, ErrorBody};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::texts::texts;

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    /// `url` 是管理 API 的地址，例如 `http://127.0.0.1:20332`。
    pub fn new(url: &str, token: String) -> anyhow::Result<Self> {
        if !url.starts_with("http://") {
            bail!((texts().ui.url_scheme)(url));
        }
        let http = reqwest::Client::builder().build().context(texts().ui.http_client)?;
        Ok(Self { http, base: format!("{}{API_PREFIX}", url.trim_end_matches('/')), token })
    }

    /// 发一个请求，返回应答的 JSON。没有应答体（删除成功）时是 `null`。
    pub async fn request<B: Serialize + Sync>(&self, method: Method, path: &str, body: Option<&B>) -> anyhow::Result<Value> {
        let ui = &texts().ui;
        let url = format!("{}{path}", self.base);
        let mut request = self.http.request(method, &url).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.with_context(|| (ui.cannot_connect)(&self.base))?;
        let status = response.status();
        let bytes = response.bytes().await.context(ui.read_response)?;
        if status.is_success() {
            return if bytes.is_empty() { Ok(Value::Null) } else { serde_json::from_slice(&bytes).context(ui.not_json) };
        }
        match serde_json::from_slice::<ErrorBody>(&bytes) {
            Ok(body) => {
                let lang = i3t_lang::current();
                let code = serde_json::to_value(body.error.code).ok().and_then(|code| code.as_str().map(str::to_owned)).unwrap_or_default();
                let said = lang.paren(&(lang.codes().api_error)(&body.error), &code);
                Err(if status == StatusCode::UNAUTHORIZED { anyhow!((ui.token_rejected)(&said)) } else { anyhow!(said) })
            }
            Err(_) => Err(anyhow!((ui.unexpected_response)(status.as_u16()))),
        }
    }

    /// 管理 API 下面一个路径的完整地址，给人看的（MCP 端点的地址）。
    pub fn url_of(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        decode(self.request(Method::GET, path, None::<&()>).await?)
    }
}

/// 把应答的 JSON 读成模型里的类型。
pub fn decode<T: DeserializeOwned>(value: Value) -> anyhow::Result<T> {
    serde_json::from_value(value).context(texts().ui.version_mismatch)
}
