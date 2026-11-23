//! 列的值和 Rust 类型之间的转换。
//!
//! 这里的包装类型把"这一列怎么存"写在一处，各张表的读写代码只管用。表里的整数一律是 `BIGINT`：
//! PostgreSQL 的整数是有符号的，编号、时间、计数都用不到最高位，统一成一种就不用在每条语句里对列宽。

use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::net::Ipv4Addr;
use std::str::FromStr;

use bytes::BytesMut;
use i3t_model::admin::{GroupId, NetworkId};
use i3t_proto::{NodeId, PublicKey};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type, to_sql_checked};

type Failure = Box<dyn Error + Sync + Send>;

/// 读一行的结果。列的值读不懂（范围不对、JSON 不是这个类型）也是这个错。
pub(super) type Read<T> = Result<T, tokio_postgres::Error>;

/// JSONB 的二进制写法：一个字节的版本号，后面是 JSON 的文字。
const JSONB_VERSION: u8 = 1;

/// 按 JSON 形式存在 `JSONB` 列里的值：枚举、结构体、列表。
pub(super) struct Json<T>(pub T);

impl<T> Debug for Json<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Json(..)")
    }
}

impl<T: Serialize> ToSql for Json<T> {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        let mut text = serde_json::to_string(&self.0)?;
        // PostgreSQL 的文本里放不了 NUL，JSONB 里的字符串也一样。合法的内容里不会有它（名字、主机名在进来时就过滤了），
        // 可节点报上来的东西不都逐字检查过：去掉它，不让一个字符卡住整条记录。
        if text.contains("\\u0000") {
            let mut value: serde_json::Value = serde_json::from_str(&text)?;
            strip_nul(&mut value);
            text = serde_json::to_string(&value)?;
        }
        if *ty == Type::JSONB {
            out.extend_from_slice(&[JSONB_VERSION]);
        }
        out.extend_from_slice(text.as_bytes());
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::JSONB | Type::JSON)
    }

    to_sql_checked!();
}

impl<'a, T: DeserializeOwned> FromSql<'a> for Json<T> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
        let text = if *ty == Type::JSONB {
            match raw.split_first() {
                Some((&JSONB_VERSION, text)) => text,
                _ => return Err("不认识的 JSONB 写法".into()),
            }
        } else {
            raw
        };
        Ok(Self(serde_json::from_slice(text)?))
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::JSONB | Type::JSON)
    }
}

fn strip_nul(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.retain(|ch| ch != '\0'),
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_nul),
        serde_json::Value::Object(fields) => {
            *fields = std::mem::take(fields)
                .into_iter()
                .map(|(mut key, mut value)| {
                    key.retain(|ch| ch != '\0');
                    strip_nul(&mut value);
                    (key, value)
                })
                .collect();
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// 按文本形式存的值：地址、地址段。
pub(super) struct Text<T>(pub T);

impl<T> Debug for Text<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Text(..)")
    }
}

impl<T: Display> ToSql for Text<T> {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        self.0.to_string().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <String as ToSql>::accepts(ty)
    }

    to_sql_checked!();
}

impl<'a, T: FromStr> FromSql<'a> for Text<T>
where
    T::Err: Error + Send + Sync + 'static,
{
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
        Ok(Self(<&str as FromSql>::from_sql(ty, raw)?.parse()?))
    }

    fn accepts(ty: &Type) -> bool {
        <&str as FromSql>::accepts(ty)
    }
}

/// 不能出现在日志里的文本：代理的密码。存进去的就是原文，只是打印出来（`Debug`）时不带内容：
/// 日志级别开到 debug 时，数据库的驱动会把每条语句的参数用 `Debug` 打出来。
pub(super) struct Secret<'a>(pub &'a str);

impl Debug for Secret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl ToSql for Secret<'_> {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        self.0.to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&str as ToSql>::accepts(ty)
    }

    to_sql_checked!();
}

/// PostgreSQL 的文本里放不了 NUL。合法的内容里没有它；可有的文本里带着节点报上来的话（更新失败的原因写进操作记录），
/// 那里面有一个 NUL 不该让整条记录记不下来：去掉它。
pub(super) fn without_nul(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\0') { text.replace('\0', "").into() } else { text.into() }
}

/// 存成 `BIGINT` 的无符号整数：编号、时间、版本号、计数。写的时候放不进、读的时候是负数或者超出 `T` 的范围，都是错。
#[derive(Debug, Clone, Copy)]
pub(super) struct Int<T>(pub T);

impl<T: Copy + Debug + TryInto<i64>> ToSql for Int<T>
where
    T::Error: Error + Send + Sync + 'static,
{
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        let value: i64 = self.0.try_into()?;
        value.to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::INT8
    }

    to_sql_checked!();
}

impl<'a, T: TryFrom<i64>> FromSql<'a> for Int<T>
where
    T::Error: Error + Send + Sync + 'static,
{
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
        Ok(Self(T::try_from(i64::from_sql(ty, raw)?)?))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::INT8
    }
}

/// 时间（Unix 秒）、版本号这类 `u64` 的列：[`Int<u64>`] 的简写。
#[derive(Debug, Clone, Copy)]
pub(super) struct Unsigned(pub u64);

impl ToSql for Unsigned {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        Int(self.0).to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::INT8
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for Unsigned {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
        Ok(Self(Int::<u64>::from_sql(ty, raw)?.0))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::INT8
    }
}

/// 借用 [`Int<u32>`] 存取的编号。
macro_rules! id_column {
    ($(#[$meta:meta])* $name:ident($inner:ty), |$value:ident| $raw:expr, |$read:ident| $make:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        pub(super) struct $name(pub $inner);

        impl ToSql for $name {
            fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
                let $value = self.0;
                let raw: u32 = $raw;
                Int(raw).to_sql(ty, out)
            }

            fn accepts(ty: &Type) -> bool {
                *ty == Type::INT8
            }

            to_sql_checked!();
        }

        impl<'a> FromSql<'a> for $name {
            fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
                let $read: u32 = Int::<u32>::from_sql(ty, raw)?.0;
                let made: Option<$inner> = $make;
                made.map(Self).ok_or_else(|| format!("{} 不是一个合法的编号", $read).into())
            }

            fn accepts(ty: &Type) -> bool {
                *ty == Type::INT8
            }
        }
    };
}

id_column!(SqlNode(NodeId), |node| node.get(), |raw| NodeId::new(raw));
id_column!(SqlNetwork(NetworkId), |network| network.0, |raw| Some(NetworkId(raw)));
id_column!(SqlGroup(GroupId), |group| group.0, |raw| Some(GroupId(raw)));
id_column!(
    /// 虚拟 IP 存成整数，这样唯一约束和排序都按数值来。
    SqlIp(Ipv4Addr),
    |ip| u32::from(ip),
    |raw| Some(Ipv4Addr::from(raw))
);

/// 存成 `BYTEA` 的定长字节：摘要、盐。长度不对是错。
#[derive(Debug, Clone, Copy)]
pub(super) struct Blob<const N: usize>(pub [u8; N]);

impl<const N: usize> ToSql for Blob<N> {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        self.0.as_slice().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::BYTEA
    }

    to_sql_checked!();
}

impl<'a, const N: usize> FromSql<'a> for Blob<N> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
        let bytes = <&[u8] as FromSql>::from_sql(ty, raw)?;
        Ok(Self(<[u8; N]>::try_from(bytes)?))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::BYTEA
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SqlKey(pub PublicKey);

impl ToSql for SqlKey {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Failure> {
        self.0.as_bytes().as_slice().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::BYTEA
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for SqlKey {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Failure> {
        Ok(Self(PublicKey::from_bytes(Blob::<{ PublicKey::LEN }>::from_sql(ty, raw)?.0)))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::BYTEA
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn nul_characters_are_dropped_from_json_before_it_is_stored() {
        let mut out = BytesMut::new();
        Json(json!({"na\0me": ["a\0b", {"deep": "\0"}], "n": 1})).to_sql(&Type::JSONB, &mut out).unwrap();
        assert_eq!(out[0], JSONB_VERSION);
        let stored: serde_json::Value = serde_json::from_slice(&out[1..]).unwrap();
        assert_eq!(stored, json!({"name": ["ab", {"deep": ""}], "n": 1}));
    }

    #[test]
    fn a_literal_backslash_u0000_in_the_text_is_kept() {
        let mut out = BytesMut::new();
        Json(json!("\\u0000")).to_sql(&Type::JSONB, &mut out).unwrap();
        assert_eq!(Json::<String>::from_sql(&Type::JSONB, &out).unwrap().0, "\\u0000");
    }

    #[test]
    fn a_secret_is_stored_as_it_is_and_printed_without_its_content() {
        let mut out = BytesMut::new();
        Secret("hunter2").to_sql(&Type::TEXT, &mut out).unwrap();
        assert_eq!(&out[..], b"hunter2");
        assert_eq!(format!("{:?}", Secret("hunter2")), "Secret(..)");
        // 驱动打日志时拿到的是 `&dyn ToSql`。
        let param: &(dyn ToSql + Sync) = &Secret("hunter2");
        assert!(!format!("{param:?} {:?}", [param]).contains("hunter2"));
    }

    #[test]
    fn nul_characters_are_dropped_from_text() {
        assert_eq!(without_nul("a\0b\0"), "ab");
        assert!(matches!(without_nul("plain"), std::borrow::Cow::Borrowed("plain")));
    }

    #[test]
    fn integers_out_of_range_are_refused_in_both_directions() {
        let mut out = BytesMut::new();
        assert!(Int(u64::MAX).to_sql(&Type::INT8, &mut out).is_err());
        out.clear();
        (-1_i64).to_sql(&Type::INT8, &mut out).unwrap();
        assert!(Int::<u32>::from_sql(&Type::INT8, &out).is_err());
        out.clear();
        0_i64.to_sql(&Type::INT8, &mut out).unwrap();
        assert!(SqlNode::from_sql(&Type::INT8, &out).is_err(), "节点编号从 1 起");
        assert_eq!(SqlNetwork::from_sql(&Type::INT8, &out).unwrap().0, NetworkId(0));
    }
}
