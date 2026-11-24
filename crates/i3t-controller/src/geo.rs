//! 节点公网地址所在的国家或地区：查程序自带的离线地址库，不联网。
//!
//! 地址库是 DB-IP 的 IP to Country Lite（<https://db-ip.com>，CC BY 4.0，使用时要注明来源），
//! 压缩着放在 `data/` 里随程序发布；第一次查的时候解压，之后常驻内存（约 8.5 MB）。
//! 库每月更新一次，换掉那个文件就是更新。

use std::io::Read;
use std::net::IpAddr;
use std::sync::LazyLock;

use flate2::read::GzDecoder;
use maxminddb::{PathElement, Reader};

const DATABASE: &[u8] = include_bytes!("../data/dbip-country-lite.mmdb.gz");

/// 记录里国家代码所在的位置：`country.iso_code`。
const ISO_CODE: [PathElement<'static>; 2] = [PathElement::Key("country"), PathElement::Key("iso_code")];

static READER: LazyLock<Option<Reader<Vec<u8>>>> = LazyLock::new(|| match open() {
    Ok(reader) => Some(reader),
    Err(reason) => {
        // 仅当随程序编译内嵌的数据文件损坏时才会走到此处；节点仍正常工作，只是不显示所在国家或地区。
        tracing::warn!(%reason, "无法加载离线地址库，节点将不显示所在国家或地区");
        None
    }
});

fn open() -> Result<Reader<Vec<u8>>, String> {
    let mut bytes = Vec::new();
    GzDecoder::new(DATABASE).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    Reader::from_source(bytes).map_err(|error| error.to_string())
}

/// 地址所在的国家或地区，ISO 3166-1 的两个大写字母（`"JP"`）。
/// 内网、回环这类地址和库里没有的地址是 `None`；库里给的不是两个大写字母（例如保留地址的 `ZZ`）也是 `None`。
pub(crate) fn country(ip: IpAddr) -> Option<String> {
    let reader = READER.as_ref()?;
    // 以 IPv4 映射的 IPv6 地址（`::ffff:1.2.3.4`）按 IPv4 查。
    let found = reader.lookup(ip.to_canonical()).ok()?;
    let code: &str = found.decode_path(&ISO_CODE).ok()??;
    let valid = code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_uppercase()) && code != "ZZ";
    valid.then(|| code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::country;

    #[test]
    fn public_addresses_have_a_country() {
        // 几个公共 DNS 解析服务器的地址：归属多年不变，换了新的地址库也还是这几个国家。
        assert_eq!(country("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        assert_eq!(country("103.2.57.5".parse().unwrap()).as_deref(), Some("JP"));
        assert_eq!(country("114.114.114.114".parse().unwrap()).as_deref(), Some("CN"));
        // 以 IPv4 映射的 IPv6 地址和原来的 IPv4 地址一样。
        assert_eq!(country("::ffff:103.2.57.5".parse().unwrap()).as_deref(), Some("JP"));
    }

    #[test]
    fn private_and_special_addresses_have_none() {
        for address in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "100.64.0.1", "::1", "fd00::1", "0.0.0.0"] {
            assert_eq!(country(address.parse().unwrap()), None, "{address} 不应该有国家");
        }
    }
}
