//! 域名解析结果的小缓存。
//!
//! 出口上同一个域名会被反复连接（LLM 网关的请求几乎都去同一个地方），每条流都问一次解析器既慢又没有必要。
//! 系统的解析器不给 TTL，所以每条结果固定留 [`TTL`]。只缓存成功的结果。

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 一条结果留多久。
const TTL: Duration = Duration::from_secs(60);

/// 最多留多少个域名。
const CAPACITY: usize = 1024;

#[derive(Debug, Default)]
pub(crate) struct DnsCache {
    entries: HashMap<String, Entry>,
}

#[derive(Debug)]
struct Entry {
    addrs: Vec<IpAddr>,
    expires: Instant,
}

impl DnsCache {
    /// `name` 要先规范化（见 [`normalize`]）。过期的结果不返回。
    pub(crate) fn get(&self, name: &str, now: Instant) -> Option<Vec<IpAddr>> {
        self.entries.get(name).filter(|entry| entry.expires > now).map(|entry| entry.addrs.clone())
    }

    /// 写入一条解析结果。缓存已满时先清理过期条目；若仍满则整体清空重建：
    /// 该情况仅在一分钟内访问上千个不同域名时发生，此时缓存本身命中率有限。
    pub(crate) fn put(&mut self, name: String, addrs: Vec<IpAddr>, now: Instant) {
        if self.entries.len() >= CAPACITY && !self.entries.contains_key(&name) {
            self.entries.retain(|_, entry| entry.expires > now);
            if self.entries.len() >= CAPACITY {
                self.entries.clear();
            }
        }
        self.entries.insert(name, Entry { addrs, expires: now + TTL });
    }
}

/// 缓存用的名字：域名不分大小写，结尾的点可有可无。
pub(crate) fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(last: u8) -> Vec<IpAddr> {
        vec![IpAddr::from([203, 0, 113, last])]
    }

    #[test]
    fn results_are_served_until_they_expire() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        cache.put("example.com".into(), addrs(1), now);
        assert_eq!(cache.get("example.com", now), Some(addrs(1)));
        assert_eq!(cache.get("example.com", now + TTL - Duration::from_millis(1)), Some(addrs(1)));
        assert_eq!(cache.get("example.com", now + TTL), None);
        assert_eq!(cache.get("other.example", now), None);
    }

    #[test]
    fn a_newer_result_replaces_the_older_one() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        cache.put("example.com".into(), addrs(1), now);
        cache.put("example.com".into(), addrs(2), now + TTL);
        assert_eq!(cache.get("example.com", now + TTL), Some(addrs(2)));
    }

    #[test]
    fn the_cache_never_grows_beyond_its_capacity() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        for index in 0..CAPACITY {
            cache.put(format!("host-{index}.example"), addrs(1), now);
        }
        assert_eq!(cache.entries.len(), CAPACITY);

        // 都还没过期：整个清空，只留新来的。
        cache.put("one-more.example".into(), addrs(2), now);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.get("one-more.example", now), Some(addrs(2)));

        // 有过期的：只清过期的。
        for index in 1..CAPACITY {
            cache.put(format!("host-{index}.example"), addrs(1), now + TTL);
        }
        cache.put("after-expiry.example".into(), addrs(3), now + TTL);
        assert_eq!(cache.entries.len(), CAPACITY);
        assert_eq!(cache.get("one-more.example", now + TTL), None);
        assert_eq!(cache.get("host-1.example", now + TTL), Some(addrs(1)));
    }

    #[test]
    fn names_are_normalized_before_they_are_used_as_keys() {
        assert_eq!(normalize("Example.COM."), "example.com");
        assert_eq!(normalize("example.com"), "example.com");
    }
}
