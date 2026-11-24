//! 认出 TLS 1.3 的握手，决定 ice3proxy 上的流什么时候可以不再加密第二次。
//!
//! 选了 passthrough，一个方向离开 lane 的 TLS 之后就是不再加密的原始字节，安全全靠用户自己的 TLS。所以不只看开头几个字节，
//! 而是把握手消息按 RFC 8446 的格式整个走一遍：每个长度都对得上、不越界，没有多余的字节。
//!
//! - 发起方（[`crate::Payload::for_first_data`]）：首批数据里的 ClientHello 要提供 TLS 1.3（§4.1.2）。
//! - 接受方（[`ServerHelloWatch`]）：目标回的 ServerHello 要选定 TLS 1.3 和一个加密的套件，而且不是 HelloRetryRequest（§4.1.3）。
//!   只有满足该条件，后续握手消息（证书等）才处于加密保护之下。若目标选用 TLS 1.2 或仅校验不加密的套件（RFC 9150），证书将以明文返回；
//!   回了 HelloRetryRequest 时，在 ServerHello 之前切换会让路上的人能冒充目标再要一次 ClientHello。

/// 明文的 TLS 记录最长 2^14 字节（RFC 8446 §5.1）。
const MAX_RECORD_LEN: usize = 1 << 14;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS12: [u8; 2] = [0x03, 0x03];
const TLS13: [u8; 2] = [0x03, 0x04];

/// `first` 以一条完整的 TLS 记录开头，记录里正好是一条格式正确、提供 TLS 1.3 的 ClientHello。记录后面还有什么不管。
pub(crate) fn offers_tls13(first: &[u8]) -> bool {
    supported_versions(first).is_some_and(|versions| versions.as_chunks::<2>().0.contains(&TLS13))
}

/// 第一条记录里的 ClientHello 的 supported_versions 扩展里列出的版本（每个 2 字节）。
/// 记录不完整、不是一条格式正确的 ClientHello，或者没有这个扩展时返回 `None`。
fn supported_versions(first: &[u8]) -> Option<&[u8]> {
    let mut record = Reader(first);
    // 记录头：握手；版本是 TLS 1.0～1.2（第一个 ClientHello 的记录可以写 1.0，RFC 8446 §5.1）。
    let [CONTENT_HANDSHAKE, 0x03, 0x01..=0x03] = record.array()? else { return None };
    let mut handshake = Reader(record.vec16()?);
    if handshake.0.len() > MAX_RECORD_LEN {
        return None;
    }
    // 记录中必须恰好包含一条 ClientHello 握手消息；跨多条记录分片的（超过 16 KB）不予识别，保持加密。
    let [HANDSHAKE_CLIENT_HELLO] = handshake.array()? else { return None };
    let mut hello = Reader(handshake.vec24()?);
    handshake.end()?;

    // legacy_version 在 TLS 1.3 里固定写 1.2。
    if hello.array()? != TLS12 {
        return None;
    }
    hello.take(32)?; // random
    let session_id = hello.vec8()?;
    let cipher_suites = hello.vec16()?;
    let compression_methods = hello.vec8()?;
    let mut extensions = Reader(hello.vec16()?);
    hello.end()?;
    // TLS 1.3 的 ClientHello 只能写 null 压缩这一个字节（§4.1.2）。
    if session_id.len() > 32 || cipher_suites.is_empty() || !cipher_suites.len().is_multiple_of(2) || compression_methods != [0] {
        return None;
    }

    let mut versions = None;
    while !extensions.0.is_empty() {
        let kind = u16::from_be_bytes(extensions.array()?);
        let data = extensions.vec16()?;
        // 同一种扩展出现两次的 ClientHello 不合法（RFC 8446 §4.2）。
        if kind == EXTENSION_SUPPORTED_VERSIONS && versions.replace(data).is_some() {
            return None;
        }
    }
    let mut data = Reader(versions?);
    let list = data.vec8()?;
    data.end()?;
    (!list.is_empty() && list.len().is_multiple_of(2)).then_some(list)
}

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const RECORD_HEADER_LEN: usize = 5;
/// HelloRetryRequest 是 random 等于这个值的 ServerHello：SHA-256("HelloRetryRequest")（RFC 8446 §4.1.3）。
const HELLO_RETRY_REQUEST: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
    0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// 接受方的方向什么时候可以不再加密（发起方的方向随后跟着它）：看目标回的头几条 TLS 记录。
///
/// 发起方选择 passthrough 仅表明首批数据为提供 TLS 1.3 的 ClientHello，目标响应尚未可知。因此接受方先保持加密，
/// 把目标发来的字节按顺序喂给 [`feed`](Self::feed)，直到看出结果：
///
/// - 第一条记录是一个选定 TLS 1.3 的 ServerHello：它之后的握手和数据都由用户自己的 TLS 加密了，这条记录一结束就可以不再加密；
/// - 第一条是 HelloRetryRequest：再等一次，它后面（可以隔着一个兼容中间设备的 ChangeCipherSpec）的 ServerHello 照上一条判断；
/// - 别的（TLS 1.2 及以前、第二个 HelloRetryRequest、格式不对、不是 TLS）：这个方向一直加密，发起方的方向也是。
///
/// 只缓冲正在看的那一条记录（最长 16 KB），看出结果之后什么都不留。
#[derive(Debug, Default)]
pub struct ServerHelloWatch {
    /// 正在看的那一条记录，从记录头开始。
    record: Vec<u8>,
    /// 已经见过一个 HelloRetryRequest。
    retried: bool,
    /// HelloRetryRequest 之后已经见过一个 ChangeCipherSpec。
    changed_cipher_spec: bool,
    /// 已经看出结果。
    decided: bool,
}

/// [`ServerHelloWatch::feed`] 看出了什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHelloVerdict {
    /// 尚未得出结论，需继续输入数据。
    Undecided,
    /// 本次输入数据中，前 `usize` 字节（TLS 1.3 ServerHello 结尾部分）仍需加密，其后字节可切换为透传。
    PassthroughAfter(usize),
    /// 这个方向一直加密。
    Sealed,
}

impl ServerHelloWatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂进目标发来的下一段字节。看出结果之后不用再喂；再喂的话一律是 [`ServerHelloVerdict::Sealed`]。
    pub fn feed(&mut self, bytes: &[u8]) -> ServerHelloVerdict {
        if self.decided {
            return ServerHelloVerdict::Sealed;
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            match self.fill(&mut rest) {
                Fill::Partial => return ServerHelloVerdict::Undecided,
                Fill::Invalid => return self.decide(ServerHelloVerdict::Sealed),
                Fill::Complete => {}
            }
            let record = std::mem::take(&mut self.record);
            match (record[0], server_hello(&record)) {
                (CONTENT_HANDSHAKE, Some(ServerHello::Tls13)) => {
                    return self.decide(ServerHelloVerdict::PassthroughAfter(bytes.len() - rest.len()));
                }
                (CONTENT_HANDSHAKE, Some(ServerHello::RetryRequest)) if !self.retried => self.retried = true,
                // 中间设备兼容模式的 ChangeCipherSpec 只有一个字节 1（RFC 8446 附录 D.4）。
                (CONTENT_CHANGE_CIPHER_SPEC, _) if self.retried && !self.changed_cipher_spec && record[RECORD_HEADER_LEN..] == [1] => {
                    self.changed_cipher_spec = true;
                }
                _ => return self.decide(ServerHelloVerdict::Sealed),
            }
        }
        ServerHelloVerdict::Undecided
    }

    /// 从 `rest` 里取字节填进正在看的记录，直到这条记录完整，或者 `rest` 用完。
    fn fill(&mut self, rest: &mut &[u8]) -> Fill {
        if self.record.len() < RECORD_HEADER_LEN {
            let take = (RECORD_HEADER_LEN - self.record.len()).min(rest.len());
            self.record.extend_from_slice(&rest[..take]);
            *rest = &rest[take..];
            if self.record.len() < RECORD_HEADER_LEN {
                return Fill::Partial;
            }
        }
        // TLS 1.3 里除了第一个 ClientHello，记录头的版本都写 1.2。
        let &[kind @ (CONTENT_HANDSHAKE | CONTENT_CHANGE_CIPHER_SPEC), 0x03, 0x03, high, low] = &self.record[..RECORD_HEADER_LEN] else {
            return Fill::Invalid;
        };
        let len = usize::from(u16::from_be_bytes([high, low]));
        if len == 0 || len > MAX_RECORD_LEN || (kind == CONTENT_CHANGE_CIPHER_SPEC && len != 1) {
            return Fill::Invalid;
        }
        let take = (RECORD_HEADER_LEN + len - self.record.len()).min(rest.len());
        self.record.extend_from_slice(&rest[..take]);
        *rest = &rest[take..];
        if self.record.len() == RECORD_HEADER_LEN + len { Fill::Complete } else { Fill::Partial }
    }

    fn decide(&mut self, verdict: ServerHelloVerdict) -> ServerHelloVerdict {
        self.decided = true;
        self.record = Vec::new();
        verdict
    }
}

/// [`ServerHelloWatch::fill`] 之后正在看的那条记录怎么样了。
enum Fill {
    /// 还没到齐（喂进来的字节已经用完）。
    Partial,
    Complete,
    /// 记录头不是 TLS 1.3 的握手或者 ChangeCipherSpec。
    Invalid,
}

/// 一条 ServerHello 选了什么。
#[derive(Debug, PartialEq, Eq)]
enum ServerHello {
    Tls13,
    RetryRequest,
}

/// 一条完整的记录（含记录头）里正好是一条选定 TLS 1.3 和加密套件的 ServerHello 时，看它是不是 HelloRetryRequest。别的都是 `None`。
fn server_hello(record: &[u8]) -> Option<ServerHello> {
    let mut record = Reader(record);
    let [CONTENT_HANDSHAKE, 0x03, 0x03] = record.array()? else { return None };
    let mut handshake = Reader(record.vec16()?);
    record.end()?;
    // ServerHello 之后就换密钥，它一定在记录的末尾结束（RFC 8446 §5.1），记录里没有别的握手消息。
    let [HANDSHAKE_SERVER_HELLO] = handshake.array()? else { return None };
    let mut hello = Reader(handshake.vec24()?);
    handshake.end()?;

    if hello.array()? != TLS12 {
        return None;
    }
    let random: [u8; 32] = hello.array()?;
    let session_id = hello.vec8()?;
    // cipher_suite：只认 TLS 1.3 里加密的套件（RFC 8446 §B.4，AES-GCM、ChaCha20-Poly1305、AES-CCM）。只校验不加密的
    // （RFC 9150 的 TLS_SHA256_SHA256、TLS_SHA384_SHA384）选用后证书仍为明文；未知套件一律按不加密处理，保持加密传输。
    let [0x13, 0x01..=0x05] = hello.array()? else { return None };
    let [0] = hello.array()? else { return None }; // legacy_compression_method
    let mut extensions = Reader(hello.vec16()?);
    hello.end()?;
    if session_id.len() > 32 {
        return None;
    }

    let mut selected = None;
    while !extensions.0.is_empty() {
        let kind = u16::from_be_bytes(extensions.array()?);
        let data = extensions.vec16()?;
        if kind == EXTENSION_SUPPORTED_VERSIONS && selected.replace(data).is_some() {
            return None;
        }
    }
    // ServerHello 的 supported_versions 里只有选定的那一个版本。没有这个扩展的是 TLS 1.2 及以前。
    if selected? != TLS13 {
        return None;
    }
    Some(if random == HELLO_RETRY_REQUEST { ServerHello::RetryRequest } else { ServerHello::Tls13 })
}

/// 按 TLS 的格式从前往后读：定长的字段，和前面带着 1、2、3 字节长度的变长字段。越界时返回 `None`。
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(taken)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let [len] = self.array()?;
        self.take(usize::from(len))
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = u16::from_be_bytes(self.array()?);
        self.take(usize::from(len))
    }

    fn vec24(&mut self) -> Option<&'a [u8]> {
        let [high, middle, low] = self.array()?;
        self.take(usize::from(high) << 16 | usize::from(middle) << 8 | usize::from(low))
    }

    /// 已经读到头了，没有多余的字节。
    fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一条 ClientHello 的各个部分，测试里改其中一处再拼起来。
    struct Hello {
        record_version: [u8; 2],
        legacy_version: [u8; 2],
        session_id: Vec<u8>,
        cipher_suites: Vec<u8>,
        compression_methods: Vec<u8>,
        extensions: Vec<u8>,
    }

    impl Hello {
        /// 一个只提供 TLS 1.3 的 ClientHello，扩展里除了 supported_versions 还有 SNI 和 key_share，像真的客户端一样。
        fn tls13() -> Self {
            let mut extensions = Vec::new();
            extensions.extend(extension(
                0x0000,
                &[0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm'],
            ));
            extensions.extend(extension(EXTENSION_SUPPORTED_VERSIONS, &supported(&[[0x7a, 0x7a], TLS13, TLS12])));
            extensions.extend(extension(0x0033, &[&[0x00, 0x24, 0x00, 0x1d, 0x00, 0x20][..], &[7; 32]].concat()));
            Self {
                record_version: [0x03, 0x01],
                legacy_version: TLS12,
                session_id: vec![9; 32],
                cipher_suites: vec![0x13, 0x01, 0x13, 0x02, 0x13, 0x03],
                compression_methods: vec![0x00],
                extensions,
            }
        }

        fn with_extensions(mut self, extensions: Vec<u8>) -> Self {
            self.extensions = extensions;
            self
        }

        fn record(&self) -> Vec<u8> {
            let mut body = self.legacy_version.to_vec();
            body.extend_from_slice(&[0x42; 32]);
            body.extend(vec8(&self.session_id));
            body.extend(vec16(&self.cipher_suites));
            body.extend(vec8(&self.compression_methods));
            body.extend(vec16(&self.extensions));
            let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
            handshake.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
            handshake.extend(body);
            let mut record = vec![CONTENT_HANDSHAKE, self.record_version[0], self.record_version[1]];
            record.extend(vec16(&handshake));
            record
        }
    }

    fn vec8(data: &[u8]) -> Vec<u8> {
        [&[u8::try_from(data.len()).unwrap()][..], data].concat()
    }

    fn vec16(data: &[u8]) -> Vec<u8> {
        [&u16::try_from(data.len()).unwrap().to_be_bytes()[..], data].concat()
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        [&kind.to_be_bytes()[..], &vec16(data)].concat()
    }

    fn supported(versions: &[[u8; 2]]) -> Vec<u8> {
        vec8(&versions.concat())
    }

    #[test]
    fn a_well_formed_client_hello_that_offers_tls13_is_recognised() {
        let hello = Hello::tls13().record();
        assert!(offers_tls13(&hello));
        assert!(offers_tls13(&[&hello[..], b"early data behind the record"].concat()), "记录后面的字节不管");
        let mut record_says_tls12 = Hello::tls13();
        record_says_tls12.record_version = TLS12;
        assert!(offers_tls13(&record_says_tls12.record()));
        let mut no_session_id = Hello::tls13();
        no_session_id.session_id.clear();
        assert!(offers_tls13(&no_session_id.record()));
    }

    #[test]
    fn a_client_hello_without_tls13_is_not() {
        let tls12_only = Hello::tls13().with_extensions(extension(EXTENSION_SUPPORTED_VERSIONS, &supported(&[TLS12])));
        assert!(!offers_tls13(&tls12_only.record()));
        let no_supported_versions = Hello::tls13().with_extensions(extension(0x0000, &[0; 4]));
        assert!(!offers_tls13(&no_supported_versions.record()), "没有 supported_versions 的是 TLS 1.2 及以前");
        assert!(!offers_tls13(&Hello::tls13().with_extensions(Vec::new()).record()));
    }

    #[test]
    fn a_forged_or_truncated_prefix_is_not() {
        // 只有前几个字节像 ClientHello（issue #17）。
        assert!(!offers_tls13(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]));
        assert!(!offers_tls13(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x03, 0x04]));
        assert!(!offers_tls13(b""));
        assert!(!offers_tls13(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"));
        let hello = Hello::tls13().record();
        for len in 0..hello.len() {
            assert!(!offers_tls13(&hello[..len]), "只到第 {len} 字节");
        }
    }

    #[test]
    fn every_length_has_to_add_up() {
        let hello = Hello::tls13().record();
        // 记录长度、握手消息长度各多一或少一，后面再垫一个字节让整条记录"在"。
        for (at, width) in [(3, 2), (6, 3)] {
            for delta in [-1_i32, 1] {
                let mut bad = hello.clone();
                bad.push(0);
                let field = &mut bad[at..at + width];
                let mut value = field.iter().fold(0_i32, |value, &byte| value << 8 | i32::from(byte));
                value += delta;
                for (i, byte) in field.iter_mut().rev().enumerate() {
                    *byte = u8::try_from((value >> (8 * i)) & 0xff).unwrap();
                }
                assert!(!offers_tls13(&bad), "第 {at} 字节起的长度改了 {delta}");
            }
        }
    }

    #[test]
    fn malformed_fields_are_rejected() {
        let mut legacy = Hello::tls13();
        legacy.legacy_version = [0x03, 0x01];
        assert!(!offers_tls13(&legacy.record()), "TLS 1.3 的 legacy_version 是 1.2");
        let mut ssl3 = Hello::tls13();
        ssl3.record_version = [0x03, 0x00];
        assert!(!offers_tls13(&ssl3.record()));
        let mut long_session = Hello::tls13();
        long_session.session_id = vec![0; 33];
        assert!(!offers_tls13(&long_session.record()));
        let mut odd_suites = Hello::tls13();
        odd_suites.cipher_suites = vec![0x13, 0x01, 0x13];
        assert!(!offers_tls13(&odd_suites.record()));
        let mut no_suites = Hello::tls13();
        no_suites.cipher_suites.clear();
        assert!(!offers_tls13(&no_suites.record()));
        for methods in [&[][..], &[0x01], &[0x00, 0x01], &[0x01, 0x00]] {
            let mut compression = Hello::tls13();
            compression.compression_methods = methods.to_vec();
            assert!(!offers_tls13(&compression.record()), "TLS 1.3 的压缩方法只能是 [0]，不能是 {methods:?}");
        }

        let twice =
            [extension(EXTENSION_SUPPORTED_VERSIONS, &supported(&[TLS13])), extension(EXTENSION_SUPPORTED_VERSIONS, &supported(&[TLS13]))];
        assert!(!offers_tls13(&Hello::tls13().with_extensions(twice.concat()).record()), "同一种扩展两次");
        let odd_list = extension(EXTENSION_SUPPORTED_VERSIONS, &[0x03, 0x03, 0x04, 0x03]);
        assert!(!offers_tls13(&Hello::tls13().with_extensions(odd_list).record()));
        let list_shorter_than_extension = extension(EXTENSION_SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04, 0x00]);
        assert!(!offers_tls13(&Hello::tls13().with_extensions(list_shorter_than_extension).record()));
        let cut_extension = [&EXTENSION_SUPPORTED_VERSIONS.to_be_bytes()[..], &[0x00, 0x03, 0x02, 0x03]].concat();
        assert!(!offers_tls13(&Hello::tls13().with_extensions(cut_extension).record()), "扩展的长度超出了扩展列表");
    }

    #[test]
    fn a_server_hello_or_another_record_type_is_not() {
        let mut server_hello = Hello::tls13().record();
        server_hello[5] = 0x02;
        assert!(!offers_tls13(&server_hello));
        let mut application_data = Hello::tls13().record();
        application_data[0] = 0x17;
        assert!(!offers_tls13(&application_data));
    }

    /// 一条 ServerHello 记录。`random` 是 [`HELLO_RETRY_REQUEST`] 时就是 HelloRetryRequest。
    fn server_hello_with(random: [u8; 32], extensions: &[u8]) -> Vec<u8> {
        let mut body = TLS12.to_vec();
        body.extend_from_slice(&random);
        body.extend(vec8(&[5; 32]));
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        body.extend(vec16(extensions));
        let mut handshake = vec![HANDSHAKE_SERVER_HELLO];
        handshake.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        handshake.extend(body);
        [&[CONTENT_HANDSHAKE, 0x03, 0x03][..], &vec16(&handshake)].concat()
    }

    /// 选定 TLS 1.3 的 ServerHello，像真的服务器一样还带着 key_share。
    fn server_hello_13() -> Vec<u8> {
        let extensions =
            [extension(EXTENSION_SUPPORTED_VERSIONS, &TLS13), extension(0x0033, &[&[0x00, 0x1d, 0x00, 0x20][..], &[3; 32]].concat())];
        server_hello_with([0x11; 32], &extensions.concat())
    }

    fn hello_retry_request() -> Vec<u8> {
        let extensions = [extension(EXTENSION_SUPPORTED_VERSIONS, &TLS13), extension(0x0033, &[0x00, 0x17])];
        server_hello_with(HELLO_RETRY_REQUEST, &extensions.concat())
    }

    const CHANGE_CIPHER_SPEC: [u8; 6] = [CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    /// ServerHello 之后的第一条加密记录（EncryptedExtensions 等，记录类型写作应用数据）。
    const ENCRYPTED: [u8; 9] = [0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];

    /// 一次喂一整段，返回结果。
    fn verdict(bytes: &[u8]) -> ServerHelloVerdict {
        ServerHelloWatch::new().feed(bytes)
    }

    #[test]
    fn passthrough_starts_right_after_a_tls13_server_hello() {
        let hello = server_hello_13();
        assert_eq!(verdict(&hello), ServerHelloVerdict::PassthroughAfter(hello.len()));
        // 后面紧跟着 ChangeCipherSpec 和加密的记录：它们不用再加密。
        let flight = [&hello[..], &CHANGE_CIPHER_SPEC, &ENCRYPTED].concat();
        assert_eq!(verdict(&flight), ServerHelloVerdict::PassthroughAfter(hello.len()));
    }

    #[test]
    fn the_server_hello_can_arrive_in_any_pieces() {
        let flight = [&server_hello_13()[..], &ENCRYPTED].concat();
        let end = server_hello_13().len();
        for piece in [1, 2, 4, 5, 7, 50, 100] {
            let mut watch = ServerHelloWatch::new();
            let mut fed = 0;
            let found = flight.chunks(piece).find_map(|chunk| {
                let verdict = watch.feed(chunk);
                fed += chunk.len();
                match verdict {
                    ServerHelloVerdict::Undecided => None,
                    ServerHelloVerdict::PassthroughAfter(at) => Some(fed - chunk.len() + at),
                    ServerHelloVerdict::Sealed => panic!("每段 {piece} 字节时判成了一直加密"),
                }
            });
            assert_eq!(found, Some(end), "每段 {piece} 字节");
        }
    }

    #[test]
    fn after_a_hello_retry_request_the_next_server_hello_decides() {
        let retry = hello_retry_request();
        assert_eq!(verdict(&retry), ServerHelloVerdict::Undecided, "HelloRetryRequest 之后客户端要再发一次 ClientHello，这时不能切换");
        let mut watch = ServerHelloWatch::new();
        assert_eq!(watch.feed(&[&retry[..], &CHANGE_CIPHER_SPEC].concat()), ServerHelloVerdict::Undecided);
        let hello = server_hello_13();
        assert_eq!(watch.feed(&[&hello[..], &ENCRYPTED].concat()), ServerHelloVerdict::PassthroughAfter(hello.len()));

        // 不隔 ChangeCipherSpec 也行。
        let flight = [&retry[..], &hello[..]].concat();
        assert_eq!(verdict(&flight), ServerHelloVerdict::PassthroughAfter(flight.len()));
        // 第二个 HelloRetryRequest 不合 TLS 1.3：一直加密。
        assert_eq!(verdict(&[&retry[..], &retry[..]].concat()), ServerHelloVerdict::Sealed);
        // HelloRetryRequest 之后不是 ServerHello：一直加密。
        assert_eq!(verdict(&[&retry[..], &CHANGE_CIPHER_SPEC, &ENCRYPTED].concat()), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&[&retry[..], &CHANGE_CIPHER_SPEC, &CHANGE_CIPHER_SPEC].concat()), ServerHelloVerdict::Sealed);
    }

    #[test]
    fn tls12_and_anything_that_is_not_a_tls13_server_hello_stays_sealed() {
        // TLS 1.2 的 ServerHello：没有 supported_versions，或者里面写的是 1.2。证书接着就明文回来。
        assert_eq!(verdict(&server_hello_with([0x11; 32], &[])), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&server_hello_with([0x11; 32], &extension(EXTENSION_SUPPORTED_VERSIONS, &TLS12))), ServerHelloVerdict::Sealed);
        // 不是 TLS。
        assert_eq!(verdict(b"HTTP/1.1 200 OK\r\n"), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(b"SSH-2.0-OpenSSH_9.6\r\n"), ServerHelloVerdict::Sealed);
        // ChangeCipherSpec、加密记录、警报打头，或者别的握手消息。
        assert_eq!(verdict(&CHANGE_CIPHER_SPEC), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&ENCRYPTED), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&Hello::tls13().record()), ServerHelloVerdict::Sealed, "ClientHello（比如回显）不算");
        // 记录头的版本不是 1.2，或者长度不合理。
        let mut old_record = server_hello_13();
        old_record[2] = 0x01;
        assert_eq!(verdict(&old_record), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&[0x16, 0x03, 0x03, 0x00, 0x00]), ServerHelloVerdict::Sealed);
        assert_eq!(verdict(&[0x16, 0x03, 0x03, 0x40, 0x01]), ServerHelloVerdict::Sealed);
    }

    #[test]
    fn a_malformed_server_hello_stays_sealed() {
        let hello = server_hello_13();
        // 握手消息的长度和记录对不上：多一个字节或者少一个字节。
        for delta in [-1_i32, 1] {
            let mut bad = hello.clone();
            let len = i32::from(bad[8]) + delta;
            bad[8] = u8::try_from(len).unwrap();
            assert_eq!(verdict(&bad), ServerHelloVerdict::Sealed, "握手消息长度改了 {delta}");
        }
        // 记录里在 ServerHello 后面还有别的握手消息。
        let mut two = hello.clone();
        let record_len = u16::from_be_bytes([two[3], two[4]]) + 4;
        two[3..5].copy_from_slice(&record_len.to_be_bytes());
        two.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
        assert_eq!(verdict(&two), ServerHelloVerdict::Sealed);
        let twice = [extension(EXTENSION_SUPPORTED_VERSIONS, &TLS13), extension(EXTENSION_SUPPORTED_VERSIONS, &TLS13)].concat();
        assert_eq!(verdict(&server_hello_with([0x11; 32], &twice)), ServerHelloVerdict::Sealed, "同一种扩展两次");
        let mut compressed = hello.clone();
        let at = 5 + 4 + 2 + 32 + 1 + 32 + 2;
        compressed[at] = 1;
        assert_eq!(verdict(&compressed), ServerHelloVerdict::Sealed, "TLS 1.3 不压缩");
    }

    #[test]
    fn only_a_server_hello_that_picks_an_encrypting_suite_lets_passthrough_start() {
        /// 把 `hello` 里选定的套件换成 `suite`。
        fn with_suite(mut hello: Vec<u8>, suite: [u8; 2]) -> Vec<u8> {
            let at = 5 + 4 + 2 + 32 + 1 + 32;
            hello[at..at + 2].copy_from_slice(&suite);
            hello
        }
        for suite in [[0x13, 0x01], [0x13, 0x02], [0x13, 0x03], [0x13, 0x04], [0x13, 0x05]] {
            let hello = with_suite(server_hello_13(), suite);
            assert_eq!(verdict(&hello), ServerHelloVerdict::PassthroughAfter(hello.len()), "套件 {suite:02x?}");
        }
        // RFC 9150 只校验不加密（证书会明文回来），和不认识的套件（这里是 RFC 8998 的 SM4 和一个没分配的值）：一直加密。
        for suite in [[0xc0, 0xb4], [0xc0, 0xb5], [0x00, 0xc6], [0x13, 0x06]] {
            assert_eq!(verdict(&with_suite(server_hello_13(), suite)), ServerHelloVerdict::Sealed, "套件 {suite:02x?}");
            let retry = with_suite(hello_retry_request(), suite);
            assert_eq!(verdict(&retry), ServerHelloVerdict::Sealed, "HelloRetryRequest 选了套件 {suite:02x?}");
        }
    }

    #[test]
    fn nothing_is_decided_before_the_record_is_complete_and_nothing_after() {
        let hello = server_hello_13();
        let mut watch = ServerHelloWatch::new();
        assert_eq!(watch.feed(&hello[..hello.len() - 1]), ServerHelloVerdict::Undecided);
        assert_eq!(watch.feed(&hello[hello.len() - 1..]), ServerHelloVerdict::PassthroughAfter(1));
        assert_eq!(watch.feed(&ENCRYPTED), ServerHelloVerdict::Sealed, "看出结果之后不用再喂");
        assert_eq!(ServerHelloWatch::new().feed(&[]), ServerHelloVerdict::Undecided);
    }
}
