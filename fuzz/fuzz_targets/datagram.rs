//! 节点端口上收到的一个 UDP 数据报（也是 TCP 中转里的一帧）：[`Datagram::parse`] 一次分出的全部帧，
//! relay 转发之前只看头的两个函数，骨干矩阵的行，以及局域网信标。
//!
//! 除了不能 panic，还查这几条：
//!
//! - 中转帧被 relay 原样转出去，所以解析出来的头重新编码、接上包，必须正好是原来的数据报；
//!   `forwarding_header_len` 和 `relayed_dst` 必须和完整的解析说的一样。
//! - 解析得出来的帧，编码之后再解析，得到的是同一帧。
//! - 封好的网络包：分类和 [`SealedHeader::parse`] 说的一样，头重新编码之后是原来的开头，relay 不把它当成要转发的帧。

#![no_main]

use i3t_proto::backbone::Row;
use i3t_proto::beacon::Beacon;
use i3t_proto::datagram::{self, Datagram, RelayHeader};
use i3t_proto::sealed::SealedHeader;
use i3t_proto::{addr, probe, session};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = Datagram::parse(data);
    assert_eq!(matches!(parsed, Ok(Datagram::Sealed(_))), SealedHeader::parse(data).is_some(), "是不是封好的网络包，两处说的不一样");
    match parsed {
        Ok(Datagram::Conn(packet)) => assert_eq!(packet, data, "连接包就是整个数据报"),
        Ok(Datagram::Sealed(packet)) => {
            assert_eq!(packet, data, "封好的网络包就是整个数据报");
            let header = SealedHeader::parse(data).expect("上面核对过：分类成封好的网络包的一定取得出头");
            assert_eq!(header.to_bytes(), data[..SealedHeader::LEN], "头重新编码之后对不上原来的开头");
            assert!(data.len() > SealedHeader::OVERHEAD, "头和校验之外至少还有一个字节");
            assert_eq!(datagram::forwarding_header_len(data), None, "它不是要 relay 转发的帧");
            assert_eq!(datagram::relayed_dst(data), None);
        }
        Ok(Datagram::Relayed { header, packet }) => {
            assert_eq!([&header.to_bytes()[..], packet].concat(), data, "一级中转的头重新编码之后对不上原来的数据报");
            assert_eq!(datagram::forwarding_header_len(data), Some(RelayHeader::LEN));
            assert_eq!(datagram::relayed_dst(data), Some(header.dst));
        }
        Ok(Datagram::Routed { header, packet }) => {
            assert_eq!([header.to_bytes().as_slice(), packet].concat(), data, "多级中转的头重新编码之后对不上原来的数据报");
            assert_eq!(datagram::forwarding_header_len(data), Some(header.encoded_len()));
            assert_eq!(datagram::relayed_dst(data), None, "多级中转的帧不是一级中转的帧");
        }
        Ok(Datagram::Row(frame)) => check_row(frame),
        Ok(Datagram::Session(frame)) => {
            assert_eq!(session::Frame::parse(&session_bytes(frame)), Some(frame), "中转会话帧编码之后读不回来");
            if let session::Frame::Error(_) = frame {
                assert!(session::Refused::echo(data).is_some(), "解析得出来的 ERROR 一定有回显");
            }
        }
        Ok(Datagram::Probe(frame)) => {
            assert_eq!(probe::Frame::parse(&probe_bytes(&frame)), Some(frame), "探测帧编码之后读不回来");
        }
        Ok(Datagram::AddrQuery(query)) => assert_eq!(addr::Query::parse(&query.to_bytes()), Some(query)),
        Ok(Datagram::AddrReply(reply)) => assert_eq!(addr::Reply::parse(&reply.to_bytes()), Some(reply)),
        Err(_) => {}
    }
    // 下面这几个 relay 和路径层会对任意数据报直接调用，不经过上面的分类。
    let _ = session::Refused::echo(data);
    let _ = Row::peek(data);
    if let Some(beacon) = Beacon::parse(data) {
        assert_eq!(Beacon::parse(&beacon.to_bytes()), Some(beacon), "信标编码之后读不回来");
    }
});

/// 长度对得上的行帧：内容不一定合格，合格的话编码之后再解析是同一行。
fn check_row(frame: &[u8]) {
    let signed = Row::signed_part(frame).expect("分类成行帧的数据报一定切得出签名的部分");
    assert!(signed.len() < frame.len());
    let Some((row, signature)) = Row::parse(frame) else { return };
    assert_eq!(Row::peek(frame), Some((row.origin, row.seq)));
    let again = row.to_bytes(&signature);
    assert_eq!(Row::parse(&again), Some((row, signature)), "行编码之后读不回同样的内容");
}

fn session_bytes(frame: session::Frame) -> Vec<u8> {
    match frame {
        session::Frame::Init(init) => init.to_bytes().to_vec(),
        session::Frame::Challenge(challenge) => challenge.to_bytes().to_vec(),
        session::Frame::Auth(auth) => auth.to_bytes().to_vec(),
        session::Frame::Ok(accepted) => accepted.to_bytes(),
        session::Frame::Ping(ping) => ping.to_bytes().to_vec(),
        session::Frame::Pong(pong) => pong.to_bytes(),
        // ERROR 的回显不在解析出来的值里，编码时补的是 0：只比较解析出来的部分。
        session::Frame::Error(refused) => refused.to_bytes().to_vec(),
    }
}

fn probe_bytes(frame: &probe::Frame) -> Vec<u8> {
    match frame {
        probe::Frame::Ping(ping) => ping.to_bytes().to_vec(),
        probe::Frame::Pong(pong) => pong.to_bytes(),
        probe::Frame::TestPing(ping) => ping.to_bytes().to_vec(),
        probe::Frame::TestPong(pong) => pong.to_bytes(),
    }
}
