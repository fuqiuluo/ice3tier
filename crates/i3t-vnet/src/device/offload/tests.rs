//! 真的建一块开了分段卸载的网卡，和这台机器的内核对着收发。要权限，所以和 `device` 里那个真网卡的测试一样，只在设了
//! `I3T_VNET_DEVICE_TEST=1` 时做（`unshare -Urn` 里，或者 CI 上 sudo）。
//!
//! 对端是测试自己：从网卡上读内核发出的包，照 TCP 的规矩手写回答、写回网卡。

use std::net::Ipv4Addr;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::device::{Device, DeviceSpec, Offload, Platform, Tun};
use crate::ipv4::testing::{header_checksum, packet};
use crate::ipv4::{Ipv4, TCP, UDP};

const OWN: [u8; 4] = [10, 67, 0, 5];
const PEER: [u8; 4] = [10, 67, 0, 9];
const PEER_PORT: u16 = 7000;
const SOON: Duration = Duration::from_secs(5);

const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// 对端发给本机程序的：二十个一千字节的包。
const INBOUND: usize = 20 * 1000;
/// 本机程序发给对端的，够内核攒出好几个大块。
const OUTBOUND: usize = 300_000;

/// 认得出位置的内容：哪里错了一个字节、丢了一段、重了一段都对不上。
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| u8::try_from((index * 7 + index / 251) % 251).expect("余数小于 251")).collect()
}

/// TCP 或 UDP 的校验和：伪首部加整段。段里校验和的位置是零时得到该填的值；已经填好的话，对的时候得到零。
fn transport_checksum(protocol: u8, source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, protocol]);
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(segment);
    header_checksum(&bytes)
}

fn checksums_ok(ip: &Ipv4<'_>) -> bool {
    ip.header_checksum_ok() && transport_checksum(ip.protocol(), ip.source(), ip.destination(), ip.payload()) == 0
}

/// 对端发给本机的一个 UDP 包，校验和是对的（不对的、没填的，网卡不合）。
fn udp_from_peer(port: u16, data: &[u8]) -> Bytes {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&9u16.to_be_bytes());
    datagram.extend_from_slice(&port.to_be_bytes());
    datagram.extend_from_slice(&u16::try_from(8 + data.len()).unwrap().to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(data);
    let sum = transport_checksum(UDP, PEER.into(), OWN.into(), &datagram);
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    packet(UDP, PEER, OWN, &datagram).into()
}

/// 对端发给本机的一个 TCP 包要写的几样。
struct Segment<'a> {
    port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &'a [u8],
    data: &'a [u8],
}

impl Segment<'_> {
    fn packet(&self) -> Bytes {
        let mut segment = Vec::new();
        segment.extend_from_slice(&PEER_PORT.to_be_bytes());
        segment.extend_from_slice(&self.port.to_be_bytes());
        segment.extend_from_slice(&self.seq.to_be_bytes());
        segment.extend_from_slice(&self.ack.to_be_bytes());
        let words = u8::try_from((20 + self.options.len()) / 4).unwrap();
        // 窗口 65535，不谈窗口放大：内核一次最多发这么多，正好是一个大块。
        segment.extend_from_slice(&[words << 4, self.flags, 0xff, 0xff, 0, 0, 0, 0]);
        segment.extend_from_slice(self.options);
        segment.extend_from_slice(self.data);
        let sum = transport_checksum(TCP, PEER.into(), OWN.into(), &segment);
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
        packet(TCP, PEER, OWN, &segment).into()
    }
}

/// 本机发给对端的一个 TCP 包里测试要看的。
struct Heard<'a> {
    port: u16,
    seq: u32,
    flags: u8,
    data: &'a [u8],
}

/// `bytes` 是本机发给对端那个端口的 TCP 包的话，拆开；内核自己还会往网卡上发些别的（IPv6 的邻居发现之类），不是。
fn heard(bytes: &[u8]) -> Option<Heard<'_>> {
    let ip = Ipv4::parse(bytes).ok().filter(|ip| ip.protocol() == TCP && ip.destination() == Ipv4Addr::from(PEER))?;
    let tcp = ip.payload();
    if u16::from_be_bytes([tcp[2], tcp[3]]) != PEER_PORT {
        return None;
    }
    assert!(checksums_ok(&ip), "读出来的包校验和是算完的：{} 字节", bytes.len());
    Some(Heard {
        port: u16::from_be_bytes([tcp[0], tcp[1]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        flags: tcp[13],
        data: &tcp[usize::from(tcp[12] >> 4) * 4..],
    })
}

/// 等网卡上的下一个包。
async fn read(tun: &Tun, buf: &mut [u8]) -> usize {
    tokio::time::timeout(SOON, tun.recv(buf)).await.expect("等内核发到网卡上的包超时").unwrap()
}

/// 内核数的这块网卡上的包。合在一起的一大块算一个。
struct Counted {
    /// 程序写进去的。
    written: u64,
    /// 程序读出来的。
    read: u64,
}

impl Counted {
    fn on(device: &str) -> Self {
        let table = std::fs::read_to_string("/proc/net/dev").unwrap();
        let numbers =
            table.lines().find_map(|line| line.trim_start().strip_prefix(device)?.strip_prefix(':')).expect("网卡在 /proc/net/dev 里");
        let numbers: Vec<u64> = numbers.split_whitespace().map(|number| number.parse().unwrap()).collect();
        Self { written: numbers[1], read: numbers[9] }
    }
}

#[tokio::test]
async fn a_real_device_with_offload_gives_and_takes_plain_packets_while_the_kernel_sees_blocks() {
    if std::env::var_os("I3T_VNET_DEVICE_TEST").is_none() {
        return;
    }
    let spec = DeviceSpec::new(Platform::Linux, OWN.into(), "10.67.0.0/16".parse().unwrap(), None);
    let tun = Tun::create(&spec).unwrap();
    println!("网卡 {}，分段卸载 {}", tun.name(), tun.offload());
    assert_ne!(tun.offload(), Offload::Off, "这台机器的内核给分段卸载");
    let mut buf = vec![0; usize::from(u16::MAX)];

    // UDP，本机发出：内核只算了一半的校验和，读出来的是算完的。
    let socket = UdpSocket::bind((Ipv4Addr::from(OWN), 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    socket.send_to(&[7; 300], (Ipv4Addr::from(PEER), 9)).await.unwrap();
    loop {
        let len = read(&tun, &mut buf).await;
        if let Ok(ip) = Ipv4::parse(&buf[..len])
            && ip.protocol() == UDP
            && ip.destination() == Ipv4Addr::from(PEER)
        {
            assert!(checksums_ok(&ip), "UDP 的校验和是算完的");
            assert_eq!(ip.payload()[8..], [7; 300]);
            break;
        }
    }

    // UDP，写一个：前面补了全零的头，内核当它是一个普通的包。
    let mut got = [0; 2048];
    tun.send(&udp_from_peer(port, &[1; 200])).await.unwrap();
    let (len, from) = tokio::time::timeout(SOON, socket.recv_from(&mut got)).await.expect("内核没有把写进去的包交给程序").unwrap();
    assert_eq!((&got[..len], from.port()), (&[1; 200][..], 9));

    // UDP，一批十个一样长的：内核给 UDP 的大块时合成一个写，程序收到的还是十个。
    let batch: Vec<Bytes> = (2..12).map(|fill| udp_from_peer(port, &[fill; 200])).collect();
    let before = Counted::on(tun.name()).written;
    tun.send_many(&batch).await.unwrap();
    for fill in 2..12 {
        let (len, _) = tokio::time::timeout(SOON, socket.recv_from(&mut got)).await.expect("合起来写的 UDP 包没有到齐").unwrap();
        assert_eq!(&got[..len], &[fill; 200][..], "顺序和内容不变");
    }
    let writes = Counted::on(tun.name()).written - before;
    assert_eq!(writes, if tun.offload() == Offload::TcpUdp { 1 } else { 10 }, "写了几次");

    // TCP：本机的程序连对端，先收后发。
    let app = tokio::spawn(async {
        let mut stream = TcpStream::connect((Ipv4Addr::from(PEER), PEER_PORT)).await.unwrap();
        let mut inbound = vec![0; INBOUND];
        stream.read_exact(&mut inbound).await.unwrap();
        stream.write_all(&pattern(OUTBOUND)).await.unwrap();
        (stream, inbound)
    });
    let (port, mut acked) = loop {
        let len = read(&tun, &mut buf).await;
        if let Some(syn) = heard(&buf[..len]) {
            assert_eq!(syn.flags & (SYN | ACK), SYN, "第一个是握手的包");
            break (syn.port, syn.seq.wrapping_add(1));
        }
    };
    let mut seq = 1000;
    // 分段长度写网卡 MTU 允许的最大值；别的选项都不答应，内核的包里就没有时间戳。
    let mss = (spec.mtu - 40).to_be_bytes();
    tun.send(&Segment { port, seq, ack: acked, flags: SYN | ACK, options: &[2, 4, mss[0], mss[1]], data: &[] }.packet()).await.unwrap();
    seq += 1;

    // 对端来的二十个首尾相接的包：合成一个交给内核，程序读到的一个字节不差。
    let inbound = pattern(INBOUND);
    // PSH 只有最后一个带：带着它的包后面不能再接别的。
    let last = seq + u32::try_from(INBOUND - 1000).unwrap();
    let batch: Vec<Bytes> = inbound
        .chunks(1000)
        .zip((seq..).step_by(1000))
        .map(|(data, seq)| Segment { port, seq, ack: acked, flags: if seq == last { ACK | PSH } else { ACK }, options: &[], data }.packet())
        .collect();
    let before = Counted::on(tun.name()).written;
    tun.send_many(&batch).await.unwrap();
    assert_eq!(Counted::on(tun.name()).written - before, 1, "二十个包写了一次");
    seq += u32::try_from(INBOUND).unwrap();

    // 本机的程序发出的：内核一大块一大块地给，读出来的每个都不超过 MTU、校验和算完了、首尾相接。
    // 像真的对端那样攒一阵才确认一次，内核下一次就给得更多。
    let (before, mut outbound, mut segments) = (Counted::on(tun.name()).read, Vec::with_capacity(OUTBOUND), 0u64);
    while outbound.len() < OUTBOUND {
        let had = outbound.len();
        let mut next = Some(Ok(read(&tun, &mut buf).await));
        while let Some(len) = next.take() {
            let len = len.unwrap();
            if let Some(segment) = heard(&buf[..len]).filter(|segment| !segment.data.is_empty()) {
                assert!(len <= usize::from(spec.mtu), "读出来的包 {len} 字节，比 MTU 大");
                // 内核重发的（序号在前面）不要；跳过去的不该有。
                let expected = acked.wrapping_add(u32::try_from(outbound.len()).unwrap());
                assert!(expected.wrapping_sub(segment.seq) < 1 << 31, "序号跳过了一段：{} 之后是 {}", expected, segment.seq);
                if segment.seq == expected {
                    outbound.extend_from_slice(segment.data);
                    segments += 1;
                }
            }
            next = tun.try_recv(&mut buf);
        }
        if outbound.len() > had {
            let ack = acked.wrapping_add(u32::try_from(outbound.len()).unwrap());
            tun.send(&Segment { port, seq, ack, flags: ACK, options: &[], data: &[] }.packet()).await.unwrap();
        }
    }
    acked = acked.wrapping_add(u32::try_from(outbound.len()).unwrap());
    let reads = Counted::on(tun.name()).read - before;
    println!("{segments} 个包，内核给了 {reads} 次（含它自己的确认），确认到 {acked}");
    assert!(outbound == pattern(OUTBOUND), "本机发出的 {OUTBOUND} 字节切开之后一个字节不差");
    assert!(reads * 4 < segments, "内核是一大块一大块给的：{segments} 个包只读了 {reads} 次");

    let (stream, heard_by_app) = tokio::time::timeout(SOON, app).await.expect("本机的程序没有收发完").unwrap();
    assert!(heard_by_app == inbound, "合起来写的 {INBOUND} 字节程序读到的一个字节不差");
    drop(stream);
}
