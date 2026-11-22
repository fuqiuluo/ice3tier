//! 数据报上下文里的一帧（对端发来的数据报的头、分片头）、网络包帧（完整的、一片、合着好几个包的）、
//! 测量流结束时对端写回的摘要，以及发送一侧的分片。
//!
//! 除了不能 panic，还查：头重新编码接上后面的字节就是原来的帧，`Recipient::peek` 和完整的解析说的一样；
//! 用输入的后半段当内容切片，每一片都不超过要求的长度，按片序号拼回来就是原来的内容；
//! 解析得了的网络包帧，只看首字节也认得出来；合在一帧里的包读出来再装回去就是原来的帧。

#![no_main]

use i3t_proto::flow::{Bundled, Channel, DatagramHeader, Frames, MeasureSteady, MeasureSummary, PacketHeader, Recipient};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match DatagramHeader::decode(data) {
        Ok((header, rest)) => {
            let mut encoded = Vec::new();
            header.encode(&mut encoded);
            encoded.extend_from_slice(rest);
            assert_eq!(encoded, data, "数据报的头重新编码之后对不上原来的帧");
            assert_eq!(Recipient::peek(data), Some(header.recipient), "只看首字节的判断和完整的解析不一样");
        }
        Err(_) => {
            let _ = Recipient::peek(data);
        }
    }

    if let Some(summary) = data.first_chunk::<{ MeasureSummary::LEN }>().and_then(MeasureSummary::from_bytes) {
        let mut encoded = Vec::new();
        summary.encode(&mut encoded);
        assert_eq!(encoded, data[..MeasureSummary::LEN], "测量的摘要重新编码之后对不上");
    }
    if let Some(steady) = data.first_chunk::<{ MeasureSteady::LEN }>() {
        assert_eq!(MeasureSteady::from_bytes(steady).to_bytes(), *steady);
    }

    packet_frame(data);
    split_and_join(data);
});

/// 网络包帧：对端发来的，内容不可信。
fn packet_frame(data: &[u8]) {
    // 反过来不成立：只看首字节时像网络包的帧，完整解析可能发现它被截短了，或者几个标志凑在一起说不通。
    let Ok((header, rest)) = PacketHeader::decode(data) else { return };
    assert_eq!(Channel::peek(data), Some(Channel::Packet), "只看首字节的判断和完整的解析不一样");
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    if header != PacketHeader::Bundle {
        encoded.extend_from_slice(rest);
        assert_eq!(encoded, data, "网络包帧的头重新编码之后对不上原来的帧");
        return;
    }
    // 合着好几个包的：读得出来的那些原样装回去，是原来的帧的开头；一个错都没有的话就是整个帧。
    let mut intact = true;
    for packet in Bundled::new(rest) {
        match packet {
            Ok(packet) => Bundled::push(&mut encoded, packet).expect("读出来的包长度写得进两个字节"),
            Err(_) => intact = false,
        }
    }
    assert!(data.starts_with(&encoded), "读出来的包装回去对不上原来的帧");
    assert!(!intact || encoded == data, "没有读到错，却没有读完整个帧");
}

/// 前 2 字节是每帧的上限，再 2 字节是报文号，剩下的是内容。
fn split_and_join(data: &[u8]) {
    let Some((&[hi, lo, m0, m1], body)) = data.split_first_chunk::<4>() else { return };
    let max_len = usize::from(u16::from_be_bytes([hi, lo]));
    let recipient = if m1 & 1 == 0 { Recipient::Acceptor } else { Recipient::Initiator };
    let Ok(frames) = Frames::split(recipient, 0x0102_0304, u16::from_be_bytes([m0, m1]), body, max_len) else { return };
    let (mut joined, mut frames_seen, mut announced) = (Vec::new(), 0, None);
    for (index, frame) in frames.enumerate() {
        assert!(frame.len() <= max_len, "第 {index} 帧有 {} 字节，上限是 {max_len}", frame.len());
        let (header, piece) = DatagramHeader::decode(&frame).expect("自己切出来的帧一定解析得了");
        assert_eq!((header.recipient, header.context), (recipient, 0x0102_0304));
        match header.fragment {
            None => assert_eq!(index, 0, "不分片的报文只有一帧"),
            Some(fragment) => {
                let count = *announced.get_or_insert(fragment.count);
                assert_eq!((fragment.count, usize::from(fragment.index)), (count, index), "片数或者片序号不对");
            }
        }
        joined.extend_from_slice(piece);
        frames_seen += 1;
    }
    if let Some(count) = announced {
        assert_eq!(frames_seen, usize::from(count), "切出来的片数和头里写的不一样");
    }
    assert_eq!(joined, body, "拼回来的内容和原来的不一样");
}
