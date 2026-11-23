//! 别的节点访问"本节点的端口"时，来源不会被洗成本机：节点程序自己的监听（端口转发、代理、名字服务）出口不当成本机的服务去连，
//! 对组网里的节点开着的端口转发按发起节点查白名单。还有端口转发守着的几样东西：云平台的元数据地址不连，
//! 监听和目标在同一个节点上的转发要求了 PROXY protocol 的头就一定发、netmap 变了之后不再成立的连接断开。

// clippy.toml 里的 allow-unwrap-in-tests 只管 #[test] 函数，管不到集成测试里的辅助函数。这里 unwrap 失败就是测试失败。
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{
    GW, LAPTOP, NAS, PATIENCE, Target, UdpTarget, World, assert_echo, assert_reset, drain, echo_server, node, non_loopback_address,
    peer_mut, proxy, socks5, udp_associate, udp_echo_server,
};
use i3t_access::{OwnListener, TargetCause};
use i3t_model::netmap::{Forward, ForwardProtocol, ForwardTarget, ListenerProtocol, ProxyProtocol};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// 断言"这件事不会发生"时观察多久。
const QUIET: Duration = Duration::from_millis(200);

const TCP: ForwardProtocol = ForwardProtocol::Tcp;
const UDP: ForwardProtocol = ForwardProtocol::Udp;

fn forward(id: u32, protocol: ForwardProtocol, bind: &str, target: u32) -> Forward {
    Forward { id, protocol, bind: bind.parse().unwrap(), target: node(target), allow_from: Vec::new(), class: None }
}

fn target(id: u32, protocol: ForwardProtocol, addr: SocketAddr, listener: u32) -> ForwardTarget {
    ForwardTarget { id, protocol, addr, listener: node(listener), proxy_protocol: None }
}

/// 这条连接被重置了。
async fn assert_cut(stream: &mut TcpStream) {
    assert_reset(&drain(stream).await.1);
}

/// `node` 上编号是 `id` 的转发最近一次在目标那里失败的原因。
fn target_cause(node: &common::Node, id: u32) -> Option<TargetCause> {
    node.access.status().forwards.iter().find(|forward| forward.id == id)?.target_failure.map(|failure| failure.cause)
}

/// 从 `stream` 读满 `len` 个字节。
async fn read(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut received = vec![0; len];
    timeout(PATIENCE, stream.read_exact(&mut received)).await.expect("数据应该到").unwrap();
    received
}

i3t_lane::on_both_transports! {
    async fn a_forward_on_every_address_is_served_to_other_nodes_by_who_they_are() {
        let world = World::new().await;
        // nas 的网卡报一个真的地址（这台机器有的话）：出口要是把这个端口当成本机的服务去连，就真的连得上入口的监听。
        let own = non_loopback_address();
        if let Some(address) = own {
            world.nas.system.set_interfaces(&["127.0.0.1/8", &format!("{address}/32")]);
        }
        let echo = echo_server().await;
        // 监听在全部地址上、端口让节点自己挑的转发，指向 nas 回环上的服务。
        world
            .nas
            .update(|netmap| {
                netmap.me.forwards.push(forward(9, TCP, "0.0.0.0:0", NAS));
                netmap.me.forward_targets.push(target(9, TCP, echo, NAS));
            })
            .await;
        let listening = world.nas.forward(9).await;

        // 别的节点经流访问 nas 的这个端口：出口按这条转发接住，自己去连它指向的地址。
        let mut stream = socks5(world.socks().await, None, "10.66.0.3", listening.port()).await.connected();
        assert_echo(&mut stream).await;
        assert_eq!(world.nas.system.connected(), [echo], "没有从本机去连入口的监听");

        // 只给局域网里的机器和本机用的白名单。别的节点不在里面：它的来源是它的虚拟 IP，不是 nas 自己的地址，
        // 尽管出口要是从本机去连那个监听，来源正好在白名单里。已经连着的那一条也断开。
        let mut lan_only: Vec<IpNet> = vec!["192.168.0.0/16".parse().unwrap(), "127.0.0.0/8".parse().unwrap()];
        lan_only.extend(own.map(IpNet::from));
        world.nas.update(|netmap| netmap.me.forwards[0].allow_from = lan_only).await;
        assert_cut(&mut stream).await;
        assert_eq!(socks5(world.socks().await, None, "10.66.0.3", listening.port()).await.failed(), 2);
        assert_eq!(world.nas.system.connected(), [echo], "被拒绝的那一次哪里都没有去连");

        // 白名单里的来源照旧连得上操作系统里的那个监听。
        let mut local = TcpStream::connect(listening).await.unwrap();
        assert_echo(&mut local).await;

        // 白名单里有发起节点的虚拟 IP 时，它经流也连得上。
        world.nas.update(|netmap| netmap.me.forwards[0].allow_from.push("10.66.0.1/32".parse().unwrap())).await;
        let mut stream = socks5(world.socks().await, None, "10.66.0.3", listening.port()).await.connected();
        assert_echo(&mut stream).await;
    }
}

#[tokio::test]
async fn a_udp_forward_on_every_address_is_served_to_other_nodes_by_who_they_are() {
    let world = World::new().await;
    let service = udp_echo_server().await;
    world
        .nas
        .update(|netmap| {
            netmap.me.forwards.push(forward(9, UDP, "0.0.0.0:0", NAS));
            netmap.me.forward_targets.push(target(9, UDP, service, NAS));
        })
        .await;
    let port = world.nas.forward(9).await.port();

    let client = udp_associate(world.socks().await, None).await;
    client.send("10.66.0.3", port, b"to the forward").await;
    assert_eq!(client.recv().await, (format!("10.66.0.3:{port}"), b"to the forward".to_vec()));
    assert_eq!(world.nas.system.udp_destinations(), [service], "去的是转发指向的地址，不是入口在本机的那个端口");

    // 只给局域网里的机器用的白名单：nas 的假网卡地址 192.168.77.5 在里面，发起节点的虚拟 IP 不在。
    world.nas.update(|netmap| netmap.me.forwards[0].allow_from = vec!["192.168.77.0/24".parse().unwrap()]).await;
    client.send("10.66.0.3", port, b"not allowed").await;
    client.assert_silent(QUIET).await;
    assert_eq!(world.nas.system.udp_destinations(), [service]);
}

#[tokio::test]
async fn a_forward_on_one_lan_address_and_a_proxy_are_not_reached_as_services_of_the_node() {
    let Some(address) = non_loopback_address() else {
        eprintln!("跳过：这台机器只有回环网卡，没法在非回环地址上监听");
        return;
    };
    let world = World::new().await;
    world.nas.system.set_interfaces(&["127.0.0.1/8", &format!("{address}/32")]);
    let service = Target::bind("127.0.0.1").await;
    // 只监听在局域网那个地址上的转发（白名单是空的），和同一个地址上的一个代理。
    world
        .nas
        .update(|netmap| {
            netmap.me.forwards.push(forward(7, TCP, &format!("{address}:0"), NAS));
            netmap.me.forward_targets.push(target(7, TCP, service.addr(), NAS));
            netmap.me.proxies.push(proxy(5, ListenerProtocol::Socks5, &format!("{address}:0"), GW));
        })
        .await;
    let (forward_at, proxy_at) = (world.nas.forward(7).await, world.nas.proxy(5).await);

    // 那块网卡上的机器照常用这条转发。
    let mut lan = TcpStream::connect(forward_at).await.unwrap();
    lan.write_all(b"from the lan").await.unwrap();
    let mut accepted = service.accept().await;
    assert_eq!(read(&mut accepted, 12).await, b"from the lan");

    // 别的节点把这两个端口当成 nas 上的服务来访问：出口不去连。连了的话来源是 nas 自己的地址，
    // 转发就替一个本来到不了这块网卡的节点开了门，代理的来源白名单也跟着失效。
    for port in [forward_at.port(), proxy_at.port()] {
        assert_eq!(socks5(world.socks().await, None, "10.66.0.3", port).await.failed(), 2, "{port}");
    }
    service.assert_untouched(QUIET).await;
    assert!(world.nas.system.connected().is_empty(), "出口哪里都没有去连：{:?}", world.nas.system.connected());

    // 同一个地址上别的程序的服务照常可达。
    let other = Target::bind(&address.to_string()).await.echo();
    let mut stream = socks5(world.socks().await, None, "10.66.0.3", other.port()).await.connected();
    assert_echo(&mut stream).await;
}

#[tokio::test]
async fn a_udp_port_the_program_itself_listens_on_is_never_sent_to_from_this_machine() {
    let world = World::new().await;
    // nas 的虚拟网卡装着，它的地址排在最前面；上面的 53 端口是名字服务，只答来源是本机的查询。
    world.nas.system.set_interfaces(&["127.0.0.1/8", "10.66.0.3/16", "192.168.77.5/24"]);
    let names = UdpTarget::bind("127.0.0.1").await;
    world.nas.system.redirect("10.66.0.3:53", names.addr());
    world.nas.system.redirect("192.168.77.5:53", udp_echo_server().await);
    world.nas.system.redirect("10.66.0.3:5353", udp_echo_server().await);
    let name_service = |ip: &str| OwnListener { protocol: UDP, local: format!("{ip}:53").parse().unwrap(), forward: None };
    *world.nas.other_listeners.lock().unwrap() = vec![name_service("10.66.0.3")];

    let client = udp_associate(world.socks().await, None).await;
    // 别的节点发往 nas 的 53 端口：绕开名字服务，发到下一个地址上（那里有这台机器自己的 DNS 服务的话，答的是它）。
    client.send("10.66.0.3", 53, b"query").await;
    assert_eq!(client.recv().await, ("10.66.0.3:53".to_owned(), b"query".to_vec()));
    names.assert_untouched(QUIET).await;
    // 虚拟 IP 上别的程序的服务不受影响：别的端口照旧发到第一个地址上。
    client.send("10.66.0.3", 5353, b"mdns").await;
    assert_eq!(client.recv().await.1, b"mdns");
    let sent_to: Vec<SocketAddr> = vec!["192.168.77.5:53".parse().unwrap(), "10.66.0.3:5353".parse().unwrap()];
    assert_eq!(world.nas.system.udp_destinations(), sent_to);

    // gw 只有虚拟 IP 这一个非回环的 IPv4 地址（纯 IPv6 的宿主机）：没有别的地址可发，丢掉。
    world.gw.system.set_interfaces(&["127.0.0.1/8", "10.66.0.2/16"]);
    world.gw.system.redirect("10.66.0.2:53", names.addr());
    *world.gw.other_listeners.lock().unwrap() = vec![name_service("10.66.0.2")];
    client.send("10.66.0.2", 53, b"query").await;
    names.assert_untouched(QUIET).await;
    client.assert_silent(QUIET).await;
    assert!(world.gw.system.udp_destinations().is_empty());
}

#[tokio::test]
async fn a_forward_never_reaches_a_cloud_metadata_address_whichever_way_it_is_used() {
    let world = World::new().await;
    let metadata = ["169.254.169.254:80", "100.100.100.200:80", "168.63.129.16:80", "[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:80"];
    // 万一出口去连了，连到的是这个测试服务，测试看得见。
    let trap = Target::bind("127.0.0.1").await;
    for address in metadata {
        world.nas.system.redirect(address, trap.addr());
    }
    // 每个地址一条 laptop 监听、指向 nas 的 TCP 转发；第一个地址另有一条 UDP 的，和一条监听在 nas 虚拟 IP 上的。
    let listed = || (20u32..).zip(metadata.map(|address| address.parse::<SocketAddr>().unwrap()));
    world
        .laptop
        .update(|netmap| {
            netmap.me.forwards.extend(listed().map(|(id, _)| forward(id, TCP, "127.0.0.1:0", NAS)));
            netmap.me.forwards.push(forward(40, UDP, "127.0.0.1:0", NAS));
        })
        .await;
    world
        .nas
        .update(|netmap| {
            netmap.me.forward_targets.extend(listed().map(|(id, address)| target(id, TCP, address, LAPTOP)));
            netmap.me.forward_targets.push(target(40, UDP, metadata[0].parse().unwrap(), LAPTOP));
            netmap.me.forwards.push(forward(41, TCP, "10.66.0.3:8169", NAS));
            netmap.me.forward_targets.push(target(41, TCP, metadata[0].parse().unwrap(), NAS));
        })
        .await;

    for (id, address) in listed() {
        let mut stream = TcpStream::connect(world.laptop.forward(id).await).await.unwrap();
        assert_cut(&mut stream).await;
        assert!(world.nas.system.connected().is_empty(), "{address}");
    }
    assert_eq!(socks5(world.socks().await, None, "10.66.0.3", 8169).await.failed(), 2, "nas 虚拟 IP 上的那一条");
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"query", world.laptop.forward(40).await).await.unwrap();
    trap.assert_untouched(QUIET).await;
    assert!(world.nas.system.connected().is_empty() && world.nas.system.udp_destinations().is_empty());
}

#[tokio::test]
async fn a_forward_to_the_listening_node_itself_does_not_dial_a_cloud_metadata_address() {
    let world = World::new().await;
    world
        .nas
        .update(|netmap| {
            netmap.me.forwards.push(forward(7, TCP, "127.0.0.1:0", NAS));
            netmap.me.forward_targets.push(target(7, TCP, "169.254.169.254:80".parse().unwrap(), NAS));
        })
        .await;
    let mut stream = TcpStream::connect(world.nas.forward(7).await).await.unwrap();
    assert_cut(&mut stream).await;
    // 没有去连过：连过而连不上的话，会记成这条转发的目标不通（在云主机上则是连上了，连接不会被重置）。
    assert_eq!(target_cause(&world.nas, 7), None);
}

#[tokio::test]
async fn a_forward_to_the_listening_node_itself_sends_the_proxy_header_for_an_ipv6_client_too() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("跳过：这台机器没有 IPv6 的回环地址");
        return;
    }
    let world = World::new().await;
    let (v1, v2) = (Target::bind("127.0.0.1").await, Target::bind("::1").await);
    world
        .nas
        .update(|netmap| {
            for (id, service, version) in [(7, v1.addr(), ProxyProtocol::V1), (8, v2.addr(), ProxyProtocol::V2)] {
                netmap.me.forwards.push(forward(id, TCP, "[::1]:0", NAS));
                netmap.me.forward_targets.push(ForwardTarget { proxy_protocol: Some(version), ..target(id, TCP, service, NAS) });
            }
        })
        .await;

    // 认这个头的服务把最先到的字节当成头：客户端的数据前面一定是节点写的头，哪怕客户端是从 IPv6 连进来的。
    let mut client = TcpStream::connect(world.nas.forward(7).await).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut service = v1.accept().await;
    let expected = format!("PROXY TCP6 ::1 ::ffff:127.0.0.1 {} {}\r\nhello", client.local_addr().unwrap().port(), v1.addr().port());
    assert_eq!(String::from_utf8(read(&mut service, expected.len()).await).unwrap(), expected);

    let mut client = TcpStream::connect(world.nas.forward(8).await).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut service = v2.accept().await;
    let received = read(&mut service, 16 + 36 + 5).await;
    assert_eq!(&received[..16], b"\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24");
    let loopback = std::net::Ipv6Addr::LOCALHOST.octets();
    assert_eq!((&received[16..32], &received[32..48]), (&loopback[..], &loopback[..]));
    assert_eq!(u16::from_be_bytes([received[48], received[49]]), client.local_addr().unwrap().port());
    assert_eq!(u16::from_be_bytes([received[50], received[51]]), v2.addr().port());
    assert_eq!(&received[52..], b"hello");
}

#[tokio::test]
async fn a_connection_through_a_forward_to_the_listening_node_itself_ends_when_the_forward_no_longer_admits_it() {
    let world = World::new().await;
    let echo = echo_server().await;
    world
        .nas
        .update(|netmap| {
            netmap.me.forwards.push(forward(7, TCP, "127.0.0.1:0", NAS));
            netmap.me.forward_targets.push(target(7, TCP, echo, NAS));
        })
        .await;
    let connected = || async {
        let mut stream = TcpStream::connect(world.nas.forward(7).await).await.unwrap();
        assert_echo(&mut stream).await;
        stream
    };

    // 白名单收紧，来源不在里面了。
    let mut stream = connected().await;
    world.nas.update(|netmap| netmap.me.forwards[0].allow_from = vec!["192.168.1.0/24".parse().unwrap()]).await;
    assert_cut(&mut stream).await;
    world.nas.update(|netmap| netmap.me.forwards[0].allow_from.clear()).await;

    // 转发改成指向别的地址。
    let mut stream = connected().await;
    let elsewhere = echo_server().await;
    world.nas.update(|netmap| netmap.me.forward_targets[0].addr = elsewhere).await;
    assert_cut(&mut stream).await;

    // 无关的变化不碰它；转发删掉，它跟着断。
    let mut stream = connected().await;
    world.nas.update(|netmap| peer_mut(netmap, GW).keep_alive = true).await;
    assert_echo(&mut stream).await;
    world.nas.update(|netmap| netmap.me.forwards.clear()).await;
    assert_cut(&mut stream).await;
}
