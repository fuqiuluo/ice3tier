//! 控制器整体的测试：在模拟的链路上跑，检查每一次状态变化的时机，和几种路径条件下的结果。
//!
//! 模拟是确定的（随机数的种子固定），所以断言里的数字可以卡得比较紧；改了算法之后数字有小的出入是正常的。

use std::time::Duration;

use super::sim::{App, Link, MTU, Reno, Sim};
use super::*;

const fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

const fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// 一条一直有数据可发的连接，在 `link` 上跑 `seconds` 秒。
fn bulk(link: Link, seconds: u64) -> Sim {
    let mut sim = Sim::new(link, 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.run(secs(seconds));
    sim
}

fn kind(state: State) -> &'static str {
    match state {
        State::Startup => "startup",
        State::Drain => "drain",
        State::ProbeBw(Phase::Cruise { .. }) => "cruise",
        State::ProbeBw(Phase::Up { .. }) => "up",
        State::ProbeBw(Phase::Down { .. }) => "down",
        State::ProbeRtt(_) => "probe-rtt",
    }
}

/// 第 `flow` 条连接在 `from` 到 `to` 之间进入过的状态。
fn entered(sim: &Sim, flow: usize, from: Duration, to: Duration) -> Vec<&'static str> {
    sim.states(flow).iter().filter(|&&(at, _)| from <= at && at < to).map(|&(_, state)| kind(state)).collect()
}

/// 第 `flow` 条连接第一次进入 `name` 状态的时刻。
fn first(sim: &Sim, flow: usize, name: &str) -> Duration {
    sim.states(flow).iter().find(|&&(_, state)| kind(state) == name).map(|&(at, _)| at).unwrap_or_else(|| panic!("没有进入过 {name}"))
}

/// 每一次停留在 `name` 状态的时长。
fn stays(sim: &Sim, flow: usize, name: &str) -> Vec<Duration> {
    sim.states(flow).windows(2).filter(|pair| kind(pair[0].1) == name).map(|pair| pair[1].0 - pair[0].0).collect()
}

fn bw_mbit(sim: &Sim, flow: usize) -> f64 {
    sim.bbr(flow).bw.get().unwrap_or(0) as f64 * 8.0 / 1e6
}

fn min_rtt(sim: &Sim, flow: usize) -> Duration {
    sim.bbr(flow).min_rtt.get().unwrap()
}

/// 在真空里喂给控制器一小段匀速的收发：每毫秒一个包，往返 `rtt`，共 `packets` 个。返回结束的时刻。
fn feed(bbr: &mut Bbr, start: Instant, rtt: Duration, packets: u32) -> Instant {
    let flight = u32::try_from(rtt.as_millis()).unwrap();
    for tick in 0..packets + flight {
        let now = start + ms(u64::from(tick));
        if tick >= flight {
            bbr.acked(now, now - rtt, MTU);
            let outstanding = packets.min(tick + 1).saturating_sub(tick + 1 - flight);
            bbr.end_acks(now, u64::from(outstanding) * MTU, false);
        }
        if tick < packets {
            bbr.sent(now, MTU);
        }
    }
    start + ms(u64::from(packets + flight))
}

fn new_bbr(now: Instant) -> Bbr {
    Bbr::new(now, u16::try_from(MTU).unwrap(), 1)
}

#[test]
fn the_window_starts_at_the_initial_window_and_never_falls_below_four_packets() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    assert_eq!(bbr.window(), 10 * MTU);
    assert_eq!(Controller::initial_window(&bbr), 10 * MTU);
    // 一条很慢的路径：每 100ms 才送到一个包。
    for tick in 0..50 {
        let now = start + ms(100 * tick);
        bbr.sent(now, MTU);
        bbr.acked(now + ms(90), now, MTU);
        bbr.end_acks(now + ms(90), 0, false);
    }
    assert!(bbr.filled_pipe, "带宽早就不涨了");
    assert_eq!(bbr.window(), MIN_WINDOW_PACKETS * MTU);
}

#[test]
fn startup_doubles_the_window_each_round_until_the_bandwidth_stops_growing() {
    let sim = bulk(Link::new(20, 50), 3);
    assert_eq!(entered(&sim, 0, Duration::ZERO, secs(1))[..3], ["startup", "drain", "cruise"]);
    // 从 10 个包到装满 20 Mbit/s × 50ms（约 100 个包）要翻三四倍，再加上确认带宽不涨了的三轮。
    let drain = first(&sim, 0, "drain");
    assert!((ms(350)..ms(650)).contains(&drain), "启动阶段在 {drain:?} 结束");
    assert!((19.0..20.5).contains(&bw_mbit(&sim, 0)), "带宽估计 {}", bw_mbit(&sim, 0));
    assert_eq!(sim.loss_ratio(0, Duration::ZERO, secs(3)), 0.0);
}

#[test]
fn startup_ends_as_soon_as_probing_loses_too_much_and_the_bandwidth_has_stalled() {
    // 缓冲只有 15 个包：启动阶段多发出去的那一倍装不下。
    let shallow = bulk(Link::new(20, 50).buffer_packets(15), 3);
    let deep = bulk(Link::new(20, 50), 3);
    assert!(first(&shallow, 0, "drain") + ms(90) < first(&deep, 0, "drain"), "丢包让启动阶段提前结束，不用等满三轮");
    assert!(shallow.bbr(0).inflight_hi.is_some());
    assert!(shallow.mbit(0, secs(2), secs(3)) > 19.0, "上限从启动阶段结束时的量一步步试探回来");
}

#[test]
fn random_loss_does_not_end_startup_while_the_bandwidth_is_still_growing() {
    let sim = bulk(Link::new(100, 50).loss_percent(5), 2);
    let drain = first(&sim, 0, "drain");
    assert!(sim.mbit(0, drain - ms(100), drain) > 80.0, "启动阶段结束前的 100ms 里吞吐是 {}", sim.mbit(0, drain - ms(100), drain));
}

#[test]
fn drain_lasts_until_the_excess_from_startup_has_left_the_queue() {
    let sim = bulk(Link::new(20, 50), 3);
    let drained = first(&sim, 0, "cruise") - first(&sim, 0, "drain");
    assert!((ms(20)..ms(120)).contains(&drained), "排空用了 {drained:?}");
    // 排空之后的往返时间回到下限附近。
    let cruise = first(&sim, 0, "cruise");
    assert!(sim.mean_rtt(0, cruise + ms(100), cruise + ms(200)) < ms(56), "{:?}", sim.mean_rtt(0, cruise + ms(100), cruise + ms(200)));
}

#[test]
fn probe_bw_cycles_through_cruise_up_and_down() {
    let sim = bulk(Link::new(20, 50), 6);
    let cycle = entered(&sim, 0, secs(1), secs(6));
    assert!(cycle.len() >= 15, "5 秒里只换了 {} 次阶段", cycle.len());
    for step in cycle.windows(2) {
        assert!(matches!(step, ["cruise", "up"] | ["up", "down"] | ["down", "cruise"]), "{step:?}");
    }
    // 向上试探两轮，向下一轮，巡航三到六轮。一轮是一个往返时间，排队的时候长一点。
    assert!(stays(&sim, 0, "up").iter().all(|stay| (ms(95)..ms(140)).contains(stay)), "{:?}", stays(&sim, 0, "up"));
    assert!(stays(&sim, 0, "down").iter().all(|stay| (ms(45)..ms(90)).contains(stay)), "{:?}", stays(&sim, 0, "down"));
    assert!(stays(&sim, 0, "cruise").iter().skip(1).all(|stay| (ms(140)..ms(340)).contains(stay)), "{:?}", stays(&sim, 0, "cruise"));
}

#[test]
fn a_clean_link_is_filled_without_loss_and_without_a_standing_queue() {
    for (mbit, rtt) in [(20, 50), (100, 50), (5, 200), (1000, 2)] {
        let sim = bulk(Link::new(mbit, rtt), 10);
        let rate = sim.mbit(0, secs(3), secs(10));
        assert!(rate > mbit as f64 * 0.95, "{mbit} Mbit/s、{rtt}ms：吞吐 {rate}");
        assert_eq!(sim.loss_ratio(0, secs(3), secs(10)), 0.0);
        let mean = sim.mean_rtt(0, secs(3), secs(10));
        assert!(mean < ms(rtt) * 6 / 5, "{mbit} Mbit/s、{rtt}ms：平均往返 {mean:?}");
    }
}

#[test]
fn upward_probing_continues_while_the_bandwidth_keeps_growing() {
    let mut sim = Sim::new(Link::new(20, 50), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(100, 50));
    sim.run(secs(8));
    // 带宽变成五倍之后的第一次向上试探，一直持续到送达速率不再涨为止：每轮 25%，要七八轮。
    let longest = stays(&sim, 0, "up").into_iter().max().unwrap();
    assert!(longest > ms(300), "最长的一次向上试探只有 {longest:?}");
    assert!(sim.mbit(0, secs(6), secs(8)) > 95.0, "带宽变大两秒之后的吞吐 {}", sim.mbit(0, secs(6), secs(8)));
}

#[test]
fn the_estimate_follows_a_bandwidth_drop_and_the_queue_drains() {
    let mut sim = Sim::new(Link::new(100, 50), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(20, 50));
    sim.run(secs(10));
    // 往返时间连续几轮远高于该有的值，提前做了一次往返时间探测；结果下限没有变，于是旧的带宽样本作废。
    assert_eq!(entered(&sim, 0, secs(4), secs(5)).iter().filter(|&&name| name == "probe-rtt").count(), 1);
    assert!((ms(50)..ms(52)).contains(&min_rtt(&sim, 0)));
    assert!((19.0..21.0).contains(&bw_mbit(&sim, 0)), "带宽估计 {}", bw_mbit(&sim, 0));
    assert!(sim.mbit(0, secs(6), secs(10)) > 19.0);
    assert!(sim.mean_rtt(0, secs(6), secs(10)) < ms(60), "带宽变小两秒之后的平均往返 {:?}", sim.mean_rtt(0, secs(6), secs(10)));
    assert_eq!(sim.loss_ratio(0, secs(5), secs(10)), 0.0, "只有变化的那一刻已经在路上的包会丢");
}

#[test]
fn a_bandwidth_drop_on_a_shallow_buffer_is_answered_by_the_in_flight_bound() {
    let mut sim = Sim::new(Link::new(100, 50).buffer_packets(30), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(20, 50).buffer_packets(30));
    sim.run(secs(10));
    // 缓冲浅，排不起队，往返时间看不出变化；靠丢包把在途量的上限压下来。
    let hi = sim.bbr(0).inflight_hi.unwrap();
    assert!(hi < 250_000, "在途量上限 {hi}，新的 BDP 是 125000");
    assert!(sim.mbit(0, secs(5), secs(10)) > 18.5);
    assert!(sim.loss_ratio(0, secs(5), secs(10)) < 0.03, "之后的丢包率 {}", sim.loss_ratio(0, secs(5), secs(10)));
}

#[test]
fn a_longer_path_is_noticed_within_a_second_and_the_floor_is_raised() {
    let mut sim = Sim::new(Link::new(100, 30), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(100, 100));
    sim.run(secs(10));
    let probes: Vec<Duration> = sim.states(0).iter().filter(|&&(_, state)| kind(state) == "probe-rtt").map(|&(at, _)| at).collect();
    // 第一次是因为往返时间高于该有的值；两秒之后复核一次被抬高的下限。
    assert_eq!(probes.len(), 2, "{probes:?}");
    assert!((secs(4)..ms(4600)).contains(&probes[0]), "{probes:?}");
    assert!((ms(6200)..ms(7200)).contains(&probes[1]), "{probes:?}");
    assert!((ms(100)..ms(102)).contains(&min_rtt(&sim, 0)));
    // 路径变长不等于带宽变小：带宽估计没有作废，探测一结束就回到原来的吞吐。
    assert!(sim.mbit(0, secs(5), secs(6)) > 95.0, "换路一秒之后的吞吐 {}", sim.mbit(0, secs(5), secs(6)));
    assert!(sim.mbit(0, secs(7), secs(10)) > 95.0);
}

#[test]
fn a_shorter_path_is_used_at_once() {
    let mut sim = Sim::new(Link::new(100, 100), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(100, 30));
    sim.run(secs(8));
    assert!((ms(30)..ms(31)).contains(&min_rtt(&sim, 0)));
    assert!(sim.mbit(0, secs(4), secs(8)) > 95.0);
    assert!(sim.mean_rtt(0, secs(5), secs(8)) < ms(36));
}

#[test]
fn a_path_that_is_both_longer_and_narrower_settles_in_two_seconds() {
    let mut sim = Sim::new(Link::new(100, 30), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(20, 100));
    sim.run(secs(10));
    assert!((ms(100)..ms(102)).contains(&min_rtt(&sim, 0)));
    assert!((19.0..21.0).contains(&bw_mbit(&sim, 0)), "带宽估计 {}", bw_mbit(&sim, 0));
    assert!(sim.mbit(0, secs(6), secs(10)) > 18.0);
    assert!(sim.loss_ratio(0, secs(6), secs(10)) < 0.01);
    assert!(sim.mean_rtt(0, secs(6), secs(10)) < ms(120));
}

#[test]
fn losses_while_the_path_is_down_are_not_taken_for_congestion() {
    let mut sim = Sim::new(Link::new(100, 50), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    // 路断了 1.5 秒，什么都过不去，之后原样恢复。
    sim.relink_at(secs(4), Link::new(100, 50).loss_percent(100));
    sim.relink_at(ms(5500), Link::new(100, 50));
    sim.run(secs(9));
    assert_eq!(sim.bbr(0).inflight_hi, None, "断路时丢掉的包不该给在途量定上限");
    assert!(sim.mbit(0, secs(7), secs(9)) > 95.0, "恢复之后的吞吐 {}", sim.mbit(0, secs(7), secs(9)));
}

#[test]
fn a_longer_path_after_an_outage_is_filled_within_a_second() {
    // 直连断了，路径层过了两秒改走经 relay 的路：往返从 30ms 变成 100ms，带宽不变。
    let mut sim = Sim::new(Link::new(100, 30), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.relink_at(secs(4), Link::new(100, 30).loss_percent(100));
    sim.relink_at(secs(6), Link::new(100, 100));
    sim.run(secs(10));
    assert!((ms(100)..ms(102)).contains(&min_rtt(&sim, 0)));
    assert_eq!(sim.bbr(0).inflight_hi, None);
    assert!(sim.mbit(0, secs(7), ms(8500)) > 95.0, "换路一秒之后的吞吐 {}", sim.mbit(0, secs(7), ms(8500)));
    // 抬高的下限两秒之后复核一次，那一次往返时间探测少发一些。
    assert!(sim.mbit(0, secs(7), secs(10)) > 85.0, "{}", sim.mbit(0, secs(7), secs(10)));
}

#[test]
fn silence_counts_from_the_first_unanswered_send_not_from_the_last_ack() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    let now = feed(&mut bbr, start, ms(50), 500);
    // 应用三秒没有数据，之后发出的包 50ms 后被确认：中间的空闲不算没有回音。
    let resume = now + secs(3);
    bbr.sent(resume, MTU);
    assert_eq!(bbr.take_silence(resume + ms(50)), ms(50));
    // 接着发出去的包两秒没有回音（路断了），这才算。
    bbr.sent(resume + ms(100), MTU);
    bbr.sent(resume + ms(200), MTU);
    let silence = bbr.take_silence(resume + ms(2100));
    assert_eq!(silence, secs(2));
    assert!(silence > bbr.outage_after());
    assert_eq!(bbr.take_silence(resume + ms(2200)), Duration::ZERO, "这之后还没有发过");
}

#[test]
fn a_much_higher_floor_drops_the_in_flight_bound_learnt_on_the_old_path() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    let now = feed(&mut bbr, start, ms(30), 500);
    bbr.inflight_hi = Some(40 * MTU);
    bbr.replace_floor(now, ms(36));
    assert_eq!(bbr.inflight_hi, Some(40 * MTU), "高出不到四分之一，还是原来那条路");
    bbr.replace_floor(now, ms(100));
    assert_eq!(bbr.inflight_hi, None);
}

#[test]
fn the_floor_is_not_probed_while_samples_keep_touching_it() {
    let sim = bulk(Link::new(20, 50), 20);
    assert!(!entered(&sim, 0, Duration::ZERO, secs(20)).contains(&"probe-rtt"), "向下的那一轮里量到的往返时间就贴着下限");
}

#[test]
fn the_floor_is_probed_when_another_flow_keeps_a_queue_standing() {
    let mut sim = Sim::new(Link::new(20, 50), 7);
    sim.add_flow(Box::new(Reno::new()), App::Bulk, Duration::ZERO);
    sim.add_bbr(App::Bulk, secs(2));
    sim.run(secs(20));
    let probes = entered(&sim, 1, secs(2), secs(20)).iter().filter(|&&name| name == "probe-rtt").count();
    assert!((2..=6).contains(&probes), "18 秒里做了 {probes} 次往返时间探测");
    // 探测期间在途量减半，每次不到半秒。
    assert!(stays(&sim, 1, "probe-rtt").iter().all(|stay| (ms(200)..ms(600)).contains(stay)), "{:?}", stays(&sim, 1, "probe-rtt"));
}

#[test]
fn random_loss_is_not_taken_for_congestion() {
    for (percent, floor) in [(1, 95.0), (3, 93.0), (5, 90.0)] {
        let sim = bulk(Link::new(100, 50).loss_percent(percent), 12);
        let rate = sim.mbit(0, secs(3), secs(12));
        assert!(rate > floor, "丢包 {percent}%：吞吐 {rate}");
    }
}

#[test]
fn bursty_random_loss_is_not_taken_for_congestion() {
    // 确认 2ms 一批地回来，发送方也就一批一批地发；丢包是整批地丢。
    for (mbit, floor) in [(100, 90.0), (20, 17.0)] {
        let sim = bulk(Link::new(mbit, 50).loss_percent(3).bursty().acks_every(ms(2)), 20);
        let rate = sim.mbit(0, secs(8), secs(20));
        assert!(rate > floor, "{mbit} Mbit/s、成片丢包 3%：吞吐 {rate}");
    }
}

#[test]
fn a_shallow_buffer_bounds_the_loss_it_causes() {
    // 缓冲分别是 BDP 的 29% 和 6%。前一个装得下向上试探多发的 25%，装不下启动阶段多发的一倍；后一个两样都装不下。
    for (mbit, floor) in [(20, 19.0), (100, 95.0)] {
        let sim = bulk(Link::new(mbit, 50).buffer_packets(30), 15);
        let (rate, loss) = (sim.mbit(0, secs(3), secs(15)), sim.loss_ratio(0, secs(3), secs(15)));
        assert!(rate > floor, "{mbit} Mbit/s：吞吐 {rate}");
        assert!(loss < 0.02, "{mbit} Mbit/s：丢包率 {loss}");
        assert!(sim.bbr(0).inflight_hi.is_some());
    }
}

#[test]
fn probing_backs_off_after_it_ends_in_loss() {
    let sim = bulk(Link::new(100, 50).buffer_packets(30), 15);
    let longest = stays(&sim, 0, "cruise").into_iter().max().unwrap();
    assert!(longest > ms(900), "最长的一次巡航 {longest:?}：试探总是以丢包收场时，间隔应该拉长");
    let clean = bulk(Link::new(100, 50), 15);
    assert!(stays(&clean, 0, "cruise").into_iter().skip(1).max().unwrap() < ms(400));
}

#[test]
fn an_idle_application_does_not_inflate_the_estimates() {
    let mut sim = Sim::new(Link::new(100, 50), 7);
    // 每 100ms 发 20KB，平均 1.6 Mbit/s，链路是 100 Mbit/s。
    sim.add_bbr(App::Chunks { bytes: 20_000, every: ms(100) }, Duration::ZERO);
    sim.set_app_at(secs(10), 0, App::Bulk);
    sim.run(secs(10));
    assert!(bw_mbit(&sim, 0) < 4.0, "带宽估计 {}", bw_mbit(&sim, 0));
    assert!(sim.bbr(0).window < 60 * MTU, "窗口 {}", sim.bbr(0).window);
    assert!(!entered(&sim, 0, Duration::ZERO, secs(10)).contains(&"probe-rtt"), "应用发得少的时候用不着专门去量往返时间");
    // 应用开始大量发送之后，一秒之内用满链路。
    sim.run(secs(13));
    assert!(sim.mbit(0, secs(11), secs(13)) > 95.0, "{}", sim.mbit(0, secs(11), secs(13)));
}

#[test]
fn two_flows_share_a_bottleneck_evenly() {
    let mut sim = Sim::new(Link::new(20, 50), 7);
    sim.add_bbr(App::Bulk, Duration::ZERO);
    sim.add_bbr(App::Bulk, secs(5));
    sim.run(secs(40));
    let (first, second) = (sim.mbit(0, secs(20), secs(40)), sim.mbit(1, secs(20), secs(40)));
    assert!(first + second > 19.0, "合计 {}", first + second);
    assert!((0.7..1.4).contains(&(first / second)), "先开始的 {first}，后开始的 {second}");
    assert!(sim.mean_rtt(0, secs(20), secs(40)) < ms(70), "{:?}", sim.mean_rtt(0, secs(20), secs(40)));
}

#[test]
fn neither_starves_next_to_a_flow_that_backs_off_on_every_loss() {
    for bbr_first in [true, false] {
        let mut sim = Sim::new(Link::new(20, 50), 7);
        let (bbr, reno) = if bbr_first {
            let bbr = sim.add_bbr(App::Bulk, Duration::ZERO);
            (bbr, sim.add_flow(Box::new(Reno::new()), App::Bulk, secs(5)))
        } else {
            let reno = sim.add_flow(Box::new(Reno::new()), App::Bulk, Duration::ZERO);
            (sim.add_bbr(App::Bulk, secs(5)), reno)
        };
        sim.run(secs(40));
        let (ours, theirs) = (sim.mbit(bbr, secs(20), secs(40)), sim.mbit(reno, secs(20), secs(40)));
        assert!(ours > 4.0 && theirs > 4.0, "先开始的是 BBR：{bbr_first}；BBR {ours}，对照组 {theirs}");
        assert!(ours + theirs > 19.0);
    }
}

#[test]
fn persistent_congestion_starts_over_from_the_minimum_window() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    let now = feed(&mut bbr, start, ms(50), 500);
    assert!(bbr.bw.get().is_some() && bbr.window() > 10 * MTU);
    bbr.lost(now, now - ms(10), true, 20 * MTU);
    assert_eq!(bbr.state, State::Startup);
    assert_eq!(bbr.window(), MIN_WINDOW_PACKETS * MTU);
    assert_eq!((bbr.bw.get(), bbr.min_rtt.get(), bbr.inflight_hi), (None, None, None));
    // 之后照常从头估计。
    feed(&mut bbr, now + ms(1), ms(80), 300);
    assert_eq!(bbr.min_rtt.get(), Some(ms(80)));
    assert!(bbr.window() > MIN_WINDOW_PACKETS * MTU);
}

#[test]
fn the_persistent_loss_of_what_was_sent_while_the_path_was_down_does_not_start_over() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    let now = feed(&mut bbr, start, ms(50), 500);
    let (bw, floor) = (bbr.bw.get(), bbr.min_rtt.get());
    // 路断了两秒，这期间发出去的包没有回音。路恢复之后先到一批确认，库接着报告那期间发的包全丢了（持续拥塞）。
    bbr.sent(now, MTU);
    bbr.sent(now + secs(1), MTU);
    let back = now + secs(2);
    bbr.acked(back, now, MTU);
    bbr.end_acks(back, MTU, false);
    bbr.lost(back, now + secs(1), true, MTU);
    assert_eq!((bbr.bw.get(), bbr.min_rtt.get()), (bw, floor), "断路之前的估计留着");
    assert!(bbr.window() > 10 * MTU, "{}", bbr.window());
    // 路恢复之后发的包又持续丢失，照常从头开始。
    bbr.sent(back + ms(10), MTU);
    bbr.lost(back + secs(1), back + ms(10), true, MTU);
    assert_eq!(bbr.window(), MIN_WINDOW_PACKETS * MTU);
}

#[test]
fn slow_deliveries_paced_by_a_stale_library_rtt_do_not_lower_the_bandwidth_estimate() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    let mut now = feed(&mut bbr, start, ms(50), 500);
    let bw = bbr.bw.get().unwrap();
    // 断路之后库的平滑往返时间是 600ms，确认却 50ms 就到：库按 600ms 定的节奏每 100ms 才发一个包。比带宽滤波器的十轮多得多。
    bbr.pacing_rtt = Some(ms(600));
    for _ in 0..40 {
        bbr.sent(now, MTU);
        bbr.acked(now + ms(50), now, MTU);
        bbr.end_acks(now + ms(50), 0, false);
        now += ms(100);
    }
    assert_eq!(bbr.bw.get(), Some(bw), "量到的是库的发送节奏，不是路径");
    // 库的往返时间回到实际的值之后，同样慢的送达就是路径真的慢了。
    bbr.pacing_rtt = Some(ms(50));
    for _ in 0..40 {
        bbr.sent(now, MTU);
        bbr.acked(now + ms(50), now, MTU);
        bbr.end_acks(now + ms(50), 0, false);
        now += ms(100);
    }
    assert!(bbr.bw.get().unwrap() < bw / 10, "{:?}", bbr.bw.get());
}

#[test]
fn congestion_marks_without_lost_bytes_are_ignored() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    let now = feed(&mut bbr, start, ms(50), 500);
    let before = (bbr.state, bbr.window(), bbr.inflight_hi);
    bbr.lost(now, now - ms(10), false, 0);
    assert_eq!((bbr.state, bbr.window(), bbr.inflight_hi), before);
}

#[test]
fn the_initial_window_follows_the_mtu() {
    let mut bbr = new_bbr(Instant::now());
    Controller::on_mtu_update(&mut bbr, 1400);
    assert_eq!(Controller::initial_window(&bbr), 14_000);
    Controller::on_mtu_update(&mut bbr, 9000);
    assert_eq!(Controller::initial_window(&bbr), 18_000, "大包时初始窗口按 RFC 9002 封顶");
}

#[test]
fn a_cloned_controller_keeps_its_estimates() {
    let start = Instant::now();
    let mut bbr = new_bbr(start);
    feed(&mut bbr, start, ms(50), 500);
    let copy = Controller::clone_box(&bbr);
    assert_eq!(copy.window(), bbr.window());
}

#[test]
fn arithmetic_helpers_saturate_instead_of_overflowing() {
    assert_eq!(mul_div(u64::MAX, 3, 2), u64::MAX);
    assert_eq!(mul_div(10, 3, 0), 30, "除数为零时按一算，不 panic");
    assert_eq!(bytes_per_sec(1_000, ms(100)), 10_000);
    assert_eq!(bytes_in(10_000, ms(100)), 1_000);
    assert_eq!(bytes_per_sec(1, Duration::ZERO), NANOS_PER_SEC);
}

#[test]
fn cruise_lengths_are_spread_over_the_whole_range() {
    let mut rng = XorShift::new(0);
    let picks: Vec<u32> = (0..200).map(|_| rng.pick(CRUISE_ROUNDS)).collect();
    for rounds in CRUISE_ROUNDS {
        assert!(picks.contains(&rounds), "200 次里一次也没有取到 {rounds}");
    }
    assert!(picks.iter().all(|rounds| CRUISE_ROUNDS.contains(rounds)));
}
