//! 主动测试和全网矩阵打印成给人看的样子。原因按代码写（`TestProblem::code`），不用 `message`：它只是给没有翻译的地方兜底。

use i3t_lang::table::Table;
use i3t_lang::{NONE, optional};
use i3t_model::admin::NodeRef;
use i3t_model::admin::diag::{
    CpuUse, DecisionView, DirectResult, HostResult, ItemState, MatrixRun, PathResult, TestProblem, TestView, ThroughputResult, Transfer,
};
use i3t_model::control::diag::{Choice, Hop, Latency};
use i3t_proto::NodeId;

use super::{Names, context, label};

/// 节点编号写成名字：测试的两端和矩阵里的节点按结果里记的名字（节点后来删了、改名了也还是当时的），别的（relay）按 `names`。
fn namer<'a>(nodes: &[&NodeRef], names: &'a Names) -> impl Fn(NodeId) -> String + use<'a> {
    let known: Vec<(NodeId, String)> = nodes.iter().map(|node| (node.id, node.name.clone())).collect();
    move |id| known.iter().find(|(known, _)| *known == id).map_or_else(|| names.of(id), |(_, name)| name.clone())
}

/// 一个原因：`nas：UDP 不通`。
fn problem_text(problem: &TestProblem, name: &dyn Fn(NodeId) -> String) -> String {
    let (_, lang, codes) = context();
    let said = (codes.test_code)(problem.code);
    match problem.node {
        Some(node) => lang.labelled(&name(node), said),
        None => said.to_owned(),
    }
}

fn mbps(transfer: Option<&Transfer>) -> String {
    let (_, lang, _) = context();
    transfer.and_then(|transfer| transfer.bits_per_second).map_or_else(|| NONE.to_owned(), |rate| lang.mbps(rate))
}

fn route_text(path: &PathResult, name: &dyn Fn(NodeId) -> String) -> String {
    let (_, _, codes) = context();
    path.route.as_ref().map_or_else(|| NONE.to_owned(), |route| (codes.route)(route, name))
}

pub fn test(view: &TestView, names: &Names) {
    let (t, lang, codes) = context();
    let name = namer(&[&view.a, &view.b], names);
    let items = lang.list(view.request.items.iter().map(label));
    let throughput = if view.request.throughput { format!(" + {}", t.throughput) } else { String::new() };
    println!(
        "{} #{}  {} → {}  {}  {}  {items}{throughput}",
        t.test,
        view.id,
        view.a.name,
        view.b.name,
        (codes.test_state)(view.state),
        lang.time(view.started_at)
    );
    if let Some(error) = &view.error {
        println!("{}", lang.labelled(t.test_failed, &problem_text(error, &name)));
    }
    if let Some(direct) = &view.direct {
        direct_lines(direct, &name);
    }
    let paths: Vec<&PathResult> = view.direct_quality.iter().chain(&view.relay_quality).collect();
    if !paths.is_empty() {
        println!("\n{}", t.path_quality);
        let mut rows = Table::new(&t.quality_header).indented(2);
        for path in &paths {
            let latency = path.latency.unwrap_or_default();
            let ms = |value: Option<u32>| value.map_or_else(|| NONE.to_owned(), |us| lang.millis(u64::from(us)));
            let state = match &path.problem {
                Some(problem) => lang.labelled((codes.item_state)(path.state), &problem_text(problem, &name)),
                None => (codes.item_state)(path.state).to_owned(),
            };
            rows.row(vec![
                route_text(path, &name),
                lang.list(path.picked_by.iter().map(|pick| (codes.path_pick)(*pick))),
                path.latency.map_or_else(|| NONE.to_owned(), |latency| format!("{}/{}", latency.answered, latency.probes)),
                path.latency.map_or_else(|| NONE.to_owned(), |latency| lang.percent(latency.loss_permille)),
                optional(latency.loss_up_permille.map(|loss| lang.percent(loss))),
                optional(latency.loss_down_permille.map(|loss| lang.percent(loss))),
                ms(latency.min_us),
                ms(latency.avg_us),
                ms(latency.p95_us),
                ms(latency.jitter_us),
                path.cost_us.map_or_else(|| NONE.to_owned(), |cost| lang.millis(cost)),
                state,
            ]);
        }
        rows.print();
        for path in &paths {
            hop_lines(path, &name);
            reverse_note(path.latency.as_ref());
        }
        throughput_lines(&paths, &name);
    }
    if let Some(route) = &view.route {
        println!("\n{}", lang.paren(t.mode_choices, (codes.item_state)(route.state)));
        let mut rows = Table::new(&t.choices_header).indented(2);
        for decision in [&route.forward, &route.reverse].into_iter().flatten() {
            rows.row(decision_row(decision, &name));
        }
        rows.print();
        if let Some(problem) = &route.problem {
            println!("  {}", problem_text(problem, &name));
        }
    }
    if let Some(hosts) = &view.hosts {
        host_lines(hosts, &name);
    }
    for note in &view.notes {
        println!("{}", lang.labelled(t.note, &problem_text(note, &name)));
    }
}

/// 展示两端主机状态及各自到对端的连接信息；无法获取的字段以 `-` 表示。
fn host_lines(hosts: &[HostResult], name: &dyn Fn(NodeId) -> String) {
    let (t, lang, codes) = context();
    let cpu =
        |used: Option<CpuUse>| used.map_or_else(|| NONE.to_owned(), |used| format!("{}% / {}%", used.system_percent, used.process_percent));
    println!("\n{}", t.hosts_title);
    let mut rows = Table::new(&t.hosts_header).indented(2);
    for host in hosts {
        let report = &host.report;
        let system = report.system.as_ref();
        let described = system
            .map(|system| lang.list([system.os.as_deref(), system.kernel.as_deref(), Some(system.arch.as_str())].into_iter().flatten()));
        let load = report.load_x100.map(|loads| loads.map(|load| format!("{}.{:02}", load / 100, load % 100)).join(" "));
        let memory = report.memory.map(|memory| format!("{} / {}", lang.bytes(memory.available_bytes), lang.bytes(memory.total_bytes)));
        let process = report.process.map(|process| {
            let resident = report.memory.map_or_else(|| NONE.to_owned(), |memory| lang.bytes(memory.process_rss_bytes));
            (t.host_process)(&resident, process.threads, &lang.duration(process.uptime_secs))
        });
        // 当该端尚无主机信息时（尚未上报、版本过旧或上报失败），在系统列显示原因。
        let state = match &host.problem {
            Some(problem) => lang.labelled((codes.item_state)(host.state), &problem_text(problem, name)),
            None => (codes.item_state)(host.state).to_owned(),
        };
        rows.row(vec![
            name(host.node),
            described.unwrap_or(state),
            optional(system.map(|system| system.cores)),
            cpu(report.cpu),
            cpu(report.cpu_peak),
            optional(load),
            optional(memory),
            optional(process),
            optional(report.connections.as_ref().map(t.host_connections)),
        ]);
    }
    rows.print();
    println!("  {}", t.cpu_note);

    println!("\n{}", t.peer_connection_title);
    let mut rows = Table::new(&t.peer_connection_header).indented(2);
    for host in hosts {
        let Some(connection) = &host.report.to_peer else {
            let mut row = vec![NONE.to_owned(); t.peer_connection_header.len()];
            row[0] = name(host.node);
            row[1] = if host.state == ItemState::Done { t.no_connection.to_owned() } else { (codes.item_state)(host.state).to_owned() };
            rows.row(row);
            continue;
        };
        // 丢了的包占发出去的千分之几。
        let lost = connection
            .lost_packets
            .saturating_mul(1000)
            .checked_div(connection.sent_packets)
            .map(|lost| u16::try_from(lost).unwrap_or(1000));
        rows.row(vec![
            name(host.node),
            (codes.route)(&connection.route, name),
            lang.millis(u64::from(connection.rtt_us)),
            optional(connection.min_rtt_us.map(|rtt| lang.millis(u64::from(rtt)))),
            lang.bytes(connection.cwnd_bytes),
            connection.mtu.to_string(),
            connection.congestion.clone(),
            connection.sent_packets.to_string(),
            connection.lost_packets.to_string(),
            optional(lost.map(|lost| lang.percent(lost))),
            format!("{} / {}", lang.bytes(connection.bytes_sent), lang.bytes(connection.bytes_received)),
            lang.duration(connection.age_secs),
        ]);
    }
    rows.print();
}

fn direct_lines(direct: &DirectResult, name: &dyn Fn(NodeId) -> String) {
    let (t, lang, codes) = context();
    let kind = || optional(direct.kind.map(codes.direct_kind));
    let verdict = match (direct.state, direct.ok) {
        (ItemState::Done, true) if direct.already => lang.paren(t.yes, &lang.labelled(t.already_direct, &kind())),
        (ItemState::Done, true) => lang.paren(t.yes, &lang.list([kind(), format!("{} ms", optional(direct.elapsed_ms))])),
        (ItemState::Done, false) => t.no.to_owned(),
        (state, _) => (codes.item_state)(state).to_owned(),
    };
    println!("\n{}", lang.labelled(t.direct_capability, &verdict));
    if let Some(problem) = &direct.problem {
        println!("  {}", lang.labelled(t.reason, &problem_text(problem, name)));
    }
    for side in &direct.sides {
        let view = &side.side;
        let udp = view.udp.map_or(NONE, |udp| if udp { t.yes } else { t.no });
        let connected = if view.ok { t.connected } else { t.not_connected };
        let connected = view.failure.map_or_else(|| connected.to_owned(), |code| lang.paren(connected, (codes.test_code)(code)));
        println!("  {}", lang.labelled(&name(side.node), &(t.direct_side)(&connected, udp, view.candidates)));
    }
}

/// 经 relay 的路径上每一段的延迟，和它从哪里来。
fn hop_lines(path: &PathResult, name: &dyn Fn(NodeId) -> String) {
    let (_, lang, _) = context();
    if path.hops.len() < 2 {
        return;
    }
    let hops: Vec<String> = path.hops.iter().map(|hop| hop_text(hop, name)).collect();
    println!("  {}", lang.labelled(&route_text(path, name), &hops.join("; ")));
}

fn hop_text(hop: &Hop, name: &dyn Fn(NodeId) -> String) -> String {
    let (_, lang, codes) = context();
    let rtt = hop.rtt_us.map_or_else(|| NONE.to_owned(), |us| format!("{} ms", lang.millis(u64::from(us))));
    let loss = hop.loss_permille.map(|loss| format!(" {}%", lang.percent(loss))).unwrap_or_default();
    format!("{}→{} {rtt}{loss} ({})", name(hop.from), name(hop.to), (codes.hop_source)(hop.source))
}

/// 回答没有全部沿原路回来时说一声：那时回程走的是对端自己的路。
fn reverse_note(latency: Option<&Latency>) {
    let (t, _, _) = context();
    if let Some(latency) = latency.filter(|latency| latency.answered > 0 && latency.same_path < latency.answered) {
        println!("  {}", (t.other_way_back)(latency.answered - latency.same_path, latency.answered));
    }
}

fn throughput_lines(paths: &[&PathResult], name: &dyn Fn(NodeId) -> String) {
    let (t, lang, codes) = context();
    let measured: Vec<(&PathResult, &ThroughputResult)> =
        paths.iter().filter_map(|path| path.throughput.as_ref().map(|throughput| (*path, throughput))).collect();
    if measured.is_empty() {
        return;
    }
    println!("\n{}", t.throughput_title);
    let mut rows = Table::new(&t.throughput_header).indented(2);
    for (path, throughput) in &measured {
        let result = &throughput.measured;
        let size = |transfer: Option<&Transfer>| transfer.map_or_else(|| NONE.to_owned(), |transfer| lang.bytes(transfer.bytes));
        let state = match &throughput.problem {
            Some(problem) => lang.labelled((codes.item_state)(throughput.state), &problem_text(problem, name)),
            None => (codes.item_state)(throughput.state).to_owned(),
        };
        rows.row(vec![
            route_text(path, name),
            mbps(result.up.as_ref()),
            size(result.up.as_ref()),
            optional(result.up.map(|transfer| transfer.ms)),
            mbps(result.down.as_ref()),
            size(result.down.as_ref()),
            optional(result.down.map(|transfer| transfer.ms)),
            if result.pinned { t.yes } else { t.no }.to_owned(),
            state,
        ]);
    }
    rows.print();
    if let Some((_, throughput)) = measured.iter().find(|(_, throughput)| !throughput.measured.congestion.is_empty()) {
        let result = &throughput.measured;
        println!("  {}", (t.throughput_note)(&result.transport, &result.congestion, &lang.bytes(result.limit_bytes), result.limit_ms));
    }
}

fn choice_text(choice: &Choice, name: &dyn Fn(NodeId) -> String) -> String {
    let (t, lang, codes) = context();
    let route =
        choice.route.as_ref().map_or_else(|| (codes.route)(&i3t_model::control::Route::None, name), |route| (codes.route)(route, name));
    let cost = choice.cost_us.map(|cost| format!(", {} ms", lang.millis(cost))).unwrap_or_default();
    let cheaper = choice
        .cheaper
        .as_ref()
        .map(|cheaper| (t.cheaper_path)(&(codes.route)(&cheaper.route, name), &lang.millis(cheaper.cost_us)))
        .unwrap_or_default();
    lang.paren(&route, &format!("{}{cost}{cheaper}", (codes.choice)(choice.reason)))
}

fn decision_row(decision: &DecisionView, name: &dyn Fn(NodeId) -> String) -> Vec<String> {
    let (_, _, codes) = context();
    vec![
        format!("{} → {}", name(decision.from), name(decision.to)),
        optional(decision.mode.as_ref().map(label)),
        decision.current.as_ref().map_or_else(|| NONE.to_owned(), |route| (codes.route)(route, name)),
        choice_text(&decision.direct_first, name),
        choice_text(&decision.lowest_cost, name),
    ]
}

pub fn tests(views: &[TestView]) {
    let (t, lang, codes) = context();
    let mut rows = Table::new(&t.tests_header);
    for view in views {
        let direct = view.direct.as_ref().map_or_else(
            || NONE.to_owned(),
            |direct| match direct.state {
                ItemState::Done if direct.ok => optional(direct.kind.map(codes.direct_kind)),
                ItemState::Done => t.no.to_owned(),
                state => (codes.item_state)(state).to_owned(),
            },
        );
        let latency =
            view.direct_quality.iter().chain(&view.relay_quality).find_map(|path| path.latency.and_then(|latency| latency.avg_us));
        let throughput = if view.request.throughput { format!(" + {}", t.throughput) } else { String::new() };
        rows.row(vec![
            view.id.to_string(),
            view.a.name.clone(),
            view.b.name.clone(),
            (codes.test_state)(view.state).to_owned(),
            lang.time(view.started_at),
            direct,
            latency.map_or_else(|| NONE.to_owned(), |us| lang.millis(u64::from(us))),
            format!("{}{throughput}", lang.list(view.request.items.iter().map(label))),
        ]);
    }
    if rows.is_empty() { println!("{}", t.no_tests) } else { rows.print() }
}

pub fn matrix(run: &MatrixRun, names: &Names) {
    let (t, lang, codes) = context();
    let nodes: Vec<&NodeRef> = run.nodes.iter().collect();
    let name = namer(&nodes, names);
    println!(
        "{} #{}  {}  {}  {}",
        t.matrix,
        run.id,
        (codes.matrix_state)(run.state),
        (t.matrix_progress)(run.finished, run.total, run.concurrency),
        lang.time(run.started_at)
    );
    let mut rows = Table::new(&t.cells_header);
    for cell in &run.cells {
        let direct = match cell.direct_ok {
            Some(true) => optional(cell.direct_kind.map(codes.direct_kind)),
            Some(false) => t.no.to_owned(),
            None => NONE.to_owned(),
        };
        let state = match &cell.problem {
            Some(problem) => lang.labelled((codes.cell_state)(cell.state), &problem_text(problem, &name)),
            None => (codes.cell_state)(cell.state).to_owned(),
        };
        rows.row(vec![
            format!("{} ↔ {}", name(cell.a), name(cell.b)),
            optional(cell.test),
            direct,
            optional(cell.direct_elapsed_ms),
            cell.route.as_ref().map_or_else(|| NONE.to_owned(), |route| (codes.route)(route, &name)),
            cell.latency.and_then(|latency| latency.avg_us).map_or_else(|| NONE.to_owned(), |us| lang.millis(u64::from(us))),
            cell.latency.map_or_else(|| NONE.to_owned(), |latency| lang.percent(latency.loss_permille)),
            state,
        ]);
    }
    rows.print();
}

#[cfg(test)]
mod tests {
    use i3t_model::control::diag::TestCode;

    use super::*;

    #[test]
    fn a_choice_that_stays_on_the_current_path_shows_the_cheaper_one_with_both_costs() {
        let name = |id: NodeId| format!("n{id}");
        let choice = Choice {
            route: Some(i3t_model::control::Route::Direct { addr: "203.0.113.7:20330".parse().unwrap() }),
            reason: i3t_model::control::diag::ChoiceCode::WithinMargin,
            cost_us: Some(74_300),
            cheaper: Some(i3t_model::control::diag::CheaperPath {
                route: i3t_model::control::Route::Relay { relays: vec![NodeId::new(3).unwrap()] },
                cost_us: 74_100,
            }),
        };
        let text = choice_text(&choice, &name);
        assert!(text.contains("74.3") && text.contains("74.1") && text.contains("n3"), "{text}");
        let plain = choice_text(&Choice { cheaper: None, ..choice }, &name);
        assert!(!plain.contains("n3"), "{plain}");
    }

    #[test]
    fn a_problem_names_the_node_and_reads_from_its_code() {
        let name = |id: NodeId| format!("n{id}");
        let problem = TestProblem::new(TestCode::UdpBlocked, NodeId::new(2));
        let text = problem_text(&problem, &name);
        assert!(text.starts_with("n2") && text.contains("UDP"), "{text}");
        let transfer = Transfer {
            bytes: 20_000_000,
            ms: 4000,
            bits_per_second: Some(40_123_456),
            stopped_by: i3t_model::control::diag::TransferEnd::Bytes,
        };
        assert_eq!(mbps(Some(&transfer)), "40.1");
        assert_eq!(mbps(None), NONE);
    }
}
