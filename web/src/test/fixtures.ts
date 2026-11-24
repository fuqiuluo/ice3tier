import {
  type EnrollTokenInfo,
  type ExitSettings,
  type ExitView,
  type Forward,
  type MatrixEntry,
  type McpTokenInfo,
  type Node,
  type NodeUpdate,
  type PairView,
  type PeerLanes,
  type Route,
  type Status,
  type UpdateOverview,
} from '@/api/types'

/** 测试里用到的节点、controller 的情况：字段全的默认值，测试只写它关心的那几项。 */

export const IDLE_UPDATE: NodeUpdate = {
  self_update: { able: true, blocker: null },
  available: null,
  status: { state: 'idle' },
  ordered: null,
  waiting: null,
  failure: null,
}

export function makeUpdate(extra: Partial<NodeUpdate> = {}): NodeUpdate {
  return { ...IDLE_UPDATE, ...extra }
}

export function makeNode(id: number, name: string, extra: Partial<Node> = {}): Node {
  return {
    id,
    network: 1,
    key: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
    name,
    fqdn: `${name}.home.i3t`,
    virtual_ip: `10.66.0.${id}`,
    groups: [],
    declared: { exit: false, relay: false, forward: false },
    relay: null,
    exit: null,
    dial_out_only: false,
    routing: null,
    reach: null,
    pinned_relays: [],
    platform: 'linux-x86_64',
    version: '0.1.0',
    online: true,
    last_seen_at: 1_794_000_000,
    created_at: 1_794_000_000,
    netmap_version: 1,
    sent_version: 1,
    acked_version: 1,
    hostname: name,
    update: IDLE_UPDATE,
    attached: [],
    ...extra,
  }
}

export function makeStatus(extra: Partial<Status> = {}): Status {
  return {
    version: '0.1.0',
    controller_key: 'LltlBKa6eUXymVVonwneDvQzlnt_0z1jqdmwdPsruNY',
    public_addr: 'ctl.example.com:20331',
    networks: 1,
    nodes: 0,
    online: 0,
    newer_version: null,
    data_dir: '/var/lib/i3t-controller',
    ...extra,
  }
}

/** 还没有查到发布的更新现状。 */
export function makeOverview(extra: Partial<UpdateOverview> = {}): UpdateOverview {
  return {
    auto_update: true,
    source: 'https://github.com/fuqiuluo/ice3tier/releases',
    source_is_default: true,
    controller_version: '0.1.0',
    release: null,
    checked_at: null,
    check_error: null,
    paused: [],
    nodes: { total: 0, updating: 0, failed: 0, manual: 0, outdated: 0, up_to_date: 0 },
    ...extra,
  }
}

export const direct = (addr = '203.0.113.7:20330'): Route => ({ via: 'direct', addr })
export const viaRelays = (...relays: number[]): Route => ({ via: 'relay', relays })
export const noRoute: Route = { via: 'none' }

export function makeEntry(from: number, to: number, route: Route, extra: Partial<MatrixEntry> = {}): MatrixEntry {
  return { from, to, route, rtt_ms: 10, age_secs: 4, stale: false, ...extra }
}

/** 出口的默认设置，和 `PUT …/exit` 写 `{}` 时一样。 */
export function makeExitSettings(extra: Partial<ExitSettings> = {}): ExitSettings {
  return {
    ports: null,
    lan: false,
    upstream_socks5: null,
    quota_bytes: null,
    quota_reset_day: 1,
    family: 'any',
    connects_per_minute: null,
    class: null,
    ...extra,
  }
}

export function makeExitView(id: number, name: string, extra: Partial<ExitView> = {}): ExitView {
  return {
    node: { id, name, virtual_ip: `10.66.0.${id}` },
    online: true,
    settings: makeExitSettings(),
    health: 'ok',
    recent_requests: 0,
    recent_failures: 0,
    usage: null,
    reported_secs_ago: null,
    observed: [],
    ...extra,
  }
}

export function makeForward(id: number, name: string, extra: Partial<Forward> = {}): Forward {
  return {
    id,
    name,
    protocol: 'tcp',
    listen_node: 1,
    bind: '127.0.0.1:8080',
    target_node: 2,
    target_addr: '127.0.0.1:80',
    allow_from: [],
    enabled: true,
    status: 'active',
    class: null,
    listen: null,
    ...extra,
  }
}

export function makeToken(id: number, extra: Partial<EnrollTokenInfo> = {}): EnrollTokenInfo {
  return {
    id,
    network: 1,
    created_at: 1_794_000_000,
    expires_at: 1_794_086_400,
    groups: [],
    virtual_ip: null,
    successor_of: null,
    prefix: 'i3t-eyJzIjoiSmFY',
    state: 'pending',
    used_at: null,
    used_by: null,
    ...extra,
  }
}

/** 一个还能用的、不限网络的只读 MCP 令牌。 */
export function makeMcpToken(id: number, name: string, extra: Partial<McpTokenInfo> = {}): McpTokenInfo {
  return {
    id,
    jti: `jti-${id}`,
    name,
    scopes: ['read'],
    network: null,
    created_at: 1_794_000_000,
    expires_at: 1_796_592_000,
    revoked_at: null,
    state: 'active',
    ...extra,
  }
}

/** 一个节点上和一个对端之间的 ice3proxy：全是 0，测试只写它关心的那几项。 */
export function makePeerLanes(peer: number, extra: Partial<PeerLanes> = {}): PeerLanes {
  return {
    peer,
    dials: false,
    control: true,
    idle: 0,
    ready: 0,
    parked_at_peer: 0,
    in_use: 0,
    dialling: 0,
    claims: 0,
    claims_waited: 0,
    claim_wait_ms: 0,
    claims_failed: 0,
    fallbacks: 0,
    dial_failures: 0,
    refused: 0,
    sealed_bytes: 0,
    passthrough_bytes: 0,
    spliced_bytes: 0,
    ...extra,
  }
}

/** 一对节点的设置：默认是连接常驻、拥塞控制用节点的默认。 */
export function makePair(a: number, b: number, extra: Partial<PairView> = {}): PairView {
  return { a, b, keep_alive: true, congestion: null, ...extra }
}
