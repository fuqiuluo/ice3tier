/**
 * 管理 API 的数据结构。手写，和 `crates/i3t-model/src/admin.rs` 一一对应。
 *
 * 约定：时间是 Unix 秒；应答里的字段总是全的，没有值写 `null`；请求里标了"可省略"的字段可以不写。
 * 名字以 `Create`、`Update` 开头或以 `Input` 结尾的是请求体，其余是应答体。
 */

/** Unix 秒。 */
export type Timestamp = number

export type NetworkId = number
export type NodeId = number
/** 分组的编号在整个 controller 里唯一，删掉之后不复用。 */
export type GroupId = number

/** 43 个字符的 base64url。 */
export type PublicKey = string

/** 语义化版本号：`主.次.修订`，预发布版后面跟 `-标识`，例如 `0.3.0-rc.1`。 */
export type Version = string

export type RoutingMode = 'direct_first' | 'lowest_cost'
export type Reach = 'any' | 'direct_only' | 'relay_only'
export type Direction = 'both' | 'one_way'
export type ForwardProtocol = 'tcp' | 'udp'

/**
 * 服务等级（`Network.class`）。一条流的等级按这个顺序取第一个有的：代理用户名里的 `+c-` 标记、
 * 监听器（或端口转发）的、出口的（只有经出口出去的流）、网络的；都没有时是 `auto`。
 */
export type ServiceClass = 'auto' | 'interactive' | 'reliable' | 'bulk'

/** 出口连互联网目标时只用哪一种地址。 */
export type IpFamily = 'any' | 'ipv4' | 'ipv6'

/** 管理 API 的错误码。以后可能增加，所以收到的值按字符串处理，不认识的按 HTTP 状态显示。 */
export type KnownErrorCode =
  | 'unauthorized'
  | 'not_found'
  | 'invalid_request'
  | 'address_out_of_range'
  | 'name_taken'
  | 'name_cooling_down'
  | 'address_taken'
  | 'address_cooling_down'
  | 'range_overlaps'
  | 'range_exhausted'
  | 'range_not_superset'
  | 'network_not_empty'
  | 'not_declared'
  /** 0.1.11 起：要启用的转发指向的目标节点没有打开"可作为端口转发的目标"。 */
  | 'forward_target_off'
  | 'predecessor_online'
  | 'conflict'
  | 'node_offline'
  | 'cannot_self_update'
  | 'no_update'
  /** 同一对节点刚测过 / 正在测，或者矩阵正在跑。 */
  | 'too_soon'
  | 'busy'
  /** 代理（新的 `/proxies`）：出口没打开、出口就是入口、策略不允许入口访问出口、用户名和密码只填了一个。 */
  | 'exit_not_enabled'
  | 'exit_is_node'
  | 'access_denied'
  | 'credentials_incomplete'
  | 'internal'

export interface ErrorBody {
  error: {
    code: string
    message: string
    /** 比 `code` 更具体的一层：找不到的东西、哪里不对。说不出来、或者 controller 比这个字段旧时是 `null` 或没有。 */
    what?: string | null
    /** 请求里出问题的那一项；分组编号的列表里是 `groups[序号]`。 */
    field?: string | null
  }
}

export interface NodeRef {
  id: NodeId
  name: string
  virtual_ip: string
}

/** 指代一个分组：编号和它现在的名字。节点、注册令牌的 `groups`，规则的 `src`、`dst` 用它。 */
export interface GroupRef {
  id: GroupId
  name: string
  /** 是不是内置的 `All`。比 0.1.8 旧的 controller 不给，这时按名字认（`isAllGroup`）。 */
  builtin?: boolean
}

export interface Status {
  version: string
  controller_key: PublicKey
  public_addr: string
  networks: number
  nodes: number
  online: number
  /** 已知的最新正式版比 controller 自己新时是那个版本号，否则 `null`。controller 不会自己更新。 */
  newer_version: Version | null
  /** controller 的数据目录，备份时拷贝它。不是从数据目录打开的（只在测试里）时是 `null`。 */
  data_dir: string | null
}

/** 操作记录能指向的东西。以后可能增加，不认识的种类界面忽略。 */
export type LogRefKind = 'network' | 'node' | 'group' | 'token' | 'rule' | 'credential' | 'proxy' | 'forward'

export interface LogRef {
  /** 一般是 {@link LogRefKind} 之一；比这个界面新的 controller 可能写别的。 */
  kind: string
  /** 东西后来被删掉了，编号还在。 */
  id: number
}

export interface LogEntry {
  id: number
  at: Timestamp
  network: NetworkId | null
  action: string
  detail: string
  /** 这条记录说的是哪些东西。这个字段出现之前的记录是 `[]`。 */
  refs: LogRef[]
}

/** `GET /log` 的查询参数，都可省略；几个条件同时写时要都满足。 */
export interface LogQuery {
  /** 默认 100，上限 1000。 */
  limit?: number
  /** 只要编号比它小的：翻页时写上一页最后一条的 `id`。 */
  before?: number
  network?: NetworkId
  /** 这种操作，或者以它加一个点开头的操作：`node` 包括 `node.relay.enable`。 */
  action?: string
  /** `<种类>:<编号>`，例如 `node:3`。 */
  ref?: string
}

export interface Network {
  id: NetworkId
  name: string
  domain: string
  cidr: string
  routing: RoutingMode
  max_relay_hops: number
  reach: Reach
  created_at: Timestamp
  nodes: number
  /** 网络的默认服务等级；`null` 表示 `auto`。 */
  class: ServiceClass | null
  /** 节点之间的连接上，请对端攒到多于这么多个包才单独发一个确认包。 */
  ack_eliciting_threshold: number
  /** 没攒够时，对端最多等多少毫秒就发确认。 */
  max_ack_delay_ms: number
  /** 节点直连时把同时要发给同一个节点的几个小包合成一个包发。比这个字段旧的 controller 不给：那时没有这项设置。 */
  bundle_small_packets?: boolean
  /** 节点的虚拟网卡和内核之间一大块一大块地交接数据（Linux 的分段卸载）。比这个字段旧的 controller 不给。 */
  vnet_offload?: boolean
  /** 节点的虚拟网卡默认的 MTU（字节）；本机另外设了的节点用本机的。比这个字段旧的 controller 不给。 */
  vnet_mtu?: number
  /** 各项设置的默认值；比这个字段旧的 controller 不给，这时说不出哪些设置改过。 */
  defaults?: NetworkDefaults | null
}

/** 网络各项设置的默认值：按它标出哪些设置改过，恢复默认就是把它写回去。 */
export interface NetworkDefaults {
  routing: RoutingMode
  max_relay_hops: number
  reach: Reach
  /** `null` 表示 `auto`。 */
  class: ServiceClass | null
  ack_eliciting_threshold: number
  max_ack_delay_ms: number
  bundle_small_packets?: boolean
  vnet_offload?: boolean
  vnet_mtu?: number
}

export interface CreateNetwork {
  name: string
  cidr?: string
  routing?: RoutingMode
  max_relay_hops?: number
  reach?: Reach
  class?: ServiceClass | null
  ack_eliciting_threshold?: number
  max_ack_delay_ms?: number
  bundle_small_packets?: boolean
  vnet_offload?: boolean
  vnet_mtu?: number
}

export interface UpdateNetwork {
  cidr?: string
  routing?: RoutingMode
  max_relay_hops?: number
  reach?: Reach
  /** 写 `null` 表示改回 `auto`。 */
  class?: ServiceClass | null
  /** 这两项只对改了之后新建立的连接生效。 */
  ack_eliciting_threshold?: number
  max_ack_delay_ms?: number
  /** 节点收到新的设置就生效。 */
  bundle_small_packets?: boolean
  /** 这两项节点收到之后自己把虚拟网卡重装一遍。 */
  vnet_offload?: boolean
  vnet_mtu?: number
}

export interface NodePair {
  a: NodeRef
  b: NodeRef
}

export interface Overview {
  network: NetworkId
  nodes: number
  online: number
  relays: number
  exits: number
  rules: number
  /** 代理的个数（替代原来的监听器和凭据）。 */
  proxies: number
  forwards: number
  pending_tokens: number
  online_nodes: NodeRef[]
  unreachable_pairs: NodePair[]
  /** 在线节点最近一次上报的活跃流之和。一条流两端的节点各报一次，所以算了两次。 */
  flows: number
  /** 在线节点最近一次上报的流量之和（各自启动以来）。经过两个节点的流量两边各算一次。 */
  tx_bytes: number
  rx_bytes: number
}

export interface Declared {
  exit: boolean
  relay: boolean
  /** 0.1.11 起没有了：端口转发的目标改由管理员在界面上打开（`Node.forward_target`），不用节点声明。 */
  forward?: boolean
}

/** 中继的一个地址从哪里来：节点上声明的、controller 看到的、节点网卡上的。`unknown` 是更新的 controller 才有的取值。 */
export type RelayAddressSource = 'declared' | 'observed' | 'local' | 'unknown'

export interface RelayAddress {
  /** `地址:端口`，UDP 和 TCP 都用。 */
  address: string
  source: RelayAddressSource
}

/**
 * 中继（0.1.10 起是 `RelayView`）：地址由 controller 找出来，只读，按节点去试的顺序；还不知道任何地址时是 `[]`。
 * 比 0.1.10 旧的 controller 给的是人填的 `udp`、`tcp` 两组，用 `relayAddresses` 读，两种都认。
 */
export interface RelaySettings {
  addresses?: RelayAddress[]
  /** 0.1.10 之前。 */
  udp?: string[]
  /** 0.1.10 之前。 */
  tcp?: string[]
  bandwidth_mbps: number | null
}

export interface RelayInput {
  /** 0.1.10 之前的 controller 要地址才能启用；新的照收、不用。界面交的是 controller 看到的那个。 */
  udp?: string[]
  tcp?: string[]
  bandwidth_mbps?: number | null
}

/** controller 从自己这边试连一个 relay 地址的结果。只是参考：它和节点不在同一个网络位置上。 */
export interface Reachability {
  protocol: 'udp' | 'tcp'
  addr: string
  reachable: boolean
  /** UDP 是地址查询的往返时间，TCP 是建连接的时间；不通是 `null`。 */
  rtt_ms: number | null
  /** 不通的原因；通是 `null`。 */
  error: string | null
}

export interface ExitSettings {
  /** `null` 表示不限制端口。 */
  ports: number[] | null
  lan: boolean
  upstream_socks5: string | null
  /** 每个账期的流量配额（字节），两个方向相加；`null` 表示不限。 */
  quota_bytes: number | null
  /** 账期从每个月的哪一天开始（UTC 的 0 点），1 到 28。 */
  quota_reset_day: number
  family: IpFamily
  /** 同一个发起节点每分钟最多让出口向同一个目标新建多少条连接；`null` 表示不限。 */
  connects_per_minute: number | null
  /** 经这个出口的流的默认服务等级；`null` 表示没有，看网络的。 */
  class: ServiceClass | null
}

export interface ExitInput {
  /** `null` 表示不限制（省略时也是，0.1.9 起；更早的 controller 省略时是 `[80, 443]`，所以界面总是写上）。 */
  ports?: number[] | null
  lan?: boolean
  upstream_socks5?: string | null
  /** 配额、建连预算都不能写 0：不限制就写 `null` 或者不写。出口没有带宽上限（用户决定去掉了）。 */
  quota_bytes?: number | null
  quota_reset_day?: number
  family?: IpFamily
  connects_per_minute?: number | null
  class?: ServiceClass | null
}

export interface Node {
  id: NodeId
  network: NetworkId
  key: PublicKey
  name: string
  fqdn: string
  virtual_ip: string
  /** 它所在的分组，按名字排。内置的 `All` 不列出：每个节点都在里面。 */
  groups: GroupRef[]
  declared: Declared
  /** 0.1.11 起：管理员打开了"可作为端口转发的目标"。更早的 controller 没有这个字段，看 `declared.forward`。 */
  forward_target?: boolean
  relay: RelaySettings | null
  exit: ExitSettings | null
  dial_out_only: boolean
  routing: RoutingMode | null
  reach: Reach | null
  pinned_relays: NodeId[]
  platform: string
  version: string
  online: boolean
  last_seen_at: Timestamp | null
  created_at: Timestamp
  netmap_version: number
  sent_version: number
  acked_version: number
  /** 节点上报的主机名，原样；旧版本的节点不报，是 `""`。主机名后来变了，`name` 不跟着变。 */
  hostname: string
  update: NodeUpdate
  /** 0.1.12 起：这个节点自己的自动更新开关，默认开。全局的开关也开着时它才会被自动更新。更早的 controller 没有这个字段。 */
  auto_update?: boolean
  /** 节点挂靠的 relay 和到它们的往返延迟，取自它最近的上报；离线时是它离线前报的。 */
  attached: Attachment[]
  /**
   * 节点公网地址所在的国家或地区，ISO 3166-1 的两个大写字母（`"JP"`）。controller 用离线的地址库查；
   * 不知道（内网地址、从没连上过、库里没有）是 `null`。比这个界面旧的 controller 没有这个字段。
   */
  country?: string | null
  /**
   * 0.1.11 起：节点出去上网用的公网 IP（`country` 按它算）。controller 只从内网地址看到过它时是 `null`。
   * 比这个界面旧的 controller 没有这个字段，看 `observed_endpoint`。
   */
  egress_ip?: string | null
  /**
   * 0.1.19 起：controller 认定这个节点用不了 UDP（连上的中继都只经 TCP，持续了两分钟）。
   * 它和别的节点之间的 TCP 连接因此走 ice3proxy。更早的 controller 没有这个字段，按 `false` 算。
   */
  no_udp?: boolean
}

export interface Attachment {
  relay: NodeId
  rtt_ms: number
}

/** 启用（或修改）relay 的应答：节点，加上 controller 从自己这边试连填的每个地址的结果。 */
export interface RelayEnabled extends Node {
  reachability: Reachability[]
}

export interface NodeDetail extends Node {
  endpoints: string[]
  observed_endpoint: string | null
  mapping_varies: boolean | null
  flows: number
  tx_bytes: number
  rx_bytes: number
  /** ice3proxy 的状况。不在线、版本太旧没有报、还没有上报过是 `null`；比界面旧的 controller 不写。 */
  lanes?: LaneReport | null
  /** 0.1.11 起，这个节点是中继时：各个节点连它连得上没有、用的什么。不是中继时是 `null`。 */
  reached_by?: ReachEntry[] | null
  /** 节点最近一次上报是多少秒之前；`lanes`、`flows`、流量、`mapping_varies` 都是那一次报的。没报过、不在线是 `null`。 */
  reported_secs_ago?: number | null
  /** 节点实际在用的性能档位。不在线、版本太旧、还没报过是 `null`。 */
  performance?: PerformanceReport | null
  /**
   * 0.1.26 起：虚拟网卡的状况（取代了透明访问的 `intercept`）。不在线、版本太旧没有报、还没上报过是 `null`
   * （界面写"未知"，不当成关着）；节点本机关着时是 `{ state: 'off', … }`。
   */
  vnet?: VnetReport | null
}

/** 虚拟网卡的原因。比界面新的节点可能报别的 `code`，界面写"原因不明"。 */
export type VnetCause =
  /**
   * `missing`：缺的东西，现在总是一项。Linux 上是能力的名字（`CAP_NET_ADMIN`；名字服务绑不上 53 端口时是
   * `CAP_NET_BIND_SERVICE`），Windows 上是 `Administrator`，macOS 上是 `root`。
   */
  | { code: 'no_permission'; missing: string[] }
  /** 打不开 `/dev/net/tun`，容器里常见。 */
  | { code: 'no_device'; detail: string }
  /** Windows：程序旁边没有 `wintun.dll`。 */
  | { code: 'driver_missing'; path: string }
  | { code: 'device_failed'; detail: string }
  | { code: 'program_missing'; program: string }
  | { code: 'command_failed'; program: string; detail: string }
  | { code: 'port_in_use'; address: string }
  | { code: 'bind_failed'; address: string; detail: string }
  /** 网络的地址段和本机的一个真实网络重叠；`with` 是 `ip` 的写法，例如 `192.168.1.5/24 dev eth0`。 */
  | { code: 'range_in_use'; with: string }

/** 程序加的一条防火墙规则。不认识的 `state` 当作未知。 */
export type RuleState =
  { state: 'on' } | { state: 'off' } | { state: 'failed'; cause: VnetCause } | { state: 'unsupported' }

/** 名字怎么解析：systemd-resolved 直接用；没有它时写进 hosts（`i3t hosts --apply`）；名字服务没开起来。 */
export type NameService = { state: 'resolved' } | { state: 'no_resolver' } | { state: 'failed'; cause: VnetCause }

export interface VnetDrops {
  /** 对端发来的包来源不是它自己的虚拟 IP。 */
  bad_source: number
  /** 目的不是本节点。 */
  bad_destination: number
  /** 访问策略不允许对端访问本节点。 */
  not_allowed: number
  /** 本机发出的送不到：不是节点的地址、没有网卡或连不上的节点。 */
  unreachable: number
  /** 读不懂、分片拼不起来，或者是不该被切开的包（TCP、ICMP 差错报文）。 */
  malformed: number
}

export interface VnetReport {
  /** `installed` 带 `device`、`mtu`、`names`；`failed` 带 `cause`。不认识的当作未知。 */
  state: 'installed' | 'off' | 'failed' | 'unsupported'
  device?: string
  mtu?: number
  names?: NameService
  cause?: VnetCause
  /** `accept`：从网卡进来的放行；`guard`：防冒充（自称来自地址段、却不是从网卡进来的丢掉，只有 Linux 加）。 */
  firewall: { accept: RuleState; guard: RuleState }
  sent_packets: number
  sent_bytes: number
  received_packets: number
  received_bytes: number
  dropped: VnetDrops
}

export interface PerformanceReport {
  /** `"balanced"` 之类；不认识的照样显示。 */
  profile: string
  threads: number
  /** 档位换了，线程数要等节点重启才变。 */
  restart_pending: boolean
  overrides: string[]
}

export interface ReachEntry {
  node: NodeRef
  online: boolean
  /** `tcp`：UDP 连不上，TCP 连得上。不认识的当作 `unknown`。 */
  outcome: 'udp' | 'tcp' | 'unreached' | 'unknown'
  at: Timestamp
}

export interface UpdateNode {
  name?: string
  /** 整个替换节点所在的分组：已有分组的编号。`[]` 表示只在 `All` 里。 */
  groups?: GroupId[]
  virtual_ip?: string
  dial_out_only?: boolean
  /** 写 `null` 表示改回用网络的默认值。 */
  routing?: RoutingMode | null
  /** 写 `null` 表示改回用网络的默认值。 */
  reach?: Reach | null
  pinned_relays?: NodeId[]
  /** 0.1.11 起：打开或关掉"可作为端口转发的目标"。 */
  forward_target?: boolean
  /** 0.1.12 起：打开或关掉这个节点的自动更新。 */
  auto_update?: boolean
}

export interface Succeed {
  predecessor: NodeId
}

export type Route = { via: 'none' } | { via: 'direct'; addr: string } | { via: 'relay'; relays: NodeId[] }

/**
 * 直连是怎么建立起来的：同一个局域网、对端的 IPv6 地址、对端的地址本来就连得上（公网地址、端口转发、端口映射）、
 * 打洞打通的。`unknown` 是比 controller 新的节点报的类型。
 */
export type DirectKind = 'lan' | 'ipv6' | 'reachable' | 'punched' | 'unknown'

/** 经 relay 时，到第一个 relay 的那一段走的传输。TCP 是 UDP 用不了时的退路。 */
export type LegTransport = 'udp' | 'tcp' | 'unknown'

/**
 * 每条路的细节。controller 的文档说它们总是写出来、不知道时是 `null`；
 * 比这个界面旧的 controller 不写这几个字段，所以这里是可省略的，读的时候缺了按 `null` 算。
 */
export interface RouteDetail {
  /** 走直连时，直连是怎么建立起来的；不是直连或者不知道时是 `null`。 */
  direct?: DirectKind | null
  /** 经 relay 时发送方到它第一个 relay 那一段的传输（后面几段不管）；不经 relay、或者节点太旧不报时是 `null`。 */
  relay_leg?: LegTransport | null
}

export interface NodeRoute extends RouteDetail {
  peer: NodeRef
  route: Route
  rtt_ms: number | null
  /** 这份数据是多少秒之前的：节点最近一次上报到现在。 */
  age_secs: number
  /** controller 看到这条路换上来已经多少秒了。只是延迟变了不算换路；controller 重启之后从头算。 */
  since_secs: number
  /** 和对端的共用连接上现在开着几条流。没有连接、或者节点太旧不报时是 `null`。 */
  flows?: number | null
  /** 节点启动以来在和这个对端的连接上发出、收到的字节数（线上的字节）。有没有同 `flows`。 */
  tx_bytes?: number | null
  rx_bytes?: number | null
  /** 0.1.11 起：到这个对端的直连在哪一步，不管现在走不走它。旧的节点不报，是 `null`。 */
  direct_status?: DirectStatusView | null
  /**
   * 0.1.11 起：节点没在用的那种选路模式此刻会选的路；那种模式没有路时 `route` 是 `{ via: 'none' }`。
   * 和现在的路一样、还没算过、或者旧的节点不报时是 `null`。
   */
  alternative?: { route: Route; rtt_ms: number | null } | null
}

export type DirectState = 'not_tried' | 'trying' | 'verified' | 'failed' | 'unknown'
export type DirectCauseCode = 'no_answer' | 'no_candidates' | 'timeouts' | 'loss' | 'stale' | 'unknown'

export interface DirectStatusView {
  state: DirectState
  /** `verified` 时：怎么通的。 */
  kind: DirectKind | null
  /** 最近一次失败的原因：`failed` 时是这一次的，`trying` 时是上一次的。 */
  cause: { code: DirectCauseCode } | null
  attempted_at: Timestamp | null
}

export interface RouteTable {
  node: NodeRef
  online: boolean
  routes: NodeRoute[]
}

export interface AccessEdge {
  node: NodeRef
  rules: number[]
}

export interface NodeAccess {
  node: NodeRef
  can_reach: AccessEdge[]
  reachable_by: AccessEdge[]
  acknowledged: boolean
}

/** `unknown` 是比这个界面新的 controller 才有的取值。 */
export type TokenState = 'pending' | 'used' | 'expired' | 'unknown'

export interface EnrollTokenInfo {
  id: number
  network: NetworkId
  created_at: Timestamp
  expires_at: Timestamp
  /** 用它加入的节点自动加入的分组，按名字排，不含 `All`。分组被删掉时也从令牌上去掉。 */
  groups: GroupRef[]
  virtual_ip: string | null
  successor_of: NodeId | null
  /** 令牌文本的开头 18 个字符，不是秘密，用来认出是哪一个。这个字段出现之前生成的令牌是 `""`。 */
  prefix: string
  state: TokenState
  used_at: Timestamp | null
  /** 用它加入的节点；没用过、或者那个节点后来被删掉了是 `null`。 */
  used_by: NodeRef | null
}

export interface CreateEnrollToken {
  expires_in_secs?: number
  /** 已有分组的编号。 */
  groups?: GroupId[]
  virtual_ip?: string
  successor_of?: NodeId
}

/** `token` 只在创建的应答里出现这一次。 */
export interface CreatedEnrollToken extends EnrollTokenInfo {
  token: string
}

/** 分组 `src` 里的节点可以访问分组 `dst` 里的节点。规则记的是编号，分组改名之后照常生效。 */
export interface Rule {
  id: number
  name: string
  src: GroupRef
  dst: GroupRef
  direction: Direction
  enabled: boolean
}

export interface CreateRule {
  name?: string
  /** 两个已有分组的编号；可以是 `All`，可以是同一个。 */
  src: GroupId
  dst: GroupId
  direction?: Direction
  enabled?: boolean
}

export type UpdateRule = Partial<CreateRule>

export interface AccessGraph {
  /** 全部分组，和 `GET …/groups` 一样：`All` 在最前面，其余按名字排。 */
  groups: Group[]
  rules: Rule[]
  unconnected: NodeRef[]
  unacknowledged: NodeRef[]
}

export interface AccessCheck {
  from: NodeRef
  to: NodeRef
  allowed: boolean
  rules: Rule[]
}

/**
 * 一个监听现在的样子。`listening` 的 `local` 是实际绑定的地址：端口写 0 时是节点挑定的端口。
 * `unknown` 是比 controller 新的节点报的、它不认识的状态。
 */
export type ListenState =
  | { state: 'listening'; local: string }
  | { state: 'port_in_use'; detail: string }
  | { state: 'failed'; detail: string }
  | { state: 'virtual' }
  | { state: 'unsupported'; detail: string }
  | { state: 'unknown' }

export interface ListenTraffic {
  /** 现在的连接数；UDP 的端口转发是会话数。 */
  connections: number
  /** 节点这次运行以来客户端发进来的、发回给客户端的字节数。 */
  bytes_up: number
  bytes_down: number
}

/** 由监听节点每 10 秒上报一次。 */
export type ListenStatus = ListenState & ListenTraffic

/**
 * 按这个顺序取第一个符合的。`forward_target_off` 是 0.1.11 起的（目标关了"可作为端口转发的目标"），
 * `target_not_declared` 是更早的 controller 的。比界面新的 controller 可能报这里没有的值，当作未知。
 */
export type ForwardStatus =
  | 'disabled'
  | 'forward_target_off'
  | 'target_not_declared'
  | 'access_denied'
  | 'listener_offline'
  | 'target_offline'
  | 'active'

export interface Forward {
  id: number
  name: string
  protocol: ForwardProtocol
  listen_node: NodeId
  bind: string
  target_node: NodeId
  target_addr: string
  allow_from: string[]
  enabled: boolean
  status: ForwardStatus
  /** `null` 时用网络的默认值。 */
  class: ServiceClass | null
  /** 监听节点最近一次报的监听状态。"端口被占用"这类情况在这里，不在 `status` 里。 */
  listen: ListenStatus | null
}

export interface ForwardInput {
  name?: string
  protocol: ForwardProtocol
  listen_node: NodeId
  /** 端口可以写 0，由监听节点挑一个空闲的、重启不变；监听在虚拟 IP 上的不能写 0。 */
  bind: string
  target_node: NodeId
  target_addr: string
  allow_from?: string[]
  enabled?: boolean
  class?: ServiceClass | null
}

/**
 * 0.1.26 起节点对只有这两项：连接常驻、拥塞控制。ice3proxy 挪到了代理上（`Proxy.lane`）；
 * 比界面旧的 controller 还会写 `lane`、`lane_effect`、`lanes`，界面不读。
 */
export interface PairSetting {
  a: NodeId
  b: NodeId
  keep_alive: boolean
  /** 这一对节点之间的连接用哪种拥塞控制；`null` 是节点的默认（BBR）。比界面旧的 controller 不写，按 `null` 算。 */
  congestion?: PairCongestion | null
}

/** `bbr`：不把随机丢包当作拥塞；`cubic`：每次丢包都减速。比界面新的 controller 存了不认识的值时读成 `null`。 */
export type PairCongestion = 'bbr' | 'cubic'

/** 每一项都可以省略：没写的项保持原样（这一对还没有设置时取默认值）。`congestion` 写 `null` 是改回默认。 */
export interface PairInput {
  keep_alive?: boolean
  congestion?: PairCongestion | null
}

/** ice3proxy 不起作用的一个原因。`node` 是说的那一个节点。比界面新的 controller 可能写别的 `reason`。 */
export type LaneBlock =
  | { reason: 'no_relay' }
  | { reason: 'no_tcp_address'; node: NodeId }
  | { reason: 'node_too_old'; node: NodeId }
  /** 访问规则不让监听的节点访问出口。 */
  | { reason: 'not_connected' }

/** 一个选了 ice3proxy 的代理，它的 ice3proxy 起不起作用。 */
export interface LaneEffect {
  /** 至少一边能被拨，两个节点都懂 ice3proxy，访问规则让监听的节点访问出口。 */
  effective: boolean
  /** 不起作用的原因；起作用时是 `[]`。 */
  blocked: LaneBlock[]
  /** 拨号的节点：对方启用了 relay、有 TCP 地址的那一个（或者两个）。 */
  dialers: NodeId[]
  /** controller 写的一句中文。界面按 `blocked` 用自己的话写，只在原因不认识时用它。 */
  summary: string
}

/** ice3proxy 的计数，从节点启动算起的累计；`in_use`、`dialling` 是现在的值。 */
export interface LaneCounts {
  in_use: number
  dialling: number
  /** 从对端停在这里的连接里取用的次数。 */
  claims: number
  /** 其中池是空的、要等对端补拨的次数，和一共等了多少毫秒。 */
  claims_waited: number
  claim_wait_ms: number
  claims_failed: number
  /** 本来要走 ice3proxy、因为取不到改走了共用连接的流。 */
  fallbacks: number
  dial_failures: number
  /** 握手成功、但因为用途或数量不对被关掉的连接。 */
  refused: number
  /** 在 ice3proxy 的 TLS 里搬运的字节数，两个方向合计。 */
  sealed_bytes: number
  /** 本来就是 TLS 的用户数据不再加密、在程序里搬运的字节数。 */
  passthrough_bytes: number
  /** 同上，由内核直接搬运（Linux 上是 splice）。 */
  spliced_bytes: number
}

/** 一个节点上和一个对端之间的 ice3proxy。 */
export interface PeerLanes extends LaneCounts {
  peer: NodeId
  /** 这个节点现在拨不拨对端（`udp_fallback` 下按需拨）。 */
  dials: boolean
  /** 和对端之间的控制连接在不在。不在时新的 TCP 流走共用的连接。 */
  control: boolean
  /** 对端拨来、停在这个节点等它开流时取用的空闲连接。 */
  idle: number
  /** 这个节点拨好、留给自己开流的空闲连接。 */
  ready: number
  /** 这个节点拨出去、停在对端那里的空闲连接。 */
  parked_at_peer: number
  /**
   * 这个节点到对端的路上现在有没有 UDP（对端用不了 UDP 时是 `false`）；`udp_fallback` 下没有才拨、才走 ice3proxy。
   * 旧版本的节点不报、现在没有路时是 `null`；更早的 controller 不写。
   */
  udp_path?: boolean | null
}

/** 一个节点报的、和一个对端之间的 ice3proxy（代理的两端：监听的节点和出口）。 */
export interface LaneSide {
  /** 报的节点。 */
  node: NodeId
  lanes: PeerLanes
  /** 这一份是多少秒之前报的；没报过是 `null`。 */
  reported_secs_ago?: number | null
}

/** 节点对的接口应答的：设置，加上有没有存下。 */
export interface PairView extends PairSetting {
  /**
   * 0.1.19 起：这一对有没有存下的设置。`false` 时各项都是默认值，只有 `GET …/pairs/{a}/{b}` 会这样答；
   * 列表和 `PUT` 的应答里总是 `true`。更早的 controller 没有这个字段，按 `true` 算。
   */
  stored?: boolean
}

/** 别人拨进来、没有握手成功的连接，按原因分。分不到对端名下，只有全节点的。 */
export interface LaneHandshakeFailures {
  deadline: number
  unknown_key: number
  tls: number
  protocol: number
  busy: number
}

/** 一个节点上的全部 ice3proxy。 */
export interface LaneReport {
  /** 全节点的合计（对端去掉之后也不减）。 */
  total: LaneCounts
  handshake_failures: LaneHandshakeFailures
  /** 设置为 `always` 的对端，和 `udp_fallback`（包括默认）的对端里现在要用或者正在用的。 */
  peers: PeerLanes[]
}

/* 节点更新。设置和发布全局只有一份，不分网络。 */

/** 节点不能自己更新的原因。 */
export type SelfUpdateBlocker = 'container' | 'package_manager' | 'read_only_dir'

export interface SelfUpdate {
  able: boolean
  /** `able` 是 `false` 时的原因；节点报了一个 controller 不认识的原因时是 `null`。 */
  blocker: SelfUpdateBlocker | null
}

/** 换程序的时机。`idle` 是自动更新用的；管理员强制更新只能选另外两种。 */
export type UpdateTiming = 'idle' | 'now' | 'after_drain'
export type ForceTiming = Exclude<UpdateTiming, 'idle'>

/** `not_installed`：没装成，和版本好坏无关，以后会再试。`version_rejected`：这个版本在这台机器上不能用。 */
export type FailureKind = 'not_installed' | 'version_rejected'

/** 新程序已经准备好或者正在准备，只带版本号的那几种进度。 */
export type UpdateStepState =
  'verifying' | 'self_check' | 'waiting_for_idle' | 'draining' | 'installing' | 'restarting' | 'confirmed'

/** 节点本次连接期间最近一次报的更新进度。`unknown` 是比 controller 新的节点报上来的、controller 不认识的状态。 */
export type UpdateStatus =
  | { state: 'idle' }
  | { state: 'downloading'; version: Version; received: number; total: number }
  | { state: UpdateStepState; version: Version }
  | { state: 'failed'; version: Version | null; kind: FailureKind; reason: string }
  | { state: 'unknown' }

export interface UpdateOrder {
  version: Version
  timing: UpdateTiming
}

/** controller 想让节点更新、但还没有下发指令的原因。 */
export type UpdateWait = 'package' | 'relay_turn' | 'unknown'

export interface UpdateFailure {
  version: Version
  kind: FailureKind
  reason: string
  at: Timestamp
}

/** 一个节点的程序更新。`Node.update` 和 `GET …/nodes/{node}/update` 是同一个东西。 */
export interface NodeUpdate {
  /** `null`：节点的版本太旧，不懂更新，只能手动换程序。 */
  self_update: SelfUpdate | null
  /** 现在可以让它更新到的版本：发布比它新、有它的平台的包、controller 也够新。不管它能不能自己更新、在不在线都给出。 */
  available: Version | null
  status: UpdateStatus
  ordered: UpdateOrder | null
  waiting: UpdateWait | null
  failure: UpdateFailure | null
  /** 0.1.12 起：它的版本低于最新发布的 `security_floor`（有已知的安全问题）。没有这个字段当作 `false`。 */
  security?: boolean
}

export type PackageState = 'not_needed' | 'fetching' | 'cached' | 'failed' | 'unknown'

export interface PackageInfo {
  platform: string
  file: string
  /** 字节数。 */
  size: number
  state: PackageState
  /** 最近一次取这个包失败的原因。 */
  error: string | null
}

export interface ReleaseInfo {
  version: Version
  published: Timestamp
  min_controller: Version
  /** controller 比 `min_controller` 旧：这个版本不会下发给任何节点。 */
  controller_too_old: boolean
  /** 这个版本比 controller 自己新：controller 要手动更新。 */
  newer_than_controller: boolean
  packages: PackageInfo[]
  /** 0.1.12 起：没有已知安全问题的最低版本；比它旧的节点要尽快更新。 */
  security_floor?: string | null
}

export interface PausedVersion {
  version: Version
  /** 报告失败的节点；后来被删掉了是 `null`。 */
  node: NodeRef | null
  network: NetworkId | null
  reason: string
  at: Timestamp
}

/** 全部网络的节点按更新情况数出来的数。一个节点只算在一项里。 */
export interface UpdateCounts {
  total: number
  updating: number
  failed: number
  manual: number
  outdated: number
  up_to_date: number
}

export interface UpdateOverview {
  auto_update: boolean
  /** `http(s)://` 地址前缀，或者 controller 所在机器上一个目录的绝对路径。 */
  source: string
  source_is_default: boolean
  controller_version: Version
  release: ReleaseInfo | null
  checked_at: Timestamp | null
  /** 最近一次查发布源失败的原因；失败时 `release` 保持上一次查到的。 */
  check_error: string | null
  paused: PausedVersion[]
  nodes: UpdateCounts
}

export interface UpdateSettings {
  auto_update?: boolean
  /** 写 `null` 表示改回项目默认的发布源。 */
  source?: string | null
}

export interface ForceUpdate {
  timing: ForceTiming
}

export interface ResumeUpdate {
  version: Version
}

export interface SkippedUpdate {
  node: NodeRef
  /** 给人看的一句话。 */
  reason: string
}

/** "全部更新"的结果。 */
export interface ForcedUpdates {
  /** 没有可以下发的版本时是 `null`，这时节点都在 `skipped` 里。 */
  version: Version | null
  ordered: NodeRef[]
  /** 稍后下发：在等包取回来，或者是 relay 在等轮到它。 */
  queued: NodeRef[]
  skipped: SkippedUpdate[]
}

/* 路由视图。数据都来自节点的上报；路是发送方选的，两个方向可以不一样。 */

export interface MatrixNode extends NodeRef {
  online: boolean
}

/** 矩阵里的一格：`from` 到 `to` 这个方向现在怎么走。 */
export interface MatrixEntry extends RouteDetail {
  from: NodeId
  to: NodeId
  route: Route
  rtt_ms: number | null
  /** `from` 最近一次上报到现在过了多少秒。 */
  age_secs: number
  /** 不是 `from` 现在这次连接报的：它不在线，或者刚重新连上还没有上报。 */
  stale: boolean
  /**
   * 0.1.22 起：`from` 最近一次报的、和 `to` 之间的 ice3proxy 连接。这一对现在不用 ice3proxy、发送方太旧或者不在线时是 `null`；
   * 更早的 controller 不写。两头各自看自己那一边，同一对的两格数不一定一样，不能相加。
   */
  lanes?: EntryLanes | null
}

export interface EntryLanes {
  /** 两个节点之间的控制连接在不在；不在时新的 TCP 流走共用的连接。 */
  control: boolean
  /** 正在带着流的连接。 */
  in_use: number
  /** 这一边看得到的空闲连接。 */
  idle: number
}

export interface RouteMatrix {
  /** 网络里的全部节点，按编号排。 */
  nodes: MatrixNode[]
  /** 有数据的格子，按 `from`、`to` 排。没出现的格子是没有数据。 */
  entries: MatrixEntry[]
}

/**
 * 一个方向的数据从哪里来。`query`：刚问的发送方；`report`：问不到，用它最近一次的上报；
 * `not_peers`：发送方说对端不在它的配置里；`none`：没有数据。`unknown` 是更新的 controller 才有的取值。
 */
export type PathSource = 'query' | 'report' | 'not_peers' | 'none' | 'unknown'

export interface RouteSince {
  secs_ago: number
  reason: string
}

/** 路径上一段的测量值。目的节点到它挂靠的 relay 的那一段只知道延迟，抖动和丢包是 0。 */
export interface PathSegment {
  from: NodeId
  to: NodeId
  rtt_us: number
  jitter_us: number
  /** 千分之几。 */
  loss_permille: number
}

/** 发送方考虑过的一条候选路径。 */
export interface PathCandidate {
  route: Route
  /** 代价，微秒：各段的延迟、抖动（四倍）、丢包的恢复代价相加，每经过一个 relay 加 1 毫秒，负载高的 relay 另外加惩罚。 */
  cost_us: number
  /** 按经过的顺序。 */
  legs: PathSegment[]
  /** 路径上负载最高的 relay 的带宽占用百分比；直连和没有设上限的 relay 是 0。 */
  load_percent: number
  /** 现在走的就是这一条。最多一条是 `true`。 */
  current: boolean
}

export interface PathLeg extends RouteDetail {
  from: NodeRef
  to: NodeRef
  source: PathSource
  route: Route | null
  rtt_ms: number | null
  /** 刚问到的是 0；没有数据是 `null`。 */
  age_secs: number | null
  /** 只有 `source` 是 `query`、并且节点这次启动以来换过这条路时才有。 */
  since: RouteSince | null
  /** 发送方用的选路模式。只有现问到、并且发送方的版本会说时才有。 */
  mode?: RoutingMode | null
  /** 发送方的路由层说的"为什么是现在这条路"。有没有同 `mode`。 */
  reason?: string | null
  /** 发送方考虑过的候选路径，按代价从低到高，最多 16 条。`null` 是不知道，`[]` 是它手上还没有任何测量值。 */
  candidates?: PathCandidate[] | null
}

/** relay 自己说的状态。`unknown` 是比 controller 新的节点报的。 */
export type RelayState = 'serving' | 'overloaded' | 'draining' | 'unknown'

/** 骨干矩阵里一个 relay 到另一个 relay 的链路。 */
export interface BackboneLink {
  to: NodeId
  /** `null` 表示连不上。 */
  rtt_ms: number | null
  jitter_ms: number
  loss_permille: number
}

/** 骨干矩阵的一行。问到的节点手上都没有这一行时，后面几项是 `null`，`links` 是空的。 */
export interface BackboneRelay {
  relay: NodeRef
  online: boolean
  state: RelayState | null
  load_percent: number | null
  /** 回答的节点收到这一行到现在多少毫秒；不会超过两分钟。 */
  age_ms: number | null
  /** 这一行是从哪个节点问来的。 */
  reported_by: NodeId | null
  links: BackboneLink[]
}

/** relay 之间的延迟矩阵。controller 每次现问几个节点，最多等 3 秒左右。 */
export interface BackboneView {
  relays: BackboneRelay[]
  /** 这次回答了的节点。是空的时候每个 relay 的行都是空的。 */
  answered: NodeRef[]
}

export interface PathView {
  /** `from` 到 `to`。 */
  forward: PathLeg
  /** `to` 到 `from`。 */
  reverse: PathLeg
}

/* 出口。计数只在 controller 的内存里：节点离线之后留着最后报的那一份，controller 重启之后等节点重新上报。 */

/**
 * 只看出口自己报的、归因于它自己的失败（解析器出错、出口内部出错）：最近 5 分钟里至少 3 次、并且占请求的一成以上是
 * `degraded`。不在线、或者最近 5 分钟里没有请求是 `unknown`。
 */
export type ExitHealth = 'ok' | 'degraded' | 'unknown'

/** 本账期的配额。时间按出口节点自己的时钟。 */
export interface QuotaUsage {
  limit_bytes: number
  /** 可能略超过配额：超出的那一段流是在用完的那一刻被断开的。 */
  used_bytes: number
  period_start: Timestamp
  period_end: Timestamp
}

/** 出口最近一次报的计数。`active` 是现在的；其余是它这次运行以来的累计。 */
export interface ExitReport {
  active: number
  /** 收到的建流请求，含 UDP 的数据报上下文。 */
  total: number
  bytes_to_target: number
  bytes_from_target: number
  failed_by_target: number
  refused: number
  failed_by_exit: number
  /** 建成之后没有正常结束的。 */
  aborted: number
  draining: boolean
  /** 没配配额是 `null`。 */
  quota: QuotaUsage | null
}

/** 一个用过这个出口的节点自己看到的，是它这次运行以来的累计。 */
export interface ExitObserved {
  by: NodeRef
  exit: NodeId
  flows: number
  bytes_up: number
  bytes_down: number
  failed_by_target: number
  refused: number
  failed_by_exit: number
  /** 到出口开流就失败了，出口根本没看到。 */
  unreachable: number
  reported_secs_ago: number
}

export interface ExitView {
  node: NodeRef
  online: boolean
  settings: ExitSettings
  health: ExitHealth
  /** 最近 5 分钟里出口报的建流请求数，和其中归因于出口自己的失败数。 */
  recent_requests: number
  recent_failures: number
  /** 没有报过是 `null`。 */
  usage: ExitReport | null
  reported_secs_ago: number | null
  /** 旧的 controller：谁经它出去过（按用户名选出口）。代理改版之后没有了。 */
  observed?: ExitObserved[]
  /** 0.1.15 起：出口是这个节点的代理（完整的代理对象，按编号排，停用的也在）。 */
  proxies?: Proxy[]
}

/* 分组。 */

/** 列表、单个分组、新建、改名和每次增减成员的应答都是它；访问关系图的 `groups` 也是。 */
export interface Group {
  id: GroupId
  /** 写的时候的大小写。在一个网络里不分大小写唯一。 */
  name: string
  /** 内置的 `All`：每个节点都在里面，不能改名、删除，也不能增减成员。 */
  builtin: boolean
  /** 成员，按编号排。`All` 的成员是网络里的全部节点。 */
  nodes: NodeRef[]
  /** `src` 或 `dst` 是它的规则（包括停用的），按编号排。删除这个分组时它们被一起删掉。 */
  rules: Rule[]
}

export interface CreateGroup {
  name: string
}

export interface UpdateGroup {
  name?: string
}

/** 批量增减成员。已经在里面的再加入、本来就不在的移出都什么也不做；要么全部做到，要么一个都不改。 */
export interface GroupMembers {
  add?: NodeId[]
  remove?: NodeId[]
}

/** 删掉一个分组的应答：删掉了什么。 */
export interface DeletedGroup {
  id: GroupId
  name: string
  /** 原来的成员。 */
  nodes: NodeRef[]
  /** 一起删掉的规则，删之前的样子。 */
  rules: Rule[]
  /** 预设了它、现在不再预设的注册令牌的编号。 */
  tokens: number[]
}

/* 主动测试。 */

export type TestItem = 'direct' | 'direct_quality' | 'relay_quality' | 'route' | 'host'

export interface CreateTest {
  a: NodeId
  b: NodeId
  items?: TestItem[]
  throughput?: boolean
  /** relay 质量测哪几条路径（最多 2 条），每条按 a 到 b 的顺序列出经过的 relay。 */
  via?: NodeId[][]
}

/** 一项或整个测试做不了、没做成的原因。界面按 `code` 写，`node` 说是哪个节点的；`message` 只是兜底。 */
export interface TestProblem {
  code: string
  node: NodeId | null
  message: string
}

export type TestState = 'running' | 'done' | 'failed' | 'cancelled'
export type TestItemState = 'pending' | 'done' | 'skipped' | 'failed'

export interface DirectSide {
  node: NodeId
  ok: boolean
  already: boolean
  kind: DirectKind | null
  elapsed_ms: number | null
  failure: string | null
  /** 这一端的 UDP 通不通；不知道是 `null`。 */
  udp: boolean | null
  mapping_varies: boolean | null
  candidates: number | null
}

export interface DirectResult {
  state: TestItemState
  ok: boolean | null
  kind: DirectKind | null
  elapsed_ms: number | null
  already: boolean | null
  problem: TestProblem | null
  sides: DirectSide[]
}

export interface Latency {
  probes: number
  answered: number
  min_us: number | null
  avg_us: number | null
  p95_us: number | null
  jitter_us: number | null
  loss_permille: number | null
  loss_up_permille: number | null
  loss_down_permille: number | null
  same_path: number | null
  interval_ms: number
  duration_ms: number
}

export interface Hop {
  from: NodeId
  to: NodeId
  rtt_us: number | null
  jitter_us: number | null
  loss_permille: number | null
  source: 'measured' | 'backbone' | 'reported' | 'unknown'
}

export interface Transfer {
  bytes: number
  ms: number
  bits_per_second: number
  /** `bytes`、`time`、`finished`；比界面新的节点可能报别的。 */
  stopped_by: string
}

export interface ThroughputResult {
  state: TestItemState
  problem: TestProblem | null
  up: Transfer | null
  down: Transfer | null
  failure: string | null
  transport: string
  congestion: string | null
  limit_bytes: number
  limit_ms: number
  pinned: boolean
  shared_connection: boolean
}

export type PickedBy = 'direct' | 'direct_first' | 'lowest_cost' | 'admin'

export interface PathResult {
  state: TestItemState
  route: Route | null
  picked_by: PickedBy[]
  problem: TestProblem | null
  latency: Latency | null
  cost_us: number | null
  hops: Hop[]
  relay_leg: LegTransport | null
  throughput: ThroughputResult | null
}

export type ChoiceReason =
  | 'lan'
  | 'direct'
  | 'peer_is_relay'
  | 'own_relay'
  | 'peer_relay'
  /** 0.1.14 起，默认模式：没有一个 relay 两端都用得上，经一串 relay。 */
  | 'no_shared_relay'
  | 'lowest_cost'
  | 'within_margin'
  | 'no_path'

export interface Choice {
  route: Route | null
  /** 一般是 `ChoiceReason`；比界面新的节点可能报别的，界面原样显示。 */
  reason: string
  cost_us: number | null
  /** `within_margin` 时那条更便宜、但没有便宜到换路的候选。 */
  cheaper?: { route: Route; cost_us: number } | null
}

export interface DecisionView {
  from: NodeId
  to: NodeId
  mode: RoutingMode
  current: Route | null
  direct_first: Choice
  lowest_cost: Choice
  candidates: PathCandidate[]
}

export interface RouteResult {
  state: TestItemState
  problem: TestProblem | null
  forward: DecisionView | null
  reverse: DecisionView | null
}

export interface TestView {
  id: number
  network: NetworkId
  a: NodeRef
  b: NodeRef
  state: TestState
  request: { items: TestItem[]; throughput: boolean; via: NodeId[][] }
  started_at: Timestamp
  finished_at: Timestamp | null
  matrix: number | null
  error: TestProblem | null
  direct: DirectResult | null
  direct_quality: PathResult | null
  relay_quality: PathResult[]
  route: RouteResult | null
  notes: TestProblem[]
  /**
   * 0.1.24 起：两端主机的快照，`a` 在前。没有要这一项时是 `null`；更早的 controller 没有这个字段。
   */
  hosts?: HostReport[] | null
}

/**
 * 两个 CPU 占用，整数百分比：`system_percent` 是整台机器的（所有核合起来 0–100），
 * `process_percent` 是 i3t 进程的、按一个核算（多线程时可能超过 100）。一条连接的数据大多在一个核上跑，
 * 所以 `process_percent` 接近 100 就是卡在 CPU 上了。
 */
export interface HostCpu {
  system_percent: number | null
  process_percent: number | null
}

/**
 * 这一端到对端的那条连接（QUIC）。计数是测试期间的（开始和结束时的差），`rtt_us`、`cwnd_bytes`、`mtu` 是结束时的值；
 * `age_secs` 是这条连接已经开了多久。
 */
export interface PeerConnection {
  route: Route | null
  /** 平滑后的往返延迟。 */
  rtt_us: number | null
  /** 这条连接上见过的最小往返延迟。 */
  min_rtt_us?: number | null
  cwnd_bytes: number | null
  mtu: number | null
  /** `"bbr"`、`"cubic"`。 */
  congestion: string | null
  sent_packets: number | null
  lost_packets: number | null
  lost_bytes: number | null
  congestion_events: number | null
  bytes_sent: number | null
  bytes_received: number | null
  age_secs: number | null
}

/**
 * 测试时一端主机的快照（`host` 项）。现在只有 Linux 读得全；Windows、macOS 上只有系统、架构、核数，
 * 别的是 `null`（不是出错）。进行中时是 `pending`、其余都是 `null`，这一端最后一次报告到了才填上。
 */
export interface HostReport {
  node: NodeId
  state: TestItemState
  /** `not_supported`（节点早于 0.1.24）、`node_offline`、`no_report`。 */
  problem: TestProblem | null
  system: {
    os: string | null
    kernel: string | null
    arch: string | null
    cpu_model: string | null
    cores: number | null
    uptime_secs: number | null
  } | null
  /** 测试开始那一秒。 */
  cpu: HostCpu | null
  /** 整个测试里最忙的一秒（两个数各取各的最大）。 */
  cpu_peak: HostCpu | null
  /** 1、5、15 分钟的平均负载乘以 100。 */
  load_x100: number[] | null
  memory: { total_bytes: number; available_bytes: number; process_rss_bytes: number | null } | null
  process: { uptime_secs: number | null; threads: number | null } | null
  connections: {
    /** 到别的节点的连接。 */
    peers: number | null
    /** 到中继的连接。 */
    relays: number | null
    /** 它作为中继在服务的会话；不是中继时是 `null`。 */
    relay_clients: number | null
    streams: number | null
    lanes_in_use: number | null
    lanes_idle: number | null
  } | null
  /** 这一端没有到对端的连接时是 `null`。 */
  to_peer: PeerConnection | null
}

/*
 * 代理（替代原来的监听器和凭据）：在节点 `node` 上监听 `bind`，流量从出口节点 `exit` 出去，
 * 用户名和密码认证（0.1.15）。
 */

/** `mixed`：同一个端口上 SOCKS5 和 HTTP 都认（按第一个字节分辨）。 */
export type ProxyProtocol = 'mixed' | 'socks5' | 'http'

export type ProxyStatusCode =
  | 'listening'
  | 'disabled'
  | 'pending'
  | 'node_offline'
  | 'port_in_use'
  | 'bind_failed'
  | 'exit_disabled'
  | 'exit_offline'
  | 'access_denied'
  | 'exit_missing'

export interface ProxyStatus {
  /** 一般是 `ProxyStatusCode`；比界面新的 controller 可能报别的，当作未知。 */
  code: string
  /** 监听失败时节点报的原话。 */
  detail?: string | null
  /** 监听失败的原因码（`port_in_use`、`bind_failed` 时有）。 */
  cause?: unknown
  /** 实际在监听的地址。 */
  local?: string | null
}

export interface Proxy {
  id: number
  name: string
  /** 监听的节点（入口）。 */
  node: NodeId
  bind: string
  protocol: ProxyProtocol
  /** 出口节点；从旧的监听器迁移过来、没有出口的是 `null`（状态是 `exit_missing`）。 */
  exit: NodeId | null
  username: string
  password: string
  enabled: boolean
  allow_from: string[]
  class: ServiceClass | null
  optimistic: boolean | null
  /**
   * 0.1.26 起：这个代理的流一直走 ice3proxy（监听的节点和出口之间一条连接一条 TCP），开不了时退回共用连接；
   * `false` 时永远不走。比界面旧的 controller 不写，按 `false` 算。
   */
  lane?: boolean
  status: ProxyStatus | null
  /** `lane` 是 `true` 并且有出口时才有，别的时候是 `null`。 */
  lane_effect?: LaneEffect | null
  /** 两端报的 ice3proxy（`lane` 是 `true` 时才有内容）。计数属于这一对节点，同一对之间选了 ice3proxy 的代理共用。 */
  lanes?: LaneSide[]
  /** 入口节点不在线或者还没报过时是 0。 */
  connections: number
  bytes_up: number
  bytes_down: number
}

export interface ProxyInput {
  name?: string
  node: NodeId
  bind: string
  protocol: ProxyProtocol
  exit: NodeId
  username: string
  password: string
  enabled?: boolean
  /** 0.1.26 起：要不要 ice3proxy，新建时不写是 `false`。 */
  lane?: boolean
}
