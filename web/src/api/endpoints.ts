import { MCP_PATH, request } from './client'
import {
  type AccessCheck,
  type AccessGraph,
  type BackboneView,
  type CreatedEnrollToken,
  type CreatedMcpToken,
  type CreateEnrollToken,
  type CreateGroup,
  type CreateMcpToken,
  type CreateNetwork,
  type CreateRule,
  type CreateTest,
  type DeletedGroup,
  type EnrollTokenInfo,
  type ExitInput,
  type ExitView,
  type ForcedUpdates,
  type ForceUpdate,
  type Forward,
  type ForwardInput,
  type Group,
  type GroupId,
  type GroupMembers,
  type LogEntry,
  type LogQuery,
  type McpTokenInfo,
  type Network,
  type NetworkId,
  type Node,
  type NodeAccess,
  type NodeDetail,
  type NodeId,
  type NodeUpdate,
  type Overview,
  type Proxy,
  type ProxyInput,
  type PairInput,
  type PairView,
  type PathView,
  type RelayEnabled,
  type RelayInput,
  type ResumeUpdate,
  type RouteMatrix,
  type RouteTable,
  type Rule,
  type Status,
  type Succeed,
  type UpdateGroup,
  type UpdateNetwork,
  type UpdateNode,
  type UpdateOverview,
  type UpdateRule,
  type UpdateSettings,
  type TestView,
} from './types'

/**
 * 管理 API 的每个接口一个函数，名字和管理 API 的路径一一对应。
 *
 * 唯一没有对应函数的是 `GET /metrics`：它不在 `/api/v1` 下面，是给 Prometheus 抓的文本，界面只写出它的地址。
 */

const net = (network: NetworkId) => `/networks/${network}`

export const api = {
  /** `token` 给了就用它而不是已登录的令牌：登录页用来检查令牌对不对。 */
  status: (token?: string, signal?: AbortSignal) => request<Status>('GET', '/status', { token, signal }),
  log: (query: LogQuery = {}) => request<LogEntry[]>('GET', '/log', { query: { ...query } }),

  networks: () => request<Network[]>('GET', '/networks'),
  createNetwork: (body: CreateNetwork) => request<Network>('POST', '/networks', { body }),
  network: (network: NetworkId) => request<Network>('GET', net(network)),
  updateNetwork: (network: NetworkId, body: UpdateNetwork) => request<Network>('PATCH', net(network), { body }),
  deleteNetwork: (network: NetworkId) => request<undefined>('DELETE', net(network)),
  overview: (network: NetworkId) => request<Overview>('GET', `${net(network)}/overview`),

  nodes: (network: NetworkId) => request<Node[]>('GET', `${net(network)}/nodes`),
  node: (network: NetworkId, node: NodeId) => request<NodeDetail>('GET', `${net(network)}/nodes/${node}`),
  updateNode: (network: NetworkId, node: NodeId, body: UpdateNode) =>
    request<Node>('PATCH', `${net(network)}/nodes/${node}`, { body }),
  deleteNode: (network: NetworkId, node: NodeId) => request<undefined>('DELETE', `${net(network)}/nodes/${node}`),
  /** controller 启用之后从自己这边试连填的每个地址，最多等 3 秒左右才应答。 */
  enableRelay: (network: NetworkId, node: NodeId, body: RelayInput) =>
    request<RelayEnabled>('PUT', `${net(network)}/nodes/${node}/relay`, { body }),
  disableRelay: (network: NetworkId, node: NodeId) => request<Node>('DELETE', `${net(network)}/nodes/${node}/relay`),
  enableExit: (network: NetworkId, node: NodeId, body: ExitInput) =>
    request<Node>('PUT', `${net(network)}/nodes/${node}/exit`, { body }),
  disableExit: (network: NetworkId, node: NodeId) => request<Node>('DELETE', `${net(network)}/nodes/${node}/exit`),
  succeed: (network: NetworkId, node: NodeId, body: Succeed) =>
    request<Node>('POST', `${net(network)}/nodes/${node}/succeed`, { body }),
  routes: (network: NetworkId, node: NodeId) => request<RouteTable>('GET', `${net(network)}/nodes/${node}/routes`),
  nodeAccess: (network: NetworkId, node: NodeId) => request<NodeAccess>('GET', `${net(network)}/nodes/${node}/access`),

  /** `all` 时连用掉的和过期的也列出（它们在 30 天之后被清掉）；否则只有还能用的。 */
  tokens: (network: NetworkId, all = false) =>
    request<EnrollTokenInfo[]>('GET', `${net(network)}/tokens`, { query: { all: all ? 'true' : undefined } }),
  createToken: (network: NetworkId, body: CreateEnrollToken) =>
    request<CreatedEnrollToken>('POST', `${net(network)}/tokens`, { body }),
  /** 收回一个还没用掉的令牌；对用掉的、过期的令牌是删掉这条记录。 */
  deleteToken: (network: NetworkId, id: number) => request<undefined>('DELETE', `${net(network)}/tokens/${id}`),

  rules: (network: NetworkId) => request<Rule[]>('GET', `${net(network)}/rules`),
  createRule: (network: NetworkId, body: CreateRule) => request<Rule>('POST', `${net(network)}/rules`, { body }),
  updateRule: (network: NetworkId, id: number, body: UpdateRule) =>
    request<Rule>('PATCH', `${net(network)}/rules/${id}`, { body }),
  deleteRule: (network: NetworkId, id: number) => request<undefined>('DELETE', `${net(network)}/rules/${id}`),

  accessGraph: (network: NetworkId) => request<AccessGraph>('GET', `${net(network)}/access/graph`),
  accessCheck: (network: NetworkId, from: NodeId, to: NodeId) =>
    request<AccessCheck>('GET', `${net(network)}/access/check`, { query: { from, to } }),

  /** 第一次是吊销（记录留着，`state` 变成 `revoked`）；对已经吊销的再删一次才彻底删掉。 */

  proxies: (network: NetworkId) => request<Proxy[]>('GET', `${net(network)}/proxies`),
  createProxy: (network: NetworkId, body: ProxyInput) => request<Proxy>('POST', `${net(network)}/proxies`, { body }),
  updateProxy: (network: NetworkId, id: number, body: Partial<ProxyInput>) =>
    request<Proxy>('PATCH', `${net(network)}/proxies/${id}`, { body }),
  deleteProxy: (network: NetworkId, id: number) => request<undefined>('DELETE', `${net(network)}/proxies/${id}`),

  forwards: (network: NetworkId) => request<Forward[]>('GET', `${net(network)}/forwards`),
  createForward: (network: NetworkId, body: ForwardInput) =>
    request<Forward>('POST', `${net(network)}/forwards`, { body }),
  replaceForward: (network: NetworkId, id: number, body: ForwardInput) =>
    request<Forward>('PUT', `${net(network)}/forwards/${id}`, { body }),
  deleteForward: (network: NetworkId, id: number) => request<undefined>('DELETE', `${net(network)}/forwards/${id}`),

  nodeUpdate: (network: NetworkId, node: NodeId) => request<NodeUpdate>('GET', `${net(network)}/nodes/${node}/update`),
  forceNodeUpdate: (network: NetworkId, node: NodeId, body: ForceUpdate) =>
    request<NodeUpdate>('POST', `${net(network)}/nodes/${node}/update`, { body }),

  routeMatrix: (network: NetworkId) => request<RouteMatrix>('GET', `${net(network)}/routes`),
  /** controller 先向两端各问一次，问不到的方向退回到上报的数据，所以最多要等 3 秒左右。 */
  path: (network: NetworkId, from: NodeId, to: NodeId, signal?: AbortSignal) =>
    request<PathView>('GET', `${net(network)}/path`, { query: { from, to }, signal }),
  /** 主动测试：发起马上应答，测试在后台进行；进行中每秒问一次。 */
  createTest: (network: NetworkId, body: CreateTest) => request<TestView>('POST', `${net(network)}/tests`, { body }),
  test: (network: NetworkId, id: number) => request<TestView>('GET', `${net(network)}/tests/${id}`),
  tests: (network: NetworkId, pair?: { a: NodeId; b: NodeId }, limit = 20) =>
    request<TestView[]>('GET', `${net(network)}/tests`, { query: { ...pair, limit } }),
  cancelTest: (network: NetworkId, id: number) => request<TestView>('POST', `${net(network)}/tests/${id}/cancel`),
  /** relay 之间的延迟矩阵。controller 现问几个节点，最多等 3 秒左右。 */
  backbone: (network: NetworkId, signal?: AbortSignal) =>
    request<BackboneView>('GET', `${net(network)}/backbone`, { signal }),

  exits: (network: NetworkId) => request<ExitView[]>('GET', `${net(network)}/exits`),
  exit: (network: NetworkId, node: NodeId) => request<ExitView>('GET', `${net(network)}/exits/${node}`),

  /** `All` 在最前面，其余按名字排（不分大小写）。每个带着成员和用到它的规则。 */
  groups: (network: NetworkId) => request<Group[]>('GET', `${net(network)}/groups`),
  createGroup: (network: NetworkId, body: CreateGroup) => request<Group>('POST', `${net(network)}/groups`, { body }),
  /** 删除之前用它说出会影响什么：成员和一起删掉的规则。 */
  group: (network: NetworkId, group: GroupId) => request<Group>('GET', `${net(network)}/groups/${group}`),
  /** 改名不改变谁能访问谁：规则记的是编号。 */
  updateGroup: (network: NetworkId, group: GroupId, body: UpdateGroup) =>
    request<Group>('PATCH', `${net(network)}/groups/${group}`, { body }),
  /** 从成员上去掉、从预设了它的令牌上去掉、删掉用到它的规则，在同一个事务里。应答是 200，不是 204。 */
  deleteGroup: (network: NetworkId, group: GroupId) =>
    request<DeletedGroup>('DELETE', `${net(network)}/groups/${group}`),
  /** 一次加入、移出几个节点：要么全部做到，要么一个都不改。 */
  setGroupMembers: (network: NetworkId, group: GroupId, body: GroupMembers) =>
    request<Group>('PATCH', `${net(network)}/groups/${group}/nodes`, { body }),
  addGroupMember: (network: NetworkId, group: GroupId, node: NodeId) =>
    request<Group>('PUT', `${net(network)}/groups/${group}/nodes/${node}`),
  /** 应答是改完之后的分组，不是 204。 */
  removeGroupMember: (network: NetworkId, group: GroupId, node: NodeId) =>
    request<Group>('DELETE', `${net(network)}/groups/${group}/nodes/${node}`),

  pairs: (network: NetworkId) => request<PairView[]>('GET', `${net(network)}/pairs`),
  /** 一对节点，有没有存下设置都有（0.1.19 起）。 */
  pair: (network: NetworkId, a: NodeId, b: NodeId) => request<PairView>('GET', `${net(network)}/pairs/${a}/${b}`),
  setPair: (network: NetworkId, a: NodeId, b: NodeId, body: PairInput) =>
    request<PairView>('PUT', `${net(network)}/pairs/${a}/${b}`, { body }),
  deletePair: (network: NetworkId, a: NodeId, b: NodeId) =>
    request<undefined>('DELETE', `${net(network)}/pairs/${a}/${b}`),

  updateOverview: () => request<UpdateOverview>('GET', '/update'),
  updateSettings: (body: UpdateSettings) => request<UpdateOverview>('PATCH', '/update', { body }),
  /** 查完才应答，连不上发布源时最多等 30 秒左右。查不到不算请求失败，原因在 `check_error` 里。 */
  checkUpdate: () => request<UpdateOverview>('POST', '/update/check'),
  resumeUpdate: (body: ResumeUpdate) => request<UpdateOverview>('POST', '/update/resume', { body }),
  forceUpdateAll: (body: ForceUpdate) => request<ForcedUpdates>('POST', '/update/force', { body }),

  /** 签过的 MCP 令牌，按编号排：还能用的、过期的、撤销的都在（过期 30 天之后清掉）。 */
  mcpTokens: () => request<McpTokenInfo[]>('GET', `${MCP_PATH}/tokens`),
  /** 签发一个 MCP 令牌。JWT 只在这一次的应答里。 */
  createMcpToken: (body: CreateMcpToken) => request<CreatedMcpToken>('POST', `${MCP_PATH}/tokens`, { body }),
  /** 撤销：它的下一次调用就被拒绝。已经撤销的再撤销一次什么也不做。 */
  revokeMcpToken: (id: number) => request<McpTokenInfo>('POST', `${MCP_PATH}/tokens/${id}/revoke`),
}
