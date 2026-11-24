import { infiniteQueryOptions, QueryClient, queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'

import { toast } from '@/components/ui/toast'
import { LIVE_INTERVAL } from '@/lib/polling'

import { ApiError, errorDetail, errorMessage } from './client'
import { api } from './endpoints'
import { type GroupId, type LogEntry, type LogQuery, type NetworkId, type NodeId } from './types'

/**
 * 服务器上的状态都经过 TanStack Query。这里是全部的查询键和查询的写法；页面里只写 `useQuery(q.nodes(network))`。
 *
 * 一个网络里的东西互相牵连（删一个节点，转发、监听器、关系图、总览都跟着变），
 * 所以查询键都以 `['n', 网络编号]` 开头，改了任何东西之后把这个网络下的查询一起作废，不逐个去想谁受影响。
 */
export const keys = {
  status: ['status'] as const,
  /** 操作记录不分网络，作废时按前缀 `['log']` 一起作废。 */
  log: (query: LogQuery) => ['log', query] as const,
  logPages: (query: Omit<LogQuery, 'before' | 'limit'>, size: number) => ['log', 'pages', size, query] as const,
  networks: ['networks'] as const,
  scope: (network: NetworkId) => ['n', network] as const,
  overview: (network: NetworkId) => ['n', network, 'overview'] as const,
  nodes: (network: NetworkId) => ['n', network, 'nodes'] as const,
  node: (network: NetworkId, node: NodeId) => ['n', network, 'node', node] as const,
  routes: (network: NetworkId, node: NodeId) => ['n', network, 'node', node, 'routes'] as const,
  nodeAccess: (network: NetworkId, node: NodeId) => ['n', network, 'node', node, 'access'] as const,
  tokens: (network: NetworkId, all = false) => ['n', network, 'tokens', all ? 'all' : 'pending'] as const,
  groups: (network: NetworkId) => ['n', network, 'groups'] as const,
  group: (network: NetworkId, group: GroupId) => ['n', network, 'group', group] as const,
  rules: (network: NetworkId) => ['n', network, 'rules'] as const,
  graph: (network: NetworkId) => ['n', network, 'graph'] as const,
  check: (network: NetworkId, from: NodeId, to: NodeId) => ['n', network, 'check', from, to] as const,
  proxies: (network: NetworkId) => ['n', network, 'proxies'] as const,
  forwards: (network: NetworkId) => ['n', network, 'forwards'] as const,
  pairs: (network: NetworkId) => ['n', network, 'pairs'] as const,
  pair: (network: NetworkId, a: NodeId, b: NodeId) => ['n', network, 'pair', a, b] as const,
  exits: (network: NetworkId) => ['n', network, 'exits'] as const,
  matrix: (network: NetworkId) => ['n', network, 'matrix'] as const,
  path: (network: NetworkId, from: NodeId, to: NodeId) => ['n', network, 'path', from, to] as const,
  backbone: (network: NetworkId) => ['n', network, 'backbone'] as const,
  test: (network: NetworkId, id: number) => ['n', network, 'test', id] as const,
  tests: (network: NetworkId) => ['n', network, 'tests'] as const,
  /** 更新的设置和现状是全局的，不在某个网络下面。 */
  update: ['update'] as const,
  /** MCP 令牌也是全局的：签给谁、限不限网络都记在令牌上。 */
  mcpTokens: ['mcp', 'tokens'] as const,
  /** 所有网络下的查询：全局的修改（全部更新、暂停和继续）会改到每个网络里的节点。 */
  everyNetwork: ['n'] as const,
}

/** 带 `refetchInterval` 的是显示实时状态的查询；标签页不在前台时它们不轮询（见 `lib/polling.ts`）。 */
export const q = {
  status: () =>
    queryOptions({ queryKey: keys.status, queryFn: ({ signal }) => api.status(undefined, signal), staleTime: 30_000 }),
  log: (query: LogQuery) => queryOptions({ queryKey: keys.log(query), queryFn: () => api.log(query) }),
  /**
   * 一页一页往前翻的操作记录：下一页从上一页最后一条的编号往前取。
   * 一页不满说明没有更早的了。
   */
  logPages: (query: Omit<LogQuery, 'before' | 'limit'>, size: number) =>
    infiniteQueryOptions({
      queryKey: keys.logPages(query, size),
      queryFn: ({ pageParam }) => api.log({ ...query, limit: size, before: pageParam }),
      initialPageParam: undefined as number | undefined,
      getNextPageParam: (last: LogEntry[]) => (last.length < size ? undefined : last.at(-1)?.id),
    }),
  networks: () => queryOptions({ queryKey: keys.networks, queryFn: api.networks }),
  overview: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.overview(network),
      queryFn: () => api.overview(network),
      refetchInterval: LIVE_INTERVAL,
    }),
  nodes: (network: NetworkId) =>
    queryOptions({ queryKey: keys.nodes(network), queryFn: () => api.nodes(network), refetchInterval: LIVE_INTERVAL }),
  node: (network: NetworkId, node: NodeId) =>
    queryOptions({
      queryKey: keys.node(network, node),
      queryFn: () => api.node(network, node),
      refetchInterval: LIVE_INTERVAL,
    }),
  routes: (network: NetworkId, node: NodeId) =>
    queryOptions({
      queryKey: keys.routes(network, node),
      queryFn: () => api.routes(network, node),
      refetchInterval: LIVE_INTERVAL,
    }),
  nodeAccess: (network: NetworkId, node: NodeId) =>
    queryOptions({ queryKey: keys.nodeAccess(network, node), queryFn: () => api.nodeAccess(network, node) }),
  /** 令牌随时可能被别处的机器用掉，跟着轮询。 */
  tokens: (network: NetworkId, all = false) =>
    queryOptions({
      queryKey: keys.tokens(network, all),
      queryFn: () => api.tokens(network, all),
      refetchInterval: LIVE_INTERVAL,
    }),
  /** 成员数随别处的改动（节点加入、删掉）变化，跟着轮询。 */
  groups: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.groups(network),
      queryFn: () => api.groups(network),
      refetchInterval: LIVE_INTERVAL,
    }),
  /** 一个分组的成员和用到它的规则：删除之前现取一次，说出会影响什么。 */
  group: (network: NetworkId, group: GroupId) =>
    queryOptions({ queryKey: keys.group(network, group), queryFn: () => api.group(network, group), staleTime: 0 }),
  rules: (network: NetworkId) => queryOptions({ queryKey: keys.rules(network), queryFn: () => api.rules(network) }),
  graph: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.graph(network),
      queryFn: () => api.accessGraph(network),
      refetchInterval: LIVE_INTERVAL,
    }),
  check: (network: NetworkId, from: NodeId, to: NodeId) =>
    queryOptions({ queryKey: keys.check(network, from, to), queryFn: () => api.accessCheck(network, from, to) }),
  /** 每个监听器带着节点报的状态。 */
  /** 代理：状态和用量随入口节点的上报变化。 */
  proxies: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.proxies(network),
      queryFn: () => api.proxies(network),
      refetchInterval: LIVE_INTERVAL,
    }),
  forwards: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.forwards(network),
      queryFn: () => api.forwards(network),
      refetchInterval: LIVE_INTERVAL,
    }),
  /** 带着两个节点报的 ice3proxy 的计数。 */
  pairs: (network: NetworkId) =>
    queryOptions({ queryKey: keys.pairs(network), queryFn: () => api.pairs(network), refetchInterval: LIVE_INTERVAL }),
  /** 一对节点，没有存下设置的也有（`stored` 是 `false`）。 */
  pair: (network: NetworkId, a: NodeId, b: NodeId) =>
    queryOptions({
      queryKey: keys.pair(network, a, b),
      queryFn: () => api.pair(network, a, b),
      refetchInterval: LIVE_INTERVAL,
    }),
  /** 出口的设置、用量、健康，和用它的节点看到的。 */
  exits: (network: NetworkId) =>
    queryOptions({ queryKey: keys.exits(network), queryFn: () => api.exits(network), refetchInterval: LIVE_INTERVAL }),
  matrix: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.matrix(network),
      queryFn: () => api.routeMatrix(network),
      refetchInterval: LIVE_INTERVAL,
    }),
  /**
   * 两个节点之间两个方向的当前路径。每取一次 controller 都要去问两端，所以不轮询，也不在窗口回到前台时自己重取：
   * 页面上有"再问一次"的按钮。
   */
  path: (network: NetworkId, from: NodeId, to: NodeId) =>
    queryOptions({
      queryKey: keys.path(network, from, to),
      queryFn: ({ signal }) => api.path(network, from, to, signal),
      staleTime: Number.POSITIVE_INFINITY,
      refetchOnWindowFocus: false,
    }),
  /** 一个测试：进行中时每秒问一次（文档说一秒就够），结束了就不再问。 */
  test: (network: NetworkId, id: number) =>
    queryOptions({
      queryKey: keys.test(network, id),
      queryFn: () => api.test(network, id),
      refetchInterval: (query) => (query.state.data?.state === 'running' ? 1000 : false),
    }),
  /** 最近的测试，新的在前；有一对节点时只要这一对的。 */
  tests: (network: NetworkId, pair?: { a: NodeId; b: NodeId }) =>
    queryOptions({
      queryKey: [...keys.tests(network), pair?.a ?? null, pair?.b ?? null],
      queryFn: () => api.tests(network, pair),
      refetchInterval: LIVE_INTERVAL,
    }),
  /** relay 之间的延迟矩阵。和路径一样每次都要现问节点：不轮询，页面上有"再问一次"。 */
  backbone: (network: NetworkId) =>
    queryOptions({
      queryKey: keys.backbone(network),
      queryFn: ({ signal }) => api.backbone(network, signal),
      staleTime: Number.POSITIVE_INFINITY,
      refetchOnWindowFocus: false,
    }),
  /** 有更新正在进行时页面会把轮询调勤（`WAITING_INTERVAL`），见 `pages/settings/updates`。 */
  update: (interval: number = LIVE_INTERVAL) =>
    queryOptions({ queryKey: keys.update, queryFn: api.updateOverview, refetchInterval: interval }),
  /** MCP 令牌到了时间自己过期，也可能在别处（`i3tctl`）被撤销，跟着轮询。 */
  mcpTokens: () => queryOptions({ queryKey: keys.mcpTokens, queryFn: api.mcpTokens, refetchInterval: LIVE_INTERVAL }),
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        refetchOnWindowFocus: true,
        // 只有"连不上"值得自动重试；controller 明确拒绝的请求再试也是一样的结果。
        retry: (failures, error) => error instanceof ApiError && error.isNetwork && failures < 2,
      },
      mutations: { retry: false },
    },
  })
}

interface ActionOptions<TData, TVars> {
  mutationFn: (vars: TVars) => Promise<TData>
  /** 成功之后弹的提示。不写、或者函数返回 `null` 就不弹：紧接着有自己的结果要显示时用。 */
  success?: string | ((data: TData, vars: TVars) => string | null)
  /**
   * 出错时弹一条不会自己消失的提示，内容是 controller 给的原因。默认开。
   * 表单把错误显示在字段旁边时关掉，免得同一句话出现两次。
   */
  toastError?: boolean
}

/**
 * 一次修改。成功之后把这个网络下的查询全部作废并等它们取回来，
 * 所以调用方 `await mutateAsync()` 回来时，页面上的列表已经是改过之后的样子。
 *
 * `network` 写 `'all'` 时作废全部网络下的查询：更新的全局操作会改到每个网络里的节点。
 * 更新的现状（`keys.update`）总是跟着作废：改一个节点也会改变按更新情况数出来的数。
 * MCP 令牌的列表（`keys.mcpTokens`）也是：删掉一个网络，只限它的令牌跟着没有了。
 */
export function useAction<TData, TVars = void>(
  network: NetworkId | 'all' | null,
  options: ActionOptions<TData, TVars>,
) {
  const client = useQueryClient()
  const { success, toastError = true } = options
  return useMutation<TData, unknown, TVars>({
    mutationFn: options.mutationFn,
    onSuccess: async (data, vars) => {
      const message = typeof success === 'function' ? success(data, vars) : success
      if (message !== undefined && message !== null) toast.success(message)
      const pending = [
        client.invalidateQueries({ queryKey: keys.networks }),
        client.invalidateQueries({ queryKey: ['log'] }),
        client.invalidateQueries({ queryKey: keys.status }),
        client.invalidateQueries({ queryKey: keys.update }),
        client.invalidateQueries({ queryKey: keys.mcpTokens }),
      ]
      if (network === 'all') pending.push(client.invalidateQueries({ queryKey: keys.everyNetwork }))
      else if (network !== null) pending.push(client.invalidateQueries({ queryKey: keys.scope(network) }))
      await Promise.all(pending)
    },
    onError: (error) => {
      if (toastError) toast.error(errorMessage(error), undefined, errorDetail(error))
    },
  })
}
