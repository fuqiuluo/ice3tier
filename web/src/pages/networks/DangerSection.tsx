import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Network } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { Button } from '@/components/ui/button'
import { BoxCard } from '@/components/ui/card'
import { t } from '@/i18n'

import { networkPath } from './context'

const n = t.networks

/**
 * 删除网络：整站唯一需要输入名字的确认，因为它一次毁掉一批东西且无法撤回。
 * controller 只删空的网络，所以网络里还有节点时按钮是灰的，旁边写明要先做什么，不等提交了再报错。
 */
export function DangerSection({ network }: { network: Network }) {
  const confirm = useConfirm()
  const navigate = useNavigate()
  const overview = useQuery(q.overview(network.id))
  const remove = useAction(null, {
    mutationFn: () => api.deleteNetwork(network.id),
    success: n.deleted(network.name),
  })

  const onDelete = async () => {
    const counts = overview.data
    const confirmed = await confirm({
      tone: 'danger',
      title: n.deleteTitle(network.name),
      body: counts === undefined ? n.dangerBody : n.deleteBody(counts.rules, counts.proxies, counts.pending_tokens),
      confirmLabel: n.deleteConfirm,
      typeToConfirm: network.name,
    })
    if (!confirmed) return
    remove.mutate(undefined, { onSuccess: () => void navigate('/', { replace: true }) })
  }

  return (
    <BoxCard aria-labelledby="network-danger-title">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3 px-5 py-4">
        <div className="min-w-0">
          <h2 id="network-danger-title" className="text-[15px] leading-6 font-semibold">
            {n.dangerTitle}
          </h2>
          <p className="mt-0.5 text-[13px] text-muted-foreground">
            {network.nodes > 0 ? n.dangerNotEmpty(network.nodes) : n.dangerBody}
            {network.nodes > 0 ? (
              <>
                {' · '}
                <Link
                  to={networkPath(network.id, 'nodes')}
                  className="rounded-sm text-primary underline-offset-4 hover:underline"
                >
                  {n.viewNodes}
                </Link>
              </>
            ) : null}
          </p>
        </div>
        <Button
          size="sm"
          variant="danger-outline"
          disabled={network.nodes > 0}
          pending={remove.isPending}
          onClick={() => void onDelete()}
        >
          {n.deleteButton}
        </Button>
      </div>
    </BoxCard>
  )
}
