import { useState } from 'react'

import { type Network } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { Button } from '@/components/ui/button'
import { Dialog, DialogBody, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { t } from '@/i18n'

import { AddNodeFlow, type AddNodeState } from './AddNodeFlow'

interface AddNodeDialogProps {
  network: Network
  open: boolean
  onClose: () => void
}

/**
 * "添加节点"对话框，令牌只在这里生成、吊销：单独一个令牌没有用，用户总是需要令牌和命令一起，
 * 所以没有单独的令牌页。令牌一次性、默认 24 小时过期。
 *
 * 令牌生成之后、节点加入之前，这个对话框不能用 Esc 误关：令牌只在这里显示这一次。
 * 这时点"完成"会先问一句。关掉时不自动吊销：命令可能已经复制走了；不打算用了在第 2 步点"吊销"。
 */
export function AddNodeDialog({ network, open, onClose }: AddNodeDialogProps) {
  const confirm = useConfirm()
  const [state, setState] = useState<AddNodeState>({ tokenOutstanding: false })

  const close = () => {
    setState({ tokenOutstanding: false })
    onClose()
  }

  const requestClose = async () => {
    if (state.tokenOutstanding) {
      const leave = await confirm({
        title: t.addNode.closeWhileWaitingTitle,
        body: t.addNode.closeWhileWaitingBody,
        confirmLabel: t.addNode.closeWhileWaitingConfirm,
        cancelLabel: t.addNode.closeWhileWaitingCancel,
      })
      if (!leave) return
    }
    close()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? undefined : void requestClose())}>
      <DialogContent title={t.addNode.title} dismissible={!state.tokenOutstanding} className="md:max-w-2xl">
        <DialogBody>
          {/* 每次打开都是一份新的状态：上一次生成的令牌不会留在这里。 */}
          {open ? <AddNodeFlow network={network} onStateChange={setState} onNavigate={close} /> : null}
        </DialogBody>
        <DialogFooter>
          <Button onClick={() => void requestClose()}>{t.addNode.done}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
