import { ChevronDown, Download } from 'lucide-react'
import { useState } from 'react'

import { CopyButton } from '@/components/copy'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'

const d = t.diagnosis

type Format = 'text' | 'json'

/** 把一段文字存成文件：浏览器的下载。 */
function save(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/**
 * 完整输出：一份文本报告（贴给别人看）和一份 JSON（原样的数据），可以复制、下载。平时收着，只有一行标题；
 * 点标题展开。文件名带上两个节点和时刻，存了几份也分得开。报告是展开时才算的。
 */
export function Output({
  report,
  fileBase,
  className,
}: {
  report: () => { text: string; json: string }
  fileBase: string
  className?: string
}) {
  const [open, setOpen] = useState(false)
  const [format, setFormat] = useState<Format>('text')
  const content = open ? report() : null
  const value = content === null ? '' : format === 'text' ? content.text : content.json
  return (
    <section
      className={cn('min-w-0 overflow-hidden rounded-lg border bg-card', className)}
      data-testid="diagnosis-output"
    >
      <header className="flex min-h-10 flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-1.5">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex min-w-0 items-center gap-2 rounded-sm text-[13px] font-semibold"
        >
          <span className="shrink-0 whitespace-nowrap">{d.sections.raw}</span>
          <ChevronDown
            className={cn('size-3.5 shrink-0 text-muted-foreground transition-transform', !open && '-rotate-90')}
            aria-hidden
          />
          <span className="truncate text-xs font-normal text-muted-foreground">{d.outputHint}</span>
        </button>
        {open ? (
          <div className="flex shrink-0 items-center gap-2">
            <Segmented<Format>
              size="sm"
              aria-label={d.sections.raw}
              value={format}
              onChange={setFormat}
              options={[
                { value: 'text', label: d.outputText },
                { value: 'json', label: d.outputJson },
              ]}
            />
            <CopyButton value={value} size="sm">
              {d.copy}
            </CopyButton>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                format === 'text'
                  ? save(`${fileBase}.txt`, value, 'text/plain;charset=utf-8')
                  : save(`${fileBase}.json`, value, 'application/json')
              }
            >
              <Download aria-hidden />
              {d.download}
            </Button>
          </div>
        ) : null}
      </header>
      {open ? (
        <pre
          className="overflow-x-auto border-t px-4 py-3 font-mono text-xs leading-relaxed whitespace-pre text-foreground"
          data-testid={`diagnosis-output-${format}`}
        >
          {value}
        </pre>
      ) : null}
    </section>
  )
}
