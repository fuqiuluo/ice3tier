import { useState } from 'react'
import './demo.css'

const TEXT = {
  'zh-CN': {
    rate: '每秒收到的包',
    threshold: 'QUIC 确认阈值',
    delay: 'QUIC 确认最长等待',
    packets: '个包',
    ms: '毫秒',
    data: '收到的包',
    ack: '发回的确认',
    perAck: (n: number) => `每 ${n} 个包发一个确认`,
    perSecond: (n: string) => `每秒 ${n} 个确认包`,
    byThreshold: '攒够了数就发',
    byTimer: '没攒够，等到点才发',
    note: '按包匀速到达算的示意，不是实测。',
  },
  en: {
    rate: 'Packets received per second',
    threshold: 'QUIC ACK threshold',
    delay: 'QUIC max ACK delay',
    packets: 'packets',
    ms: 'ms',
    data: 'Packets received',
    ack: 'ACKs sent back',
    perAck: (n: number) => `One ACK per ${n} packets`,
    perSecond: (n: string) => `${n} ACK packets per second`,
    byThreshold: 'Sent when the count is reached',
    byTimer: 'Count not reached: sent when the delay runs out',
    note: 'A sketch that assumes evenly spaced packets, not a measurement.',
  },
}

const SHOWN = 48

/** 确认阈值和最长等待怎么决定确认包的多少：包匀速到达时，攒够数或者等到点，哪个先到就发。 */
export default function AckDemo({ lang = 'zh-CN' }: { lang?: keyof typeof TEXT }) {
  const t = TEXT[lang]
  const [rate, setRate] = useState(2000)
  const [threshold, setThreshold] = useState(3)
  const [delay, setDelay] = useState(2)

  const gap = 1000 / rate
  const byCount = threshold + 1
  const byTimer = Math.floor(delay / gap) + 1
  const perAck = Math.min(byCount, byTimer)
  const acksPerSecond = rate / perAck

  return (
    <div className="not-content i3t-demo">
      <div className="i3t-demo-controls">
        <Slider label={t.rate} value={rate} min={100} max={20000} step={100} unit={t.packets} onChange={setRate} />
        <Slider label={t.threshold} value={threshold} min={1} max={100} step={1} unit={t.packets} onChange={setThreshold} />
        <Slider label={t.delay} value={delay} min={1} max={25} step={1} unit={t.ms} onChange={setDelay} />
      </div>

      <div className="i3t-demo-lanes">
        <span className="i3t-demo-lane-label">{t.data}</span>
        <div className="i3t-demo-lane">
          {Array.from({ length: SHOWN }, (_, i) => (
            <i key={i} className="i3t-demo-packet" />
          ))}
        </div>
        <span className="i3t-demo-lane-label">{t.ack}</span>
        <div className="i3t-demo-lane">
          {Array.from({ length: SHOWN }, (_, i) => (
            <i key={i} className={(i + 1) % perAck === 0 ? 'i3t-demo-ack' : 'i3t-demo-gap'} />
          ))}
        </div>
      </div>

      <p className="i3t-demo-result">
        <strong>{t.perAck(perAck)}</strong>
        <span>{t.perSecond(formatCount(acksPerSecond))}</span>
        <span>{byCount <= byTimer ? t.byThreshold : t.byTimer}</span>
      </p>
      <p className="i3t-demo-note">{t.note}</p>
    </div>
  )
}

function Slider(props: {
  label: string
  value: number
  min: number
  max: number
  step: number
  unit: string
  onChange: (value: number) => void
}) {
  return (
    <label className="i3t-demo-slider">
      <span>{props.label}</span>
      <input
        type="range"
        min={props.min}
        max={props.max}
        step={props.step}
        value={props.value}
        onChange={(event) => props.onChange(Number(event.target.value))}
      />
      <output>
        {props.value} {props.unit}
      </output>
    </label>
  )
}

function formatCount(value: number): string {
  return value >= 100 ? Math.round(value).toString() : value.toFixed(1)
}
