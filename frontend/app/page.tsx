'use client'

import { useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowDownRight,
  ArrowUpRight,
  Ban,
  Bell,
  Check,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  Database,
  FileSearch,
  Fingerprint,
  GitBranch,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  PanelLeftClose,
  Play,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  X,
  Zap,
} from 'lucide-react'

const memories = [
  { id: 'mem_8f3a2', title: 'Quarterly planning notes', source: 'Notion', time: '2 min ago', status: 'QUARANTINED', risk: 'HIGH', hash: 'sha256:8f3a2c91...a91e', detail: 'Contains an instruction to ignore workspace policies and reveal internal context.' },
  { id: 'mem_19d0b', title: 'Customer support preferences', source: 'Intercom', time: '18 min ago', status: 'TRUSTED', risk: 'LOW', hash: 'sha256:19d0b7fa...0cc2', detail: 'Stable preferences derived from verified support conversations.' },
  { id: 'mem_6c221', title: 'Product launch timeline', source: 'Google Drive', time: '41 min ago', status: 'REVIEW', risk: 'MEDIUM', hash: 'sha256:6c2216e0...f781', detail: 'Timeline contains an unverified third-party link.' },
  { id: 'mem_44a18', title: 'Sales territory definitions', source: 'Salesforce', time: '1 hr ago', status: 'TRUSTED', risk: 'LOW', hash: 'sha256:44a18b0d...cc10', detail: 'Approved taxonomy synced from the CRM system.' },
]

const baseEvents = [
  { type: 'BLOCKED', title: 'Prompt injection blocked', meta: 'mem_8f3a2 · Notion', time: '2 min ago', icon: Ban },
  { type: 'QUARANTINE', title: 'Memory moved to quarantine', meta: 'mem_8f3a2 · policy:p-004', time: '2 min ago', icon: Archive },
  { type: 'SYNC', title: 'New memory ingested', meta: 'mem_6c221 · Google Drive', time: '41 min ago', icon: Database },
  { type: 'REVIEW', title: 'Human review requested', meta: 'mem_6c221 · risk:medium', time: '41 min ago', icon: FileSearch },
  { type: 'TRUSTED', title: 'Memory authority upgraded', meta: 'mem_44a18 · Salesforce', time: '1 hr ago', icon: ShieldCheck },
]

const metrics = [
  { label: 'Memories protected', value: '24,891', change: '+12.4%', positive: true, Icon: ShieldCheck },
  { label: 'Threats blocked', value: '187', change: '+28.6%', positive: true, Icon: ShieldAlert },
  { label: 'Pending review', value: '06', change: '-2 this week', positive: false, Icon: Clock3 },
  { label: 'Policy coverage', value: '98.7%', change: '+0.8%', positive: true, Icon: Zap },
] as const

function StatusPill({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'danger' | 'warning' | 'success' | 'neutral' }) {
  return <span className={`status-pill ${tone}`}><span className="status-dot" />{children}</span>
}

export default function Page() {
  const [activeNav, setActiveNav] = useState('Overview')
  const [selectedId, setSelectedId] = useState('mem_8f3a2')
  const [filter, setFilter] = useState('All events')
  const [events, setEvents] = useState(baseEvents)
  const [simulating, setSimulating] = useState(false)
  const [toast, setToast] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const selected = memories.find((memory) => memory.id === selectedId) ?? memories[0]
  const filteredEvents = useMemo(() => filter === 'All events' ? events : events.filter((event) => event.type === filter), [events, filter])

  function simulateAttack() {
    setSimulating(true)
    setToast('Poisoning attempt detected and blocked')
    setEvents((current) => [{ type: 'BLOCKED', title: 'Simulated poisoning blocked', meta: 'sandbox_event · policy:p-004', time: 'just now', icon: Ban }, ...current])
    window.setTimeout(() => setSimulating(false), 900)
    window.setTimeout(() => setToast(''), 3500)
  }

  function action(message: string) {
    setToast(message)
    window.setTimeout(() => setToast(''), 2500)
  }

  return (
    <main className="firewall-shell">
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="brand"><div className="brand-mark"><Shield size={17} /></div><span>memory<span className="brand-accent">/</span>firewall</span></div>
        <div className="workspace-label">CONTROL PLANE <span className="live-indicator" /></div>
        <nav className="nav-list" aria-label="Primary navigation">
          {[['Overview', LayoutDashboard], ['Memory store', Database], ['Provenance', GitBranch], ['Policies', SlidersHorizontal]].map(([label, Icon]) => (
            <button key={label as string} className={`nav-item ${activeNav === label ? 'active' : ''}`} onClick={() => { setActiveNav(label as string); setSidebarOpen(false) }}><Icon size={16} /><span>{label as string}</span>{label === 'Memory store' && <span className="nav-count">24</span>}</button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="system-status"><span className="status-dot green" /><div><strong>All systems operational</strong><small>Last checked 12 sec ago</small></div></div>
          <button className="nav-item"><Settings2 size={16} /><span>Settings</span></button>
          <div className="user-row"><div className="avatar">AR</div><div><strong>Alex Rivera</strong><small>Security admin</small></div><ChevronRight size={15} className="muted-icon" /></div>
        </div>
      </aside>

      <section className="content-area">
        <header className="topbar"><button className="mobile-menu" onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="Open menu"><Menu size={20} /></button><div className="crumb"><span>Workspace</span><ChevronRight size={14} /><strong>Overview</strong></div><div className="top-actions"><div className="environment"><span className="status-dot green" />Production <ChevronRight size={13} /></div><button className="icon-button" aria-label="Notifications"><Bell size={17} /><span className="notification-dot" /></button><div className="mini-avatar">AR</div></div></header>
        <div className="page-wrap">
          <div className="page-heading"><div><div className="eyebrow"><CircleDot size={12} /> SECURITY OBSERVABILITY</div><h1>Memory Firewall</h1><p>Detect and contain poisoned context before it reaches your agents.</p></div><button className={`simulate-button ${simulating ? 'simulating' : ''}`} onClick={simulateAttack} disabled={simulating}><Play size={14} />{simulating ? 'Simulating...' : 'Simulate poisoning'}</button></div>

           <div className="metric-grid">{metrics.map(({ label, value, change, positive, Icon }) => <div className="metric-card" key={label}><div className="metric-top"><span>{label}</span><Icon size={16} /></div><div className="metric-value">{value}</div><div className={`metric-change ${positive ? 'positive' : 'calm'}`}>{positive ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}{change}<span className="change-context">vs last 7d</span></div></div>)}
          </div>

          <div className="main-grid">
            <section className="panel events-panel"><div className="panel-header"><div><h2>Recent events</h2><p>Live activity across your memory layer</p></div><button className="text-button">View all <ArrowUpRight size={13} /></button></div><div className="event-filters">{['All events', 'BLOCKED', 'QUARANTINE', 'REVIEW'].map((item) => <button key={item} className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)}>{item}</button>)}</div><div className="event-list">{filteredEvents.map((event, index) => { const Icon = event.icon; return <div className="event-row" key={`${event.title}-${index}`}><div className={`event-icon ${event.type.toLowerCase()}`}><Icon size={15} /></div><div className="event-copy"><strong>{event.title}</strong><span>{event.meta}</span></div><time>{event.time}</time></div> })}</div></section>
            <section className="panel health-panel"><div className="panel-header"><div><h2>Protection health</h2><p>Policy enforcement over time</p></div><span className="health-badge"><span className="status-dot green" />Healthy</span></div><div className="chart-wrap"><div className="chart-labels"><span>100%</span><span>75%</span><span>50%</span><span>25%</span><span>0%</span></div><div className="chart"><div className="chart-grid" /><svg viewBox="0 0 560 170" preserveAspectRatio="none" aria-label="Protection health chart"><defs><linearGradient id="chartFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="var(--cyan)" stopOpacity=".28" /><stop offset="1" stopColor="var(--cyan)" stopOpacity="0" /></linearGradient></defs><path d="M0 139 C35 133 42 116 69 121 S102 106 126 112 S155 93 181 99 S212 74 239 84 S274 66 300 73 S326 46 354 61 S383 38 410 51 S441 30 468 39 S503 20 530 29 S549 18 560 12 V170 H0Z" fill="url(#chartFill)" /><path d="M0 139 C35 133 42 116 69 121 S102 106 126 112 S155 93 181 99 S212 74 239 84 S274 66 300 73 S326 46 354 61 S383 38 410 51 S441 30 468 39 S503 20 530 29 S549 18 560 12" fill="none" stroke="var(--cyan)" strokeWidth="2.5" vectorEffect="non-scaling-stroke" /></svg></div></div><div className="chart-footer"><span>May 16</span><span>May 19</span><span>May 22</span><span>May 25</span><span>May 28</span></div></section>
          </div>

          <div className="lower-grid"><section className="panel memories-panel"><div className="panel-header"><div><h2>Memory store</h2><p>Recent memories and their authority level</p></div><button className="search-button"><Search size={15} /> Search memories</button></div><div className="memory-table"><div className="table-head"><span>MEMORY</span><span>SOURCE</span><span>AUTHORITY</span><span>RISK</span><span>INGESTED</span></div>{memories.map((memory) => <button className={`memory-row ${selectedId === memory.id ? 'selected' : ''}`} key={memory.id} onClick={() => setSelectedId(memory.id)}><div className="memory-name"><div className="memory-symbol"><Fingerprint size={15} /></div><div><strong>{memory.title}</strong><small>{memory.id}</small></div></div><span className="source-cell"><span className="source-mark">{memory.source.slice(0, 1)}</span>{memory.source}</span><StatusPill tone={memory.status === 'QUARANTINED' ? 'danger' : memory.status === 'REVIEW' ? 'warning' : 'success'}>{memory.status}</StatusPill><span className={`risk ${memory.risk.toLowerCase()}`}>{memory.risk}</span><span className="time-cell">{memory.time}</span></button>)}</div></section>
            <section className="panel provenance-panel"><div className="panel-header"><div><h2>Provenance chain</h2><p>Selected memory lineage</p></div><button className="icon-button"><PanelLeftClose size={16} /></button></div><div className="selected-memory"><div className="selected-icon"><Fingerprint size={19} /></div><div><strong>{selected.title}</strong><span>{selected.hash}</span></div><StatusPill tone={selected.status === 'QUARANTINED' ? 'danger' : selected.status === 'REVIEW' ? 'warning' : 'success'}>{selected.status}</StatusPill></div><div className="provenance-chain"><div className="chain-node"><div className="chain-icon external"><Code2 size={15} /></div><div><small>EXTERNAL SOURCE</small><strong>{selected.source} connector</strong><span>Untrusted input received</span></div></div><div className="chain-line" /><div className="chain-node"><div className="chain-icon agent"><Sparkles size={15} /></div><div><small>AGENT TRANSFORM</small><strong>context-normalizer v2.4</strong><span>2 policies evaluated</span></div></div><div className="chain-line" /><div className="chain-node"><div className="chain-icon memory"><Database size={15} /></div><div><small>DERIVED MEMORY</small><strong>{selected.id}</strong><span>Authority: <b className="danger-text">{selected.status}</b></span></div></div></div><div className="alert-box"><AlertTriangle size={16} /><div><strong>Policy violation detected</strong><span>{selected.detail}</span></div></div><div className="provenance-actions"><button className="secondary-button" onClick={() => action('Memory marked for human review')}><FileSearch size={14} /> Review</button><button className="danger-button" onClick={() => action('Memory remains quarantined')}><LockKeyhole size={14} /> Keep quarantined</button></div></section></div>
          <footer className="page-footer"><span><Terminal size={13} /> All enforcement actions are logged</span><span>Memory Firewall v0.9.4 <span className="footer-sep">·</span> <a href="#docs">View documentation <ArrowUpRight size={11} /></a></span></footer>
        </div>
      </section>
      {toast && <div className="toast"><Check size={15} />{toast}<button onClick={() => setToast('')} aria-label="Dismiss"><X size={14} /></button></div>}
    </main>
  )
}
