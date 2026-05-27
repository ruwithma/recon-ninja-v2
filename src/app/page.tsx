'use client'

import { useState } from 'react'

const PHASES = [
  { num: 0, name: 'Pre-flight', desc: 'Target validation, VPN check, tool inventory, SecLists detection' },
  { num: 1, name: 'Port Discovery', desc: 'RustScan / Nmap fast SYN scan for open ports' },
  { num: 2, name: 'Deep Nmap', desc: 'Full service enumeration with -sC -sV -O + box classification' },
  { num: 3, name: 'Service Modules', desc: '16 protocol-specific modules dispatched concurrently' },
  { num: 4, name: 'OSINT', desc: 'DNS enumeration, subdomain discovery, email harvesting' },
  { num: 5, name: 'Vuln Correlate', desc: 'searchsploit + nuclei + NVD API enrichment' },
  { num: 6, name: 'Loot Extract', desc: 'Regex scan for creds, flags, hashes, private keys' },
  { num: 7, name: 'Reports', desc: 'Markdown + HTML + JSON report generation' },
]

const MODULES = [
  { name: 'Web', tools: 'whatweb, nikto, feroxbuster, gobuster, ffuf, nuclei, wpscan', ports: '80, 443, 8080+', color: '#22c55e' },
  { name: 'SMB', tools: 'enum4linux-ng, smbclient, smbmap, crackmapexec', ports: '139, 445', color: '#eab308' },
  { name: 'SSH', tools: 'ssh-audit, nmap scripts', ports: '22', color: '#06b6d4' },
  { name: 'FTP', tools: 'ftp, nmap scripts', ports: '21', color: '#f97316' },
  { name: 'SMTP', tools: 'smtp-enum, nmap scripts', ports: '25, 465, 587', color: '#ef4444' },
  { name: 'SNMP', tools: 'snmpwalk, onesixtyone', ports: 'UDP 161', color: '#a855f7' },
  { name: 'DNS', tools: 'dnsrecon, dig', ports: '53', color: '#3b82f6' },
  { name: 'LDAP', tools: 'ldapsearch, windapsearch', ports: '389, 636', color: '#ec4899' },
  { name: 'Kerberos', tools: 'kerbrute, nmap scripts', ports: '88', color: '#ef4444' },
  { name: 'RPC', tools: 'rpcclient, nmap scripts', ports: '111, 135', color: '#14b8a6' },
  { name: 'NFS', tools: 'showmount, nmap scripts', ports: '2049', color: '#84cc16' },
  { name: 'RDP', tools: 'xfreerdp, nmap scripts', ports: '3389', color: '#6366f1' },
  { name: 'VNC', tools: 'nmap scripts', ports: '5900-5910', color: '#f43f5e' },
  { name: 'WinRM', tools: 'crackmapexec, nmap scripts', ports: '5985, 5986', color: '#0ea5e9' },
  { name: 'Database', tools: 'nmap scripts', ports: '3306, 1433, 5432, 6379', color: '#8b5cf6' },
  { name: 'SSL', tools: 'sslscan, testssl.sh', ports: 'HTTPS', color: '#10b981' },
  { name: 'OSINT', tools: 'subfinder, theHarvester, dnsrecon', ports: 'Domain targets', color: '#f59e0b' },
  { name: 'Vuln Correlate', tools: 'searchsploit, nuclei, NVD API', ports: 'All services', color: '#dc2626' },
]

const BOX_PROFILES = [
  { name: 'WINDOWS_AD', criteria: 'Kerberos + LDAP + SMB + WinRM', color: '#3b82f6' },
  { name: 'WINDOWS_WEB', criteria: 'IIS detected, no Kerberos', color: '#6366f1' },
  { name: 'LINUX_WEB', criteria: 'SSH + HTTP, no SMB', color: '#22c55e' },
  { name: 'LINUX_AD', criteria: 'SMB + LDAP, no Kerberos', color: '#eab308' },
  { name: 'LINUX_SERVER', criteria: 'SSH only, no HTTP', color: '#64748b' },
]

const QUICK_COMMANDS = [
  { cmd: 'reconninja 10.10.11.58', desc: 'Standard scan' },
  { cmd: 'reconninja 10.10.11.58 --htb --add-hosts', desc: 'HackTheBox mode' },
  { cmd: 'reconninja 10.10.11.58 --fast', desc: 'Fast scan (top-1000 ports)' },
  { cmd: 'reconninja 10.10.11.58 --full', desc: 'Full scan with all modules' },
  { cmd: 'reconninja 10.10.11.58 --resume', desc: 'Resume interrupted scan' },
  { cmd: 'reconninja check-tools', desc: 'Check installed tools' },
  { cmd: 'reconninja install', desc: 'Auto-install all tools' },
  { cmd: 'reconninja install --required', desc: 'Install only required tools' },
]

export default function Home() {
  const [activeTab, setActiveTab] = useState<'phases' | 'modules' | 'profiles' | 'commands'>('phases')

  return (
    <div className="min-h-screen flex flex-col" style={{ background: '#0a0a0f' }}>
      {/* Header */}
      <header className="border-b border-white/10" style={{ background: '#0d0d14' }}>
        <div className="max-w-6xl mx-auto px-4 py-6">
          <div className="flex items-center gap-4">
            <div className="text-2xl font-mono px-3 py-1 rounded border" style={{ borderColor: '#00f0ff40', color: '#00f0ff', background: '#00f0ff10' }}>&gt;_</div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight" style={{ color: '#00f0ff' }}>
                RECONNINJA
                <span className="text-sm font-normal ml-2 px-2 py-0.5 rounded" style={{ background: '#00f0ff20', color: '#00f0ff' }}>v2.0.0</span>
              </h1>
              <p className="text-sm mt-1" style={{ color: '#8892a4' }}>
                Automated reconnaissance pipeline for CTFs &amp; pentesting
              </p>
            </div>
          </div>
          <div className="flex gap-3 mt-4 flex-wrap">
            <span className="text-xs px-2 py-1 rounded-full border" style={{ borderColor: '#00f0ff40', color: '#00f0ff', background: '#00f0ff10' }}>7-Phase Pipeline</span>
            <span className="text-xs px-2 py-1 rounded-full border" style={{ borderColor: '#22c55e40', color: '#22c55e', background: '#22c55e10' }}>18 Modules</span>
            <span className="text-xs px-2 py-1 rounded-full border" style={{ borderColor: '#eab30840', color: '#eab308', background: '#eab30810' }}>30+ Tools</span>
            <span className="text-xs px-2 py-1 rounded-full border" style={{ borderColor: '#a855f740', color: '#a855f7', background: '#a855f710' }}>Checkpoint/Resume</span>
            <span className="text-xs px-2 py-1 rounded-full border" style={{ borderColor: '#ef444440', color: '#ef4444', background: '#ef444410' }}>Auto Box Classification</span>
          </div>
        </div>
      </header>

      {/* Tab Navigation */}
      <nav className="border-b border-white/10 sticky top-0 z-10" style={{ background: '#0d0d14' }}>
        <div className="max-w-6xl mx-auto px-4 flex gap-0">
          {(['phases', 'modules', 'profiles', 'commands'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-5 py-3 text-sm font-medium transition-colors capitalize border-b-2"
              style={{
                borderBottomColor: activeTab === tab ? '#00f0ff' : 'transparent',
                color: activeTab === tab ? '#00f0ff' : '#8892a4',
                background: 'transparent',
              }}
            >
              {tab}
            </button>
          ))}
        </div>
      </nav>

      {/* Content */}
      <main className="flex-1 max-w-6xl mx-auto px-4 py-8 w-full">
        {activeTab === 'phases' && (
          <div className="space-y-3">
            <h2 className="text-lg font-semibold mb-4" style={{ color: '#e2e8f0' }}>7-Phase Execution Pipeline</h2>
            {PHASES.map((phase) => (
              <div
                key={phase.num}
                className="flex items-start gap-4 p-4 rounded-lg border transition-colors"
                style={{ background: '#12121a', borderColor: '#ffffff10' }}
              >
                <div
                  className="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-lg font-bold"
                  style={{ background: '#00f0ff15', color: '#00f0ff' }}
                >
                  {phase.num}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold" style={{ color: '#e2e8f0' }}>{phase.name}</h3>
                  </div>
                  <p className="text-sm mt-1" style={{ color: '#8892a4' }}>{phase.desc}</p>
                </div>
              </div>
            ))}
            <div className="mt-6 p-4 rounded-lg border" style={{ background: '#00f0ff08', borderColor: '#00f0ff20' }}>
              <p className="text-sm" style={{ color: '#8892a4' }}>
                Each phase is <span style={{ color: '#00f0ff' }}>checkpointed</span> after completion. Interrupted scans can be resumed with{' '}
                <code className="px-1.5 py-0.5 rounded text-xs" style={{ background: '#ffffff10', color: '#00f0ff' }}>--resume</code>.
                Modules run concurrently under an <code className="px-1.5 py-0.5 rounded text-xs" style={{ background: '#ffffff10', color: '#00f0ff' }}>asyncio.Semaphore</code> controlled by <code className="px-1.5 py-0.5 rounded text-xs" style={{ background: '#ffffff10', color: '#00f0ff' }}>--threads</code>.
              </p>
            </div>
          </div>
        )}

        {activeTab === 'modules' && (
          <div>
            <h2 className="text-lg font-semibold mb-4" style={{ color: '#e2e8f0' }}>18 Service Modules</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              {MODULES.map((mod) => (
                <div
                  key={mod.name}
                  className="p-4 rounded-lg border"
                  style={{ background: '#12121a', borderColor: '#ffffff10' }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ background: mod.color }}
                    />
                    <h3 className="font-semibold" style={{ color: '#e2e8f0' }}>{mod.name}</h3>
                    <span className="text-xs px-1.5 py-0.5 rounded ml-auto" style={{ background: '#ffffff08', color: '#8892a4' }}>
                      {mod.ports}
                    </span>
                  </div>
                  <p className="text-xs" style={{ color: '#6b7280' }}>{mod.tools}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'profiles' && (
          <div>
            <h2 className="text-lg font-semibold mb-4" style={{ color: '#e2e8f0' }}>Box Profile Classification</h2>
            <p className="text-sm mb-4" style={{ color: '#8892a4' }}>
              After Phase 2, the target is automatically classified into a box profile based on detected services. This drives module selection and report presentation.
            </p>
            <div className="space-y-3">
              {BOX_PROFILES.map((profile) => (
                <div
                  key={profile.name}
                  className="flex items-center gap-4 p-4 rounded-lg border"
                  style={{ background: '#12121a', borderColor: '#ffffff10' }}
                >
                  <div
                    className="flex-shrink-0 w-3 h-3 rounded-full"
                    style={{ background: profile.color }}
                  />
                  <div>
                    <h3 className="font-mono font-semibold text-sm" style={{ color: profile.color }}>{profile.name}</h3>
                    <p className="text-xs mt-0.5" style={{ color: '#8892a4' }}>{profile.criteria}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-6 p-4 rounded-lg border" style={{ background: '#12121a', borderColor: '#ffffff10' }}>
              <h3 className="font-semibold mb-2" style={{ color: '#e2e8f0' }}>Graceful Degradation</h3>
              <p className="text-sm" style={{ color: '#8892a4' }}>
                Every module checks for its required tools before running. If a tool is missing, the module returns{' '}
                <code className="px-1.5 py-0.5 rounded text-xs" style={{ background: '#ffffff10', color: '#eab308' }}>status=&quot;skipped&quot;</code>{' '}
                instead of raising an error. The pipeline always continues to the next phase.
              </p>
            </div>
          </div>
        )}

        {activeTab === 'commands' && (
          <div>
            <h2 className="text-lg font-semibold mb-4" style={{ color: '#e2e8f0' }}>Quick Commands</h2>
            <div className="space-y-2">
              {QUICK_COMMANDS.map((item) => (
                <div
                  key={item.cmd}
                  className="flex items-center gap-4 p-3 rounded-lg border"
                  style={{ background: '#12121a', borderColor: '#ffffff10' }}
                >
                  <div className="flex-1 min-w-0">
                    <code className="text-sm font-mono" style={{ color: '#00f0ff' }}>{item.cmd}</code>
                  </div>
                  <span className="text-xs flex-shrink-0" style={{ color: '#8892a4' }}>{item.desc}</span>
                </div>
              ))}
            </div>

            <h3 className="text-lg font-semibold mt-8 mb-4" style={{ color: '#e2e8f0' }}>Key Flags</h3>
            <div className="grid gap-2 sm:grid-cols-2">
              {[
                { flag: '--fast', desc: 'Top-1000 ports + basic enum only' },
                { flag: '--full', desc: 'All modules including nuclei, amass' },
                { flag: '--udp', desc: 'Enable UDP scanning (requires root)' },
                { flag: '--stealth', desc: 'Low-rate T2 timing, 200ms delay' },
                { flag: '--htb', desc: 'HackTheBox mode + VPN check' },
                { flag: '--add-hosts', desc: 'Auto /etc/hosts entries' },
                { flag: '--only-web', desc: 'Web enumeration only' },
                { flag: '--only-ports', desc: 'Phase 1+2 only, no modules' },
                { flag: '--no-vuln', desc: 'Skip vulnerability correlation' },
                { flag: '--resume', desc: 'Resume from last checkpoint' },
                { flag: '--html', desc: 'Generate styled HTML report' },
                { flag: '--proxy URL', desc: 'Route HTTP through proxy' },
              ].map((item) => (
                <div
                  key={item.flag}
                  className="flex items-center gap-3 p-3 rounded-lg border"
                  style={{ background: '#12121a', borderColor: '#ffffff10' }}
                >
                  <code className="text-xs font-mono flex-shrink-0" style={{ color: '#eab308' }}>{item.flag}</code>
                  <span className="text-xs" style={{ color: '#8892a4' }}>{item.desc}</span>
                </div>
              ))}
            </div>

            <div className="mt-8 p-4 rounded-lg border" style={{ background: '#ef444410', borderColor: '#ef444420' }}>
              <h3 className="font-semibold mb-1" style={{ color: '#ef4444' }}>Legal Disclaimer</h3>
              <p className="text-sm" style={{ color: '#8892a4' }}>
                Use only on machines and networks you own or have explicit written permission to test. Unauthorized scanning is illegal.
                HackTheBox, TryHackMe, OSCP labs, and your own home lab are the intended environments.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 mt-auto" style={{ background: '#0d0d14' }}>
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <span className="text-xs" style={{ color: '#6b7280' }}>
            Built for CTF warriors. Sharpened for pentesters.
          </span>
          <span className="text-xs" style={{ color: '#6b7280' }}>
            ReconNinja v2.0.0
          </span>
        </div>
      </footer>
    </div>
  )
}
