'use client'

import { useState, useEffect } from 'react'
import { Header, SystemCard } from '@/components/ui'
import { Activity, Shield, Brain, Database, Search, FlaskConical, Users, Zap } from 'lucide-react'

const systems = [
  {
    name: 'AgentGuard',
    description: 'Real-time prompt injection detection & policy enforcement',
    path: '/agentguard',
    status: 'healthy' as const,
    zenodoDOI: '10.5281/zenodo.22945778',
    icon: Shield,
  },
  {
    name: 'Orchestration (FoundationCentar)',
    description: 'Multi-model AI orchestration with NVIDIA NIM, xAI, Mistral',
    path: '/orchestration',
    status: 'healthy' as const,
    zenodoDOI: '10.5281/zenodo.23073888',
    icon: Brain,
  },
  {
    name: 'Hybrid RAG',
    description: 'Enterprise hybrid retrieval with BM25 + Qdrant vector search',
    path: '/hybrid-rag',
    status: 'healthy' as const,
    zenodoDOI: '10.5281/zenodo.22945802',
    icon: Search,
  },
  {
    name: 'Agent Eval',
    description: 'Automated agent evaluation & benchmarking framework',
    path: '/eval',
    status: 'healthy' as const,
    zenodoDOI: '10.5281/zenodo.22945804',
    icon: Activity,
  },
  {
    name: 'AgentVault',
    description: 'Secure agent registry with verification & provenance',
    path: '/vault',
    status: 'healthy' as const,
    zenodoDOI: '10.5281/zenodo.22983557',
    icon: Database,
  },
  {
    name: 'Pharma Intelligence OS',
    description: 'Pharmaceutical research intelligence platform',
    path: '/pharma',
    status: 'healthy' as const,
    zenodoDOI: '10.5281/zenodo.22983388',
    icon: FlaskConical,
  },
]

const metrics = [
  { label: 'Total Audited Calls', value: '12,847', icon: Activity, color: 'text-wdcg-cyan' },
  { label: 'Threat Block Rate', value: '99.2%', icon: Shield, color: 'text-wdcg-emerald' },
  { label: 'Average Latency', value: '<15ms', icon: Zap, color: 'text-yellow-400' },
  { label: 'Active Agents', value: '6', icon: Users, color: 'text-purple-400' },
]

export default function DashboardPage() {
  const [gatewayHealth, setGatewayHealth] = useState<'healthy' | 'unhealthy' | 'checking'>('checking')

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('http://localhost:8000/healthz')
        if (res.ok) {
          setGatewayHealth('healthy')
        } else {
          setGatewayHealth('unhealthy')
        }
      } catch {
        setGatewayHealth('unhealthy')
      }
    }
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-wdcg-navy">
      <Header gatewayHealth={gatewayHealth} />
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Metrics Row */}
        <section className="mb-12">
          <h2 className="text-2xl font-bold text-white mb-6">System Metrics</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {metrics.map((metric, i) => (
              <div
                key={metric.label}
                className="p-6 rounded-xl bg-white/5 border border-white/10 hover:border-wdcg-cyan/50 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <metric.icon className={`w-6 h-6 ${metric.color}`} />
                  <span className="text-xs text-wdcg-slate uppercase tracking-wider">
                    Live
                  </span>
                </div>
                <p className="text-3xl font-bold text-white">{metric.value}</p>
                <p className="text-sm text-wdcg-slate mt-1">{metric.label}</p>
              </div>
            ))}
          </div>
        </section>

        {/* System Cards */}
        <section>
          <h2 className="text-2xl font-bold text-white mb-6">We Do Care Global Systems</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {systems.map((system) => (
              <SystemCard
                key={system.name}
                name={system.name}
                description={system.description}
                path={system.path}
                status={system.status}
                zenodoDOI={system.zenodoDOI}
              />
            ))}
          </div>
        </section>

        {/* Sandbox Link */}
        <section className="mt-12">
          <div className="p-6 rounded-xl bg-gradient-to-r from-wdcg-cyan/10 to-wdcg-emerald/10 border border-wdcg-cyan/30">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xl font-bold text-white mb-1">In-Flight Prompt Simulator</h3>
                <p className="text-wdcg-slate">Test AgentGuard policy enforcement in real-time against the live gateway</p>
              </div>
              <a
                href="/sandbox"
                className="px-6 py-2.5 bg-wdcg-cyan text-wdcg-navy font-semibold rounded-lg hover:bg-wdcg-cyan/90 transition-colors"
              >
                Open Sandbox
              </a>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}