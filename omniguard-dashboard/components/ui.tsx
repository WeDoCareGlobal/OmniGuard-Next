'use client'

import { useState, useEffect } from 'react'
import { Shield, AlertCircle, CheckCircle, Zap, Globe, Heart } from 'lucide-react'

interface SystemCardProps {
  name: string
  description: string
  path: string
  thumbnail?: string
  status: 'healthy' | 'degraded' | 'unknown'
  zenodoDOI?: string
}

export function SystemCard({ name, description, path, thumbnail, status, zenodoDOI }: SystemCardProps) {
  const statusColors = {
    healthy: 'bg-wdcg-emerald/20 border-wdcg-emerald/50 text-wdcg-emerald',
    degraded: 'bg-yellow-500/20 border-yellow-500/50 text-yellow-500',
    unknown: 'bg-wdcg-slate/20 border-wdcg-slate/50 text-wdcg-slate',
  }

  const statusIcons = {
    healthy: CheckCircle,
    degraded: AlertCircle,
    unknown: Shield,
  }

  const StatusIcon = statusIcons[status]

  return (
    <div className={`group relative p-6 rounded-xl border transition-all duration-300 ${statusColors[status]} hover:border-opacity-100 hover:shadow-lg hover:shadow-wdcg-cyan/10`}>
      {thumbnail && (
        <div className="absolute inset-0 opacity-0 group-hover:opacity-5 transition-opacity duration-300">
          <img
            src={thumbnail}
            alt={`${name} thumbnail`}
            className="w-full h-full object-cover rounded-xl"
          />
        </div>
      )}
      <div className="relative z-10 space-y-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <h3 className="text-xl font-semibold text-white">{name}</h3>
            <p className="text-wdcg-slate text-sm">{description}</p>
          </div>
          <StatusIcon className={`w-6 h-6 ${statusColors[status].replace('bg-', 'text-').replace('border-', 'text-').split(' ')[0]}`} />
        </div>
        <div className="flex items-center gap-2 text-xs text-wdcg-slate">
          {zenodoDOI && (
            <a
              href={`https://doi.org/${zenodoDOI}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 hover:text-wdcg-cyan transition-colors"
            >
              <Globe className="w-3 h-3" />
              <span>DOI: {zenodoDOI}</span>
            </a>
          )}
        </div>
        <a
          href={path}
          className="inline-flex items-center gap-2 text-wdcg-cyan hover:text-white transition-colors font-medium group"
        >
          View Dashboard
          <Zap className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
        </a>
      </div>
    </div>
  )
}

interface HeaderProps {
  gatewayHealth: 'healthy' | 'unhealthy' | 'checking'
}

export function Header({ gatewayHealth }: HeaderProps) {
  const healthColors = {
    healthy: 'bg-wdcg-emerald/20 text-wdcg-emerald border-wdcg-emerald/50',
    unhealthy: 'bg-red-500/20 text-red-500 border-red-500/50',
    checking: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50',
  }

  const healthLabels = {
    healthy: 'Gateway Healthy',
    unhealthy: 'Gateway Unhealthy',
    checking: 'Checking Gateway...',
  }

  const healthIcons = {
    healthy: CheckCircle,
    unhealthy: AlertCircle,
    checking: Shield,
  }

  const HealthIcon = healthIcons[gatewayHealth]

  return (
    <header className="border-b border-white/10 bg-wdcg-navy/95 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-wdcg-cyan" />
              <div>
                <h1 className="text-xl font-bold text-white">OmniGuard</h1>
                <p className="text-xs text-wdcg-slate">Unified AI Security & Governance</p>
              </div>
            </div>
            <div className="hidden md:flex items-center gap-3 px-3 py-1.5 rounded-full bg-wdcg-cyan/10 border border-wdcg-cyan/30">
              <Heart className="w-4 h-4 text-wdcg-cyan" />
              <span className="text-sm font-medium text-wdcg-cyan">33% Humanitarian Revenue Pledge</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border ${healthColors[gatewayHealth]}`}>
              <HealthIcon className="w-4 h-4" />
              <span className="text-sm font-medium">{healthLabels[gatewayHealth]}</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  )
}