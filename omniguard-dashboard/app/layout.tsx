import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { Heart } from 'lucide-react'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'OmniGuard Dashboard | We Do Care Global',
  description: 'Unified AI Security & Governance Dashboard',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} bg-wdcg-navy text-white min-h-screen`}>
        {/* Global pledge banner — visible at every viewport width, on every page.
            The in-header badge in components/ui.tsx is hidden below md, so this
            strip is what guarantees the 33% pledge is always on screen. */}
        <div className="w-full bg-wdcg-cyan/10 border-b border-wdcg-cyan/30">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex items-center justify-center gap-2 text-center">
            <Heart className="w-4 h-4 text-wdcg-cyan shrink-0" />
            <span className="text-sm font-medium text-wdcg-cyan">
              33% Humanitarian Revenue Pledge
            </span>
            <span className="hidden sm:inline text-xs text-wdcg-slate">
              — one third of revenue funds relief for people in need
            </span>
          </div>
        </div>
        {children}
      </body>
    </html>
  )
}
