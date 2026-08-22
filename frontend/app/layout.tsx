import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import { Public_Sans, Unbounded } from 'next/font/google'
import './globals.css'

const publicSans = Public_Sans({ subsets: ['latin'], variable: '--font-public-sans' })
const unbounded = Unbounded({ subsets: ['latin'], variable: '--font-unbounded' })

export const metadata: Metadata = {
  title: 'Provenance Firewall — Authorize the source, not only the agent',
  description: 'Deterministic source-trust authorization for AI agent tool calls.',
}

export const viewport: Viewport = {
  colorScheme: 'light',
  themeColor: '#f4f1e7',
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${publicSans.variable} ${unbounded.variable}`}>
        <template
          dangerouslySetInnerHTML={{
            __html: `<!--
THESIS: Chain-of-custody evidence makes source authority visible and refuses the generic SaaS security dashboard.
OWN-WORLD: Mineral paper, custody blue, evidence yellow, failure red, square forms, stamps, perforations, and signed ledgers.
STORY: Judges see 50,000 records become zero, trace the source, then operate the live middleware and its memory layer.
FIRST VIEWPORT: A split statement faces an oversized evidence label; the protected action sits beside the fixed 50,000 to 0 comparison.
FORM: Chain of Custody, grounded direction 1, seed 9bee9400.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
-->`,
          }}
        />
        {children}
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
