import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import { Instrument_Sans, Space_Grotesk } from 'next/font/google'
import './globals.css'

const instrumentSans = Instrument_Sans({ subsets: ['latin'], variable: '--font-instrument-sans' })
const spaceGrotesk = Space_Grotesk({ subsets: ['latin'], weight: ['400', '500', '600', '700'], variable: '--font-space-grotesk' })

export const metadata: Metadata = {
  title: 'Memory Firewall — Security Observability',
  description: 'Detect and contain poisoned context before it reaches your agents.',
  generator: 'v0.app',
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#081019',
  userScalable: false,
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="bg-background">
      <body className={`${instrumentSans.variable} ${spaceGrotesk.variable} antialiased`}>
        {children}
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
