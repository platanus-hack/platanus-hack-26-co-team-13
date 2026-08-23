import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Mi actividad',
  description: 'Resumen y registro firmado de todo lo que el firewall bloqueó o permitió en tu espacio.',
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return children
}
