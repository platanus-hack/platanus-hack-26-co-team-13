import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Demo del correo malicioso',
  description:
    'Redacta un correo, entrégalo al buzón del agente y observa cómo la puerta de ejecución bloquea la acción de riesgo.',
}

export default function DemoLayout({ children }: { children: React.ReactNode }) {
  return children
}
