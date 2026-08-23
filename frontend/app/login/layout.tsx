import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Iniciar sesión',
  description: 'Accede a tu espacio aislado para ejecutar el demo y revisar tu actividad protegida.',
}

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return children
}
