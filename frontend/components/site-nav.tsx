'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { LogIn, LogOut, Menu, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { BrandMark } from '@/components/brand-mark'
import { useSession } from '@/components/session-provider'
import { useToast } from '@/components/toast-provider'

export function SiteNav() {
  const pathname = usePathname()
  const router = useRouter()
  const { session, signOut } = useSession()
  const { showToast } = useToast()
  const [menuOpen, setMenuOpen] = useState(false)

  const onLanding = pathname === '/'

  // Close the mobile drawer whenever the route changes.
  useEffect(() => setMenuOpen(false), [pathname])

  async function handleSignOut() {
    setMenuOpen(false)
    await signOut()
    showToast('Sesión cerrada. Tu actividad queda guardada en tu espacio.')
    router.push('/')
  }

  return (
    <header className="site-header">
      <Link className="site-brand" href="/" aria-label="Inicio de Provenance">
        <BrandMark />
      </Link>
      <button
        className="menu-button"
        onClick={() => setMenuOpen((open) => !open)}
        aria-label="Abrir o cerrar navegación"
        aria-expanded={menuOpen}
      >
        {menuOpen ? <X /> : <Menu />}
      </button>
      <nav className={menuOpen ? 'open' : ''} aria-label="Navegación principal">
        {onLanding && <a href="#mechanism">Cómo funciona</a>}
        {onLanding && <a href="#adapters">Adaptadores</a>}
        {session && (
          <Link className={pathname === '/demo' ? 'active' : ''} href="/demo" aria-current={pathname === '/demo' ? 'page' : undefined}>
            Demo
          </Link>
        )}
        {session && (
          <Link
            className={pathname === '/dashboard' ? 'active' : ''}
            href="/dashboard"
            aria-current={pathname === '/dashboard' ? 'page' : undefined}
          >
            Mi actividad
          </Link>
        )}
        {session ? (
          <button onClick={() => void handleSignOut()}>
            <LogOut /> Salir / {session.email}
          </button>
        ) : (
          <Link className="nav-cta" href="/login">
            <LogIn /> Iniciar sesión
          </Link>
        )}
      </nav>
    </header>
  )
}
