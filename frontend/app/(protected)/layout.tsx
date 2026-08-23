'use client'

import { useRouter } from 'next/navigation'
import { useEffect } from 'react'
import { RefreshCw } from 'lucide-react'
import { useSession } from '@/components/session-provider'

/**
 * Client-side gate for /demo and /dashboard.
 *
 * The real enforcement lives in the backend: every workspace endpoint answers
 * 401 without a valid session cookie. This only avoids showing an empty shell.
 */
export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const { session } = useSession()
  const router = useRouter()

  useEffect(() => {
    if (session === null) router.replace('/login')
  }, [session, router])

  if (session === undefined) {
    return (
      <div className="route-loading" role="status">
        <RefreshCw className="spinning" /> Comprobando tu sesión…
      </div>
    )
  }

  if (session === null) {
    return (
      <div className="route-loading" role="status">
        <RefreshCw className="spinning" /> Necesitas iniciar sesión. Redirigiendo…
      </div>
    )
  }

  return <>{children}</>
}
