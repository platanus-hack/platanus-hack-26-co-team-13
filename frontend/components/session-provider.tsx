'use client'

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import {
  type SessionIdentity,
  type ViewerSession,
  getViewerSession,
  logoutViewer,
} from '@/lib/api'

/** `undefined` means "still checking"; `null` means "no session". */
export type SessionState = SessionIdentity | null | undefined

interface SessionContextValue {
  session: SessionState
  /**
   * Adopt a session returned by login/register without a second round trip.
   *
   * The plaintext `workspace_key` is dropped here on purpose: the credential
   * belongs to the one screen that shows it, not to shared app state.
   */
  adopt: (session: ViewerSession) => void
  reload: () => Promise<void>
  signOut: () => Promise<void>
}

const SessionContext = createContext<SessionContextValue | null>(null)

/** Keep the identity fields only; never let the agent key into the context. */
function toIdentity(session: ViewerSession): SessionIdentity {
  return {
    authenticated: session.authenticated,
    username: session.username,
    workspace_id: session.workspace_id,
    expires_in_seconds: session.expires_in_seconds,
  }
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionState>(undefined)

  const reload = useCallback(async () => {
    const next = await getViewerSession().catch(() => null)
    setSession(next === null ? null : toIdentity(next))
  }, [])

  useEffect(() => {
    void reload()
  }, [reload])

  const adopt = useCallback((next: ViewerSession) => setSession(toIdentity(next)), [])

  const signOut = useCallback(async () => {
    await logoutViewer().catch(() => undefined)
    setSession(null)
  }, [])

  const value = useMemo<SessionContextValue>(
    () => ({ session, adopt, reload, signOut }),
    [session, adopt, reload, signOut],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext)
  if (context === null) {
    throw new Error('useSession must be used inside <SessionProvider>')
  }
  return context
}
