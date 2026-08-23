'use client'

import { useRouter } from 'next/navigation'
import { type FormEvent, useEffect, useState } from 'react'
import { ArrowRight, LockKeyhole, LogIn, RefreshCw, ShieldCheck } from 'lucide-react'
import { useSession } from '@/components/session-provider'
import { useToast } from '@/components/toast-provider'
import { WorkspaceKeyReveal } from '@/components/workspace-key-reveal'
import { authErrorMessage, loginViewer, registerViewer } from '@/lib/api'

type AuthMode = 'login' | 'register'

/** The one-time credential handed over right after registration. */
interface IssuedKey {
  key: string
  workspaceId: string
}

export default function LoginPage() {
  const router = useRouter()
  const { session, adopt } = useSession()
  const { showToast } = useToast()

  const [mode, setMode] = useState<AuthMode>('register')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // In-memory only: never localStorage, sessionStorage, a URL, or a log.
  const [issuedKey, setIssuedKey] = useState<IssuedKey | null>(null)

  // Already authenticated: this screen has nothing to offer. The handover panel
  // takes precedence, otherwise adopting the new session would navigate away
  // before the operator had a chance to copy the key.
  useEffect(() => {
    if (issuedKey !== null) return
    if (session) router.replace('/dashboard')
  }, [session, router, issuedKey])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const next =
        mode === 'register'
          ? await registerViewer(username, password)
          : await loginViewer(username, password)
      adopt(next)
      setPassword('')
      if (next.workspace_key !== null && next.workspace_key !== undefined) {
        setIssuedKey({ key: next.workspace_key, workspaceId: next.workspace_id })
        showToast(`Cuenta creada para ${next.username}. Guarda tu clave de espacio.`)
        return
      }
      showToast(
        mode === 'register'
          ? `Cuenta creada para ${next.username}. Espacio ${next.workspace_id}.`
          : `Sesión iniciada para ${next.username}.`,
      )
      router.replace('/demo')
    } catch (caught) {
      setError(authErrorMessage(caught))
    } finally {
      setBusy(false)
    }
  }

  function switchMode(next: AuthMode) {
    setMode(next)
    setError('')
  }

  if (issuedKey !== null) {
    return (
      <section className="auth-page">
        <div className="key-handoff">
          <WorkspaceKeyReveal
            workspaceKey={issuedKey.key}
            workspaceId={issuedKey.workspaceId}
            heading="Guarda la clave de tu espacio"
          >
            <button
              type="button"
              className="primary-action"
              onClick={() => router.replace('/demo')}
            >
              <ArrowRight /> Ya la guardé, continuar
            </button>
          </WorkspaceKeyReveal>
        </div>
      </section>
    )
  }

  if (session === undefined || session) {
    return (
      <div className="route-loading" role="status">
        <RefreshCw className="spinning" />
        {session ? 'Ya tienes sesión activa. Abriendo tu actividad…' : 'Comprobando tu sesión…'}
      </div>
    )
  }

  return (
    <section className="auth-page">
      <div className="viewer-gate">
        <form className="viewer-login" onSubmit={(event) => void handleSubmit(event)}>
          <div className="auth-mode-tabs" aria-label="Tipo de acceso">
            <button
              type="button"
              className={mode === 'register' ? 'active' : ''}
              onClick={() => switchMode('register')}
            >
              Crear cuenta
            </button>
            <button
              type="button"
              className={mode === 'login' ? 'active' : ''}
              onClick={() => switchMode('login')}
            >
              Iniciar sesión
            </button>
          </div>
          <div className="access-seal">
            <LockKeyhole />
            <span>ESPACIO PRIVADO</span>
          </div>
          <h1>
            {mode === 'register'
              ? 'Crea tu cuenta para probar el firewall.'
              : 'Vuelve a tu actividad protegida.'}
          </h1>
          <p>
            {mode === 'register'
              ? 'Cada cuenta recibe su propio espacio aislado. Tu contraseña se cifra antes de guardarse y la sesión vive en una cookie HttpOnly.'
              : 'Ingresa con el usuario y la contraseña que elegiste al registrarte.'}
          </p>

          <label htmlFor="auth-username">Usuario</label>
          <input
            id="auth-username"
            name="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            minLength={3}
            maxLength={64}
            pattern="[a-z0-9][a-z0-9._\-]{2,63}"
            aria-describedby="auth-username-hint"
            required
          />
          <small id="auth-username-hint" className="field-hint">
            3 a 64 caracteres: minúsculas, números, punto, guion o guion bajo.
          </small>

          <label htmlFor="auth-password">Contraseña</label>
          <input
            id="auth-password"
            name="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
            minLength={mode === 'register' ? 12 : 1}
            maxLength={256}
            aria-describedby="auth-password-hint"
            required
          />
          <small id="auth-password-hint" className="field-hint">
            {mode === 'register' ? 'Mínimo 12 caracteres.' : 'La que definiste al registrarte.'}
          </small>

          <div aria-live="polite">
            {error !== '' && (
              <p className="login-error" role="alert">
                {error}
              </p>
            )}
          </div>

          <button className="primary-action" disabled={busy}>
            {busy ? <RefreshCw className="spinning" /> : mode === 'register' ? <ShieldCheck /> : <LogIn />}
            {busy ? 'Procesando' : mode === 'register' ? 'Crear cuenta y continuar' : 'Iniciar sesión'}
          </button>
          <small>
            {mode === 'register'
              ? 'No guardamos tu contraseña en texto plano. Solo el demo sintético toca tu espacio.'
              : 'La sesión dura 8 horas y puedes cerrarla en cualquier momento.'}
          </small>
        </form>

        <aside className="access-evidence" aria-label="Controles de acceso a la actividad protegida">
          <div className="document-meta">
            <span>PROTECCIÓN DE TU CUENTA</span>
            <strong>ACTIVA</strong>
          </div>
          <dl>
            <div>
              <dt>Contraseña</dt>
              <dd>hash scrypt + sal única</dd>
            </div>
            <div>
              <dt>Sesión</dt>
              <dd>revocable y HttpOnly</dd>
            </div>
            <div>
              <dt>Espacio</dt>
              <dd>aislado por cuenta</dd>
            </div>
            <div>
              <dt>Acceso anónimo</dt>
              <dd>bloqueado</dd>
            </div>
          </dl>
          <span className="custody-stamp">SOLO TÚ PUEDES ENTRAR</span>
        </aside>
      </div>
    </section>
  )
}
