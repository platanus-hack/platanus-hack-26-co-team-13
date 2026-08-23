'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { Copy, KeyRound, TriangleAlert } from 'lucide-react'
import { useToast } from '@/components/toast-provider'
import { copyToClipboard } from '@/lib/utils'

interface WorkspaceKeyRevealProps {
  /** Plaintext `mfw_...` credential. Held in React state only, never persisted. */
  workspaceKey: string
  workspaceId: string
  heading: string
  /** Acknowledgement control ("Ya la guardé…") rendered under the warning. */
  children?: React.ReactNode
}

/**
 * One-time delivery panel for an agent workspace key.
 *
 * The key is rendered from a prop and nothing else: it is not written to
 * storage, not put in the URL, and not logged. When the parent drops the prop
 * the value is gone for good, exactly like on the server.
 */
export function WorkspaceKeyReveal({
  workspaceKey,
  workspaceId,
  heading,
  children,
}: WorkspaceKeyRevealProps) {
  const { showToast } = useToast()
  const headingId = useId()
  const panel = useRef<HTMLDivElement>(null)
  const [copyResult, setCopyResult] = useState('')

  // Move focus to the panel so the credential is the next thing announced.
  useEffect(() => {
    panel.current?.focus()
  }, [])

  async function handleCopy() {
    const copied = await copyToClipboard(workspaceKey)
    const message = copied
      ? 'Clave copiada al portapapeles.'
      : 'No se pudo copiar automáticamente. Selecciona la clave y cópiala a mano.'
    setCopyResult(message)
    showToast(message)
  }

  return (
    <div
      className="key-reveal"
      ref={panel}
      tabIndex={-1}
      role="group"
      aria-labelledby={headingId}
      aria-live="polite"
    >
      <span className="key-reveal-seal">
        <KeyRound /> CLAVE DE ESPACIO · SE MUESTRA UNA SOLA VEZ
      </span>
      <h2 id={headingId}>{heading}</h2>
      <p className="key-reveal-purpose">
        Es la credencial con la que tu agente escribe en tu espacio <code>{workspaceId}</code>.
      </p>

      <div className="key-reveal-value">
        <code>{workspaceKey}</code>
        <button type="button" className="secondary-action" onClick={() => void handleCopy()}>
          <Copy /> Copiar clave
        </button>
      </div>

      <p className="key-reveal-warning">
        <TriangleAlert />
        <span>
          Guárdala ahora. No podremos volver a mostrártela; si la pierdes tendrás que rotarla.
        </span>
      </p>

      <p className="visually-hidden" role="status" aria-live="polite">
        {copyResult}
      </p>

      {children !== undefined && <div className="key-reveal-actions">{children}</div>}
    </div>
  )
}
