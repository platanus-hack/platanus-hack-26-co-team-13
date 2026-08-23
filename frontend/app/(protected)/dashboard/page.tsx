'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useCallback, useEffect, useState } from 'react'
import {
  BadgeCheck,
  Ban,
  Check,
  CircleAlert,
  Clock,
  Copy,
  Database,
  Fingerprint,
  Inbox,
  KeyRound,
  LockKeyhole,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react'
import { useSession } from '@/components/session-provider'
import { useToast } from '@/components/toast-provider'
import { WorkspaceKeyReveal } from '@/components/workspace-key-reveal'
import {
  type LedgerEventView,
  type LedgerVerifyResponse,
  type WorkspaceStats,
  API_BASE_URL,
  ApiError,
  eventTypeLabel,
  getWorkspaceStats,
  listLedgerEvents,
  relativeTime,
  rotateWorkspaceKey,
  shortId,
  verifyLedger,
} from '@/lib/api'
import { copyToClipboard } from '@/lib/utils'

const LEDGER_LIMIT = 50

/** Stand-in shown whenever we do not hold a freshly minted plaintext key. */
const MASKED_KEY = 'mfw_••••'

function configSnippet(workspaceKey: string): string {
  return [
    `export MEMORY_FIREWALL_WORKSPACE_KEY=${workspaceKey}`,
    `export MEMORY_FIREWALL_URL=${API_BASE_URL}`,
  ].join('\n')
}

/** Spanish copy for the failure modes of `POST /workspace/key/rotate`. */
function rotateErrorMessage(caught: unknown): string {
  if (!(caught instanceof ApiError)) return 'No se pudo rotar la clave. Inténtalo de nuevo.'
  if (caught.status === 429) {
    return 'Demasiados intentos seguidos. Espera un minuto antes de volver a rotar.'
  }
  if (caught.code === 'network_unreachable') {
    return 'No se pudo contactar el núcleo local del firewall. Confirma que el backend esté activo.'
  }
  return 'No se pudo rotar la clave. Tu clave actual sigue vigente.'
}

export default function DashboardPage() {
  const router = useRouter()
  const { session, reload } = useSession()
  const { showToast } = useToast()

  const [stats, setStats] = useState<WorkspaceStats | null>(null)
  const [events, setEvents] = useState<LedgerEventView[] | null>(null)
  const [verification, setVerification] = useState<LedgerVerifyResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Agent credential. `rotatedKey` holds a plaintext key in memory only, and
  // only between a successful rotation and the operator acknowledging it.
  const [rotatedKey, setRotatedKey] = useState<string | null>(null)
  const [confirmingRotate, setConfirmingRotate] = useState(false)
  const [rotating, setRotating] = useState(false)
  const [rotateError, setRotateError] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [nextStats, nextEvents, nextVerification] = await Promise.all([
        getWorkspaceStats(),
        listLedgerEvents(LEDGER_LIMIT),
        verifyLedger(),
      ])
      setStats(nextStats)
      setEvents(nextEvents)
      setVerification(nextVerification)
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        void reload()
        router.replace('/login')
        return
      }
      if (caught instanceof ApiError && caught.code === 'network_unreachable') {
        setError('No se pudo contactar el núcleo local del firewall. Confirma que el backend esté activo.')
      } else if (caught instanceof ApiError && caught.status === 429) {
        setError('Demasiadas solicitudes seguidas. Espera un momento y vuelve a actualizar.')
      } else {
        setError('No se pudo cargar tu actividad. Inténtalo de nuevo.')
      }
    } finally {
      setLoading(false)
    }
  }, [reload, router])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const handleRotate = useCallback(async () => {
    setRotating(true)
    setRotateError('')
    try {
      const minted = await rotateWorkspaceKey()
      setRotatedKey(minted.workspace_key)
      setConfirmingRotate(false)
      showToast('Clave rotada. La anterior quedó revocada.')
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        void reload()
        router.replace('/login')
        return
      }
      setRotateError(rotateErrorMessage(caught))
    } finally {
      setRotating(false)
    }
  }, [reload, router, showToast])

  const workspaceId = stats?.workspace_id ?? session?.workspace_id ?? ''
  const isEmpty = events !== null && events.length === 0
  const snippet = configSnippet(rotatedKey ?? MASKED_KEY)

  async function handleCopySnippet() {
    const copied = await copyToClipboard(snippet)
    showToast(
      copied
        ? 'Configuración copiada al portapapeles.'
        : 'No se pudo copiar automáticamente. Selecciona el bloque y cópialo a mano.',
    )
  }

  return (
    <section className="workspace-page">
      <div className="workspace-shell">
        <div className="workspace-heading">
          <div>
            <h1>Mi actividad protegida</h1>
            <p>
              Todo lo que el firewall escribió, derivó, recuperó o bloqueó dentro de tu espacio.
              Ninguna otra cuenta puede leer estos eventos ni saber que existen.
            </p>
          </div>
          <div className="heading-side">
            <span className="workspace-tag">
              <LockKeyhole /> ESPACIO <code>{workspaceId || '—'}</code>
            </span>
            {session && (
              <span className="workspace-tag">
                <Fingerprint /> {session.username}
              </span>
            )}
          </div>
        </div>

        <div aria-live="polite">
          {error !== '' && (
            <p className="inline-alert" role="alert">
              <CircleAlert /> <span>{error}</span>
            </p>
          )}
        </div>

        <div className="stat-grid" aria-label="Resumen de tu espacio">
          <article className="headline">
            <small>
              <Ban /> Acciones bloqueadas
            </small>
            <strong>{stats?.blocked_actions ?? '—'}</strong>
            <p>Herramientas de riesgo que la puerta de ejecución rechazó antes de invocarlas.</p>
          </article>
          <article>
            <small>
              <ShieldCheck /> Acciones permitidas
            </small>
            <strong>{stats?.allowed_actions ?? '—'}</strong>
            <p>Decisiones que sí cumplieron autoridad, capacidad, alcance y vigencia.</p>
          </article>
          <article>
            <small>
              <Database /> Memorias registradas
            </small>
            <strong>{stats?.memories_written ?? '—'}</strong>
            <p>Sobres firmados escritos en SQLite con su origen y su linaje.</p>
          </article>
          <article>
            <small>
              <Inbox /> Eventos totales
            </small>
            <strong>{stats?.total_events ?? '—'}</strong>
            <p>Cada hop de la cadena de custodia queda encadenado por hash.</p>
          </article>
        </div>

        <div className="stat-strip">
          <span>
            <Clock /> Última actividad:{' '}
            <b>{stats?.last_event_at ? relativeTime(stats.last_event_at) : 'sin registros todavía'}</b>
          </span>
          <span className={verification?.valid ? 'verified' : ''}>
            <BadgeCheck />{' '}
            {verification === null
              ? 'cadena sin verificar'
              : verification.valid
                ? `cadena íntegra · ${verification.events_checked} eventos verificados`
                : `cadena inválida en el evento ${verification.first_invalid_event ?? '?'}`}
          </span>
          <button className="secondary-action" onClick={() => void refresh()} disabled={loading}>
            <RefreshCw className={loading ? 'spinning' : ''} /> Actualizar
          </button>
        </div>

        <section className="agent-credential" aria-labelledby="agent-credential-title">
          <div className="agent-credential-head">
            <div>
              <h2 id="agent-credential-title">
                <KeyRound /> Credencial de tu agente
              </h2>
              <p>
                Los agentes se autentican con la cabecera <code>X-Workspace-Key</code>; el
                dashboard sólo muestra actividad firmada con esa credencial.
              </p>
            </div>
            <span className="workspace-tag">
              <LockKeyhole /> ESPACIO <code>{workspaceId || '—'}</code>
            </span>
          </div>

          <div className="agent-credential-body">
            <div className="config-snippet">
              <div className="config-snippet-head">
                <span>CONFIGURACIÓN DEL AGENTE</span>
                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => void handleCopySnippet()}
                >
                  <Copy /> Copiar configuración
                </button>
              </div>
              <pre>{snippet}</pre>
              {rotatedKey === null && (
                <small>
                  La clave va enmascarada porque el servidor guarda sólo su resumen sha256.
                  Reemplaza <code>{MASKED_KEY}</code> por la clave que guardaste al registrarte, o
                  rota para obtener una nueva.
                </small>
              )}
            </div>

            <div className="rotate-controls">
              {!confirmingRotate && (
                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => {
                    setRotateError('')
                    setConfirmingRotate(true)
                  }}
                  disabled={rotating}
                >
                  <RotateCcw /> Rotar clave
                </button>
              )}

              {confirmingRotate && (
                <div className="rotate-confirm" role="group" aria-labelledby="rotate-confirm-title">
                  <p id="rotate-confirm-title">
                    <TriangleAlert />
                    <span>
                      ¿Seguro? Esto revoca la clave actual y tus agentes dejarán de funcionar hasta
                      que la actualices.
                    </span>
                  </p>
                  <div className="rotate-confirm-actions">
                    <button
                      type="button"
                      className="primary-action compact"
                      onClick={() => void handleRotate()}
                      disabled={rotating}
                    >
                      {rotating ? <RefreshCw className="spinning" /> : <Check />}
                      {rotating ? 'Rotando…' : 'Sí, rotar ahora'}
                    </button>
                    <button
                      type="button"
                      className="secondary-action"
                      onClick={() => setConfirmingRotate(false)}
                      disabled={rotating}
                    >
                      <X /> Cancelar
                    </button>
                  </div>
                </div>
              )}

              <div aria-live="polite">
                {rotateError !== '' && (
                  <p className="inline-alert" role="alert">
                    <CircleAlert /> <span>{rotateError}</span>
                  </p>
                )}
              </div>
            </div>

            {rotatedKey !== null && (
              <WorkspaceKeyReveal
                workspaceKey={rotatedKey}
                workspaceId={workspaceId}
                heading="Tu nueva clave de espacio"
              >
                <button
                  type="button"
                  className="primary-action"
                  onClick={() => setRotatedKey(null)}
                >
                  <Check /> Ya la guardé, ocultar
                </button>
              </WorkspaceKeyReveal>
            )}
          </div>
        </section>

        <div className="persistent-ledger-console">
          <div className="ledger-toolbar">
            <div>
              <h3>Registro persistente de custodia</h3>
              <p>
                Persistido en SQLite, encadenado mediante resúmenes criptográficos y firmado con
                Ed25519. Se muestran los últimos {LEDGER_LIMIT} eventos.
              </p>
            </div>
            <div className="ledger-actions">
              <span className={verification?.valid ? 'verified' : ''}>
                <BadgeCheck />{' '}
                {verification?.valid ? `${verification.events_checked} eventos verificados` : 'sin verificar'}
              </span>
            </div>
          </div>

          <div className="persistent-ledger-table">
            <div className="persistent-ledger-head">
              <span>SEC. / EVENTO</span>
              <span>OBJETO</span>
              <span>ACTOR</span>
              <span>PRUEBA</span>
            </div>

            {events === null && loading && (
              <p className="table-empty">
                <RefreshCw className="spinning" /> Cargando tu registro firmado…
              </p>
            )}

            {events === null && !loading && (
              <p className="table-empty">
                No se pudo cargar el registro firmado. Usa «Actualizar» para reintentar.
              </p>
            )}

            {isEmpty && (
              <div className="workspace-empty">
                <Inbox />
                <h4>Tu espacio todavía no tiene eventos.</h4>
                <p>
                  Entrega un correo al buzón del agente y pregúntale algo: cada paso quedará aquí
                  como evidencia firmada.
                </p>
                <Link className="primary-action" href="/demo">
                  <Play /> Ir al demo del correo
                </Link>
              </div>
            )}

            {events?.map((event) => (
              <div className="persistent-ledger-row" key={event.event_id}>
                <span>
                  <b>
                    {event.seq.toString().padStart(3, '0')} / {eventTypeLabel(event.event_type)}
                  </b>
                  <small>{relativeTime(event.created_at)}</small>
                </span>
                <code title={event.object_ref}>{shortId(event.object_ref, 20)}</code>
                <span>{event.actor_ref}</span>
                <span>
                  <BadgeCheck /> proyectada / {shortId(event.source_event_hash, 12)}
                </span>
              </div>
            ))}
          </div>
        </div>

        {!isEmpty && events !== null && (
          <div className="panel-actions">
            <Link className="primary-action" href="/demo">
              <Play /> Probar otro correo
            </Link>
          </div>
        )}
      </div>
    </section>
  )
}
