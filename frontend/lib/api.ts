/**
 * Memory Firewall — API client (typed against the FastAPI backend).
 *
 * All types mirror the Pydantic schemas in backend/memory_firewall/schemas.py.
 * Keep in sync with that file when adding new fields.
 *
 * Every request is sent with `credentials: 'include'`. The session lives in an
 * HttpOnly cookie issued by the backend; no Authorization header is ever set
 * and no token is readable from JavaScript.
 */

const BASE_URL = process.env.NEXT_PUBLIC_API_URL
  ?? (process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:8000')

/**
 * Public base URL of the firewall core. Exported so the dashboard can print the
 * exact value an operator must export as `MEMORY_FIREWALL_URL`.
 */
export const API_BASE_URL = BASE_URL

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export type Decision = 'allow' | 'review' | 'block'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type MemoryState = 'active' | 'quarantined' | 'blocked' | 'expired'
export type Authority =
  | 'untrusted'
  | 'observed'
  | 'user_confirmed'
  | 'org_verified'
  | 'system_authority'

export type Tone = 'danger' | 'warning' | 'success' | 'neutral' | 'info'

export interface MemoryThreat {
  type: string
  severity: Severity
  line: number
  description: string
  confidence: number
  indicator: string
}

export interface LedgerEventView {
  seq: number
  event_id: string
  event_type: string
  object_ref: string
  actor_ref: string
  tenant_id: string
  source_event_hash: string
  projection_signature: string
  created_at: string
}

export interface LedgerVerifyResponse {
  valid: boolean
  events_checked: number
  first_invalid_event: number | null
}

export interface ViewerSession {
  authenticated: boolean
  username: string
  workspace_id: string
  expires_in_seconds: number
  /**
   * Plaintext agent workspace key (`mfw_<43 url-safe chars>`). Only
   * registration returns it; login and session lookups return null because the
   * server keeps just its sha256 digest and can never re-read the plaintext.
   *
   * Treat it as a write-once value: render it, let the operator copy it, and
   * drop it. It must never reach `localStorage`, `sessionStorage`, a URL, or a
   * console log.
   */
  workspace_key: string | null
}

/**
 * The subset of a session that is safe to keep in long-lived shared state.
 *
 * `workspace_key` is deliberately excluded at the type level so the plaintext
 * agent credential cannot be parked in the global session context.
 */
export type SessionIdentity = Omit<ViewerSession, 'workspace_key'>

/** A freshly minted agent workspace key. The server shows it exactly once. */
export interface WorkspaceKeyResponse {
  workspace_key: string
  workspace_id: string
}

export interface WorkspaceStats {
  workspace_id: string
  total_events: number
  blocked_actions: number
  allowed_actions: number
  memories_written: number
  last_event_at: string | null
}

export interface RuntimeAdapterStatus {
  name: string
  hook: string
  language: string
  status: string
  install_command: string
}

export interface RuntimeStatusResponse {
  service: string
  core_status: string
  memory_store: string
  execution_boundary: string
  adapters: RuntimeAdapterStatus[]
  live_connections: string[]
}

// --- Demo console -----------------------------------------------------------

export interface DemoEmailRequest {
  /** 1..120 characters. */
  sender: string
  /** 1..200 characters. */
  subject: string
  /** 1..5000 characters. */
  body: string
  /**
   * Simulates an already compromised internal account. When true the message
   * enters with `org_verified` authority, so the origin-authority gate can no
   * longer stop it and only the content judgement remains. Defaults to false.
   */
  from_verified_account?: boolean
}

export interface DemoEmailVerdict {
  message_id: string
  decision: Decision
  risk_score: number
  authority: Authority
  state: MemoryState
  threats: MemoryThreat[]
  reason: string
  sanitized_preview: string
  created_at: string
}

export type DemoStepId = 'write' | 'derive' | 'retrieve' | 'tool'
export type DemoStepStatus = 'ok' | 'quarantined' | 'blocked'
export type DemoEventType = 'WRITE' | 'DERIVE' | 'RETRIEVE' | 'TOOL_DECISION'

export interface DemoAgentStep {
  id: DemoStepId
  label: string
  status: DemoStepStatus
  detail: string
  event_type: DemoEventType
  analysis_id: string
  authority: Authority
}

export interface DemoAgentAskRequest {
  message_id: string
  /** 1..500 characters. */
  question: string
}

/** Verdict of the semantic backstop. `null` means the layer never ran. */
export type SemanticJudgement = 'safe' | 'suspicious' | 'malicious'

/** Whether the agent sentence came from the model or from the fixed table. */
export type AnswerSource = 'model' | 'deterministic'

export interface DemoAgentAnswer {
  question: string
  inferred_action: string
  agent_answer: string
  decision: Decision
  executed: boolean
  function_invocations: number
  steps: DemoAgentStep[]
  /**
   * `null` when the semantic layer was never consulted because the origin
   * authority already settled the outcome deterministically.
   */
  semantic_judgement: SemanticJudgement | null
  semantic_reason: string | null
  semantic_model: string | null
  answer_source: AnswerSource
}

// ---------------------------------------------------------------------------
// Low-level fetch helper
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`API error ${status}: ${code}`)
    this.name = 'ApiError'
  }
}

/** Normalize FastAPI error shapes: `{error}`, `{detail: string}`, `{detail: [...]}`. */
function errorCode(body: unknown): string {
  if (typeof body !== 'object' || body === null) return 'unknown_error'
  const { error, detail } = body as { error?: unknown; detail?: unknown }
  if (typeof error === 'string') return error
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return 'validation_error'
  return 'unknown_error'
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      ...init,
    })
  } catch {
    throw new ApiError(0, 'network_unreachable')
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new ApiError(response.status, errorCode(body))
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function registerViewer(username: string, password: string): Promise<ViewerSession> {
  return apiFetch<ViewerSession>('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
}

export async function loginViewer(username: string, password: string): Promise<ViewerSession> {
  return apiFetch<ViewerSession>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
}

/** Resolves to `null` when there is no session — an anonymous 401 is not an error. */
export async function getViewerSession(): Promise<ViewerSession | null> {
  try {
    return await apiFetch<ViewerSession>('/api/v1/auth/session')
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null
    throw error
  }
}

export async function logoutViewer(): Promise<void> {
  await apiFetch<void>('/api/v1/auth/logout', { method: 'POST' })
}

// ---------------------------------------------------------------------------
// Workspace (session scoped — the backend derives the tenant from the cookie)
// ---------------------------------------------------------------------------

/**
 * Mint a new agent workspace key and revoke the previous one.
 *
 * Requires the browser session cookie: an agent key cannot rotate itself, so a
 * leaked key can never lock the owner out. The plaintext is returned once and
 * is not recoverable afterwards.
 */
export async function rotateWorkspaceKey(): Promise<WorkspaceKeyResponse> {
  return apiFetch<WorkspaceKeyResponse>('/api/v1/workspace/key/rotate', { method: 'POST' })
}

export async function getWorkspaceStats(): Promise<WorkspaceStats> {
  return apiFetch<WorkspaceStats>('/api/v1/workspace/stats')
}

export async function listLedgerEvents(limit = 50): Promise<LedgerEventView[]> {
  return apiFetch<LedgerEventView[]>(`/api/v1/ledger/events?limit=${encodeURIComponent(limit)}`)
}

export async function verifyLedger(): Promise<LedgerVerifyResponse> {
  return apiFetch<LedgerVerifyResponse>('/api/v1/ledger/verify')
}

// ---------------------------------------------------------------------------
// Demo console (session scoped)
// ---------------------------------------------------------------------------

/** Deliver a synthetic email into the caller's own inbox and return the verdict. */
export async function submitDemoEmail(req: DemoEmailRequest): Promise<DemoEmailVerdict> {
  return apiFetch<DemoEmailVerdict>('/api/v1/demo/inbox/email', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

/** Ask the agent about a stored message; returns the full write→tool trace. */
export async function askDemoAgent(req: DemoAgentAskRequest): Promise<DemoAgentAnswer> {
  return apiFetch<DemoAgentAnswer>('/api/v1/demo/agent/ask', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

export async function getRuntimeStatus(): Promise<RuntimeStatusResponse> {
  return apiFetch<RuntimeStatusResponse>('/api/v1/runtime/status')
}

// ---------------------------------------------------------------------------
// Utility helpers for display
// ---------------------------------------------------------------------------

/** Map an Authority value to a human-readable display label. */
export function authorityLabel(a: Authority): string {
  const map: Record<Authority, string> = {
    untrusted: 'NO CONFIABLE',
    observed: 'OBSERVADA',
    user_confirmed: 'CONFIRMADA POR USUARIO',
    org_verified: 'VERIFICADA POR LA ORGANIZACIÓN',
    system_authority: 'AUTORIDAD DEL SISTEMA',
  }
  return map[a] ?? String(a).toUpperCase()
}

/** One-line explanation of what an authority level lets a memory do. */
export function authorityHint(a: Authority): string {
  const map: Record<Authority, string> = {
    untrusted:
      'Origen externo sin verificar: el agente puede leerlo y resumirlo, pero este dato nunca autoriza por sí solo una acción de riesgo.',
    observed:
      'El sistema vio el dato pero nadie lo confirmó: sirve como contexto, no como permiso.',
    user_confirmed:
      'Una persona confirmó el dato: habilita acciones de riesgo bajo, no pagos ni transferencias.',
    org_verified:
      'La organización verificó el dato por un canal propio: es el nivel mínimo para autorizar un pago.',
    system_authority:
      'Autoridad máxima, reservada al propio sistema. No se alcanza desde contenido entrante.',
  }
  return map[a] ?? 'Nivel de autoridad desconocido.'
}

export function stateLabel(state: MemoryState): string {
  const map: Record<MemoryState, string> = {
    active: 'ACTIVA',
    quarantined: 'EN CUARENTENA',
    blocked: 'BLOQUEADA',
    expired: 'VENCIDA',
  }
  return map[state] ?? String(state).toUpperCase()
}

export function stateHint(state: MemoryState): string {
  const map: Record<MemoryState, string> = {
    active: 'La memoria está disponible según sus capacidades.',
    quarantined: 'La memoria se guarda y se puede leer, pero queda aislada de cualquier ejecución.',
    blocked: 'La memoria queda inutilizable para cualquier acción.',
    expired: 'La memoria caducó y ya no puede sustentar decisiones.',
  }
  return map[state] ?? ''
}

export function decisionLabel(d: Decision): string {
  const map: Record<Decision, string> = {
    allow: 'PERMITIDO',
    review: 'EN REVISIÓN',
    block: 'BLOQUEADO',
  }
  return map[d] ?? String(d).toUpperCase()
}

export function severityLabel(s: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'CRÍTICA',
    high: 'ALTA',
    medium: 'MEDIA',
    low: 'BAJA',
  }
  return map[s] ?? String(s).toUpperCase()
}

/** Map a MemoryState to a display tone for the status pill. */
export function stateTone(state: MemoryState): Tone {
  if (state === 'blocked') return 'danger'
  if (state === 'quarantined') return 'warning'
  if (state === 'active') return 'success'
  return 'neutral'
}

/** Map a Decision to a display tone. */
export function decisionTone(d: Decision): Tone {
  if (d === 'block') return 'danger'
  if (d === 'review') return 'warning'
  if (d === 'allow') return 'success'
  return 'neutral'
}

/** red = critical, orange = high, yellow = medium, blue = low. */
export function severityTone(s: Severity): 'critical' | 'high' | 'medium' | 'low' {
  return s === 'critical' || s === 'high' || s === 'medium' ? s : 'low'
}

/** Trace-step status to a display tone: ok = green, quarantined = amber, blocked = red. */
export function stepTone(status: DemoStepStatus): Tone {
  if (status === 'blocked') return 'danger'
  if (status === 'quarantined') return 'warning'
  return 'success'
}

/** Semantic backstop verdict to a display label. */
export function semanticJudgementLabel(j: SemanticJudgement): string {
  const map: Record<SemanticJudgement, string> = {
    safe: 'CONTENIDO SEGURO',
    suspicious: 'CONTENIDO SOSPECHOSO',
    malicious: 'CONTENIDO MALICIOSO',
  }
  return map[j] ?? String(j).toUpperCase()
}

/** safe = green, suspicious = amber, malicious = red. */
export function semanticJudgementTone(j: SemanticJudgement): Tone {
  if (j === 'malicious') return 'danger'
  if (j === 'suspicious') return 'warning'
  if (j === 'safe') return 'success'
  return 'neutral'
}

/** One-line explanation of what each semantic verdict means for the action. */
export function semanticJudgementHint(j: SemanticJudgement): string {
  const map: Record<SemanticJudgement, string> = {
    safe: 'El modelo no encontró intención hostil en el contenido: la acción sigue su curso normal.',
    suspicious:
      'El modelo no pudo descartar una intención hostil, así que la acción se frena en vez de asumir buena fe.',
    malicious:
      'El modelo identificó una intención hostil en el contenido y la acción se frena aunque la autoridad alcanzara.',
  }
  return map[j] ?? 'Veredicto semántico desconocido.'
}

export function stepStatusLabel(status: DemoStepStatus): string {
  const map: Record<DemoStepStatus, string> = {
    ok: 'CORRECTO',
    quarantined: 'EN CUARENTENA',
    blocked: 'BLOQUEADO',
  }
  return map[status] ?? String(status).toUpperCase()
}

/** Deterministic policy-engine sentences, mirrored from memory_firewall/service.py. */
const reasonSentences: Record<string, string> = {
  'No blocking memory threat was detected; content remains bound to its source authority.':
    'No se detectó ninguna amenaza que obligue a bloquear; el contenido sigue atado a la autoridad de su origen.',
  'Persistent instructions, overrides, manipulation, or exfiltration require blocking.':
    'Las instrucciones persistentes, las anulaciones, la manipulación o la exfiltración obligan a bloquear.',
  'The content may be useful, but it requires human review before becoming trusted memory.':
    'El contenido puede ser útil, pero requiere revisión humana antes de convertirse en memoria confiable.',
  'Derived memory inherits quarantine from an inactive, unapproved, or expired parent.':
    'La memoria derivada hereda la cuarentena de un padre inactivo, sin aprobar o vencido.',
  'External content cannot create organization-wide policy automatically.':
    'El contenido externo no puede crear política para toda la organización de forma automática.',
  'All memories satisfy authority, capability, scope, TTL, and state checks.':
    'Todas las memorias cumplen las verificaciones de autoridad, capacidad, alcance, vigencia y estado.',
  'At least one memory is not active.': 'Al menos una memoria no está activa.',
  'At least one memory requires approval before this action.':
    'Al menos una memoria requiere aprobación antes de esta acción.',
  'Requested scope is not allowed by every memory.':
    'El alcance solicitado no está permitido por todas las memorias.',
}

function translateSentence(sentence: string): string {
  const exact = reasonSentences[sentence]
  if (exact !== undefined) return exact

  const capability = sentence.match(/^Required capability (.+) is missing\.$/)
  if (capability) return `Falta la capacidad requerida ${capability[1]}.`

  const authority = sentence.match(/^Required authority is ([a-z_]+); received ([a-z_]+)\.$/)
  if (authority) {
    return `La autoridad requerida es ${authorityLabel(authority[1] as Authority)}; se recibió ${authorityLabel(authority[2] as Authority)}.`
  }

  const approval = sentence.match(/^Memory approval expired: (.+)$/)
  if (approval) return `La aprobación de la memoria venció: ${approval[1]}`

  return sentence
}

/**
 * Translate a policy reason into Spanish. The engine may concatenate several
 * sentences, so each one is matched independently and unknown text is passed
 * through verbatim rather than dropped.
 */
export function reasonLabel(reason: string): string {
  const trimmed = reason.trim()
  if (trimmed === '') return ''
  const chunks = trimmed.split('. ')
  return chunks
    .map((chunk, index) => translateSentence(index < chunks.length - 1 ? `${chunk}.` : chunk))
    .join(' ')
}

export function eventTypeLabel(value: string): string {
  const labels: Record<string, string> = {
    WRITE: 'MEMORIA ESCRITA',
    DERIVE: 'MEMORIA DERIVADA',
    RETRIEVE: 'MEMORIA RECUPERADA',
    TOOL_DECISION: 'DECISIÓN DE HERRAMIENTA',
    TOOL_BLOCKED_LOCAL: 'HERRAMIENTA BLOQUEADA LOCALMENTE',
    ACTION_DECISION: 'DECISIÓN DE ACCIÓN',
    AUTHORITY_ELEVATION: 'ELEVACIÓN DE AUTORIDAD',
  }
  return labels[value] ?? value.replaceAll('_', ' ')
}

/** Relative time string from an ISO datetime. */
export function relativeTime(iso: string): string {
  const delta = (Date.now() - new Date(iso).getTime()) / 1000
  if (delta < 60) return 'ahora mismo'
  if (delta < 3600) return `hace ${Math.floor(delta / 60)} min`
  if (delta < 86400) return `hace ${Math.floor(delta / 3600)} h`
  const days = Math.floor(delta / 86400)
  return `hace ${days} ${days === 1 ? 'día' : 'días'}`
}

/** Truncate long identifiers/hashes for display without hiding the full value. */
export function shortId(value: string | undefined, length = 24): string {
  if (!value) return 'pendiente'
  return value.length > length ? `${value.slice(0, length)}...` : value
}

/** Translate the auth error codes returned by the backend into Spanish copy. */
export function authErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'No se pudo completar el acceso. Inténtalo nuevamente.'
  }
  const messages: Record<string, string> = {
    username_unavailable: 'Ese nombre de usuario ya existe. Elige otro o inicia sesión.',
    invalid_username:
      'Usa entre 3 y 64 caracteres: letras minúsculas, números, punto, guion o guion bajo. Debe empezar con letra o número.',
    invalid_password: 'La contraseña debe tener al menos 12 caracteres.',
    invalid_credentials: 'El usuario o la contraseña no son correctos.',
    rate_limit_exceeded: 'Demasiados intentos. Espera un minuto antes de volver a probar.',
    validation_error: 'Revisa los datos: el usuario o la contraseña no cumplen el formato exigido.',
    network_unreachable:
      'No se pudo contactar el núcleo local del firewall. Confirma que el backend esté activo.',
  }
  if (error.status === 429) return messages.rate_limit_exceeded
  return messages[error.code] ?? 'No se pudo completar el acceso. Inténtalo nuevamente.'
}
