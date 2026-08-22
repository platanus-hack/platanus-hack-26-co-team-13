/**
 * Memory Firewall — API client (typed against the FastAPI backend).
 *
 * All types mirror the Pydantic schemas in backend/memory_firewall/schemas.py.
 * Keep in sync with that file when adding new fields.
 */

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

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

export interface MemoryCapabilities {
  allowed_actions: string[]
  allowed_scopes: string[]
  requires_approval: boolean
  usable_for_action: boolean
}

export interface MemoryThreat {
  type: string
  severity: Severity
  line: number
  description: string
  confidence: number
  indicator: string
}

export interface MemoryProvenance {
  origin: string
  authority: Authority
  verified: boolean
  parent_analysis_ids: string[]
  transformation: string | null
}

export interface MemoryAnalysisResponse {
  analysis_id: string
  decision: Decision
  risk_score: number
  threats: MemoryThreat[]
  sanitized_content: string
  reason: string
  source: string
  authority: Authority
  capabilities: MemoryCapabilities
  provenance: MemoryProvenance
  state: MemoryState
  content_hash: string
  key_id: string
  signature: string
  requested_action: string | null
  created_at: string // ISO datetime string
}

export interface ActionEvaluationResponse {
  decision: Decision
  action: string
  scope: string
  required_authority: Authority
  provided_authority: Authority | null
  required_capability: string
  provided_capabilities: string[]
  usable_memory_ids: string[]
  blocked_memory_ids: string[]
  scope_valid: boolean
  reasons: string[]
}

export interface EvaluateWriteResponse {
  decision: Decision
  risk_score: number
  authority: string
  state: MemoryState
  reason: string
  would_be_quarantined: boolean
  would_be_blocked: boolean
  threats_found: number
}

export interface CurrentKeyResponse {
  key_id: string
  algorithm: string
  public_key_base64: string
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

interface MemoryAnalyzeRequest {
  content: string
  source?: string
  scope?: string
  requested_action?: string
  metadata?: Record<string, unknown>
}

interface MemoryDeriveRequest {
  content: string
  parent_analysis_ids: string[]
  transformation?: string
  scope?: string
}

interface ActionEvaluationRequest {
  analysis_ids: string[]
  action: string
  scope?: string
}

interface EvaluateWriteRequest {
  content: string
  source?: string
  scope?: string
  requested_action?: string
}

// ---------------------------------------------------------------------------
// Low-level fetch helper
// ---------------------------------------------------------------------------

async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new ApiError(response.status, (body as { error?: string }).error ?? 'unknown_error')
  }
  return response.json() as Promise<T>
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`API error ${status}: ${code}`)
  }
}

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

/** Analyze a piece of memory/context. Returns a signed envelope. */
export async function analyzeMemory(
  req: MemoryAnalyzeRequest,
): Promise<MemoryAnalysisResponse> {
  return apiFetch<MemoryAnalysisResponse>('/api/v1/memory/analyze', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

/** Derive a new memory from one or more parent analyses. */
export async function deriveMemory(
  req: MemoryDeriveRequest,
): Promise<MemoryAnalysisResponse> {
  return apiFetch<MemoryAnalysisResponse>('/api/v1/memory/derive', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

/** Get a single analysis by id. */
export async function getAnalysis(analysisId: string): Promise<MemoryAnalysisResponse> {
  return apiFetch<MemoryAnalysisResponse>(`/api/v1/analyses/${analysisId}`)
}

/** List stored analyses with optional filters. */
export async function searchMemories(opts?: {
  scope?: string
  source?: string
  limit?: number
}): Promise<MemoryAnalysisResponse[]> {
  const params = new URLSearchParams()
  if (opts?.scope) params.set('scope', opts.scope)
  if (opts?.source) params.set('source', opts.source)
  if (opts?.limit !== undefined) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return apiFetch<MemoryAnalysisResponse[]>(`/api/v1/memory/search${qs ? `?${qs}` : ''}`)
}

/** Evaluate whether memory evidence can authorize a high-risk action. */
export async function evaluateAction(
  req: ActionEvaluationRequest,
): Promise<ActionEvaluationResponse> {
  return apiFetch<ActionEvaluationResponse>('/api/v1/actions/evaluate', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

/** Dry-run: preview the firewall verdict without persisting. */
export async function evaluateWrite(
  req: EvaluateWriteRequest,
): Promise<EvaluateWriteResponse> {
  return apiFetch<EvaluateWriteResponse>('/api/v1/memory/evaluate-write', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

/** Fetch the current public signing key. */
export async function getCurrentKey(): Promise<CurrentKeyResponse> {
  return apiFetch<CurrentKeyResponse>('/api/v1/keys/current')
}

/** Health check — resolves to true if the backend is reachable. */
export async function checkHealth(): Promise<boolean> {
  try {
    const res = await apiFetch<{ status: string }>('/api/v1/health')
    return res.status === 'ok'
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Utility helpers for display
// ---------------------------------------------------------------------------

/** Map an Authority value to a human-readable display label. */
export function authorityLabel(a: Authority): string {
  const map: Record<Authority, string> = {
    untrusted: 'UNTRUSTED',
    observed: 'OBSERVED',
    user_confirmed: 'USER CONFIRMED',
    org_verified: 'ORG VERIFIED',
    system_authority: 'SYSTEM AUTHORITY',
  }
  return map[a] ?? a.toUpperCase()
}

/** Map a MemoryState to a display tone for the status pill. */
export function stateTone(
  state: MemoryState,
): 'danger' | 'warning' | 'success' | 'neutral' {
  if (state === 'blocked') return 'danger'
  if (state === 'quarantined') return 'warning'
  if (state === 'active') return 'success'
  return 'neutral'
}

/** Map a Decision to a display tone. */
export function decisionTone(
  d: Decision,
): 'danger' | 'warning' | 'success' | 'neutral' {
  if (d === 'block') return 'danger'
  if (d === 'review') return 'warning'
  if (d === 'allow') return 'success'
  return 'neutral'
}

/** Relative time string from an ISO datetime. */
export function relativeTime(iso: string): string {
  const delta = (Date.now() - new Date(iso).getTime()) / 1000
  if (delta < 60) return 'just now'
  if (delta < 3600) return `${Math.floor(delta / 60)} min ago`
  if (delta < 86400) return `${Math.floor(delta / 3600)} hr ago`
  return `${Math.floor(delta / 86400)} day(s) ago`
}
