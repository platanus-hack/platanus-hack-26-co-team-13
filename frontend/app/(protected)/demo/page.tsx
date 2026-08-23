'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { type FormEvent, useRef, useState } from 'react'
import {
  ArrowRight,
  Ban,
  Bot,
  Check,
  CircleAlert,
  GitBranch,
  HardDrive,
  Inbox,
  LayoutDashboard,
  LockKeyhole,
  Mail,
  MessageSquare,
  RefreshCw,
  RotateCcw,
  Send,
  ShieldCheck,
  TerminalSquare,
  UserRound,
} from 'lucide-react'
import { useSession } from '@/components/session-provider'
import { useToast } from '@/components/toast-provider'
import {
  type DemoAgentAnswer,
  type DemoAgentStep,
  type DemoEmailVerdict,
  type DemoStepId,
  ApiError,
  askDemoAgent,
  authorityHint,
  authorityLabel,
  decisionLabel,
  decisionTone,
  eventTypeLabel,
  reasonLabel,
  relativeTime,
  severityLabel,
  severityTone,
  shortId,
  stateHint,
  stateLabel,
  stateTone,
  stepStatusLabel,
  stepTone,
  submitDemoEmail,
} from '@/lib/api'

const MAX_SENDER = 120
const MAX_SUBJECT = 200
const MAX_BODY = 5_000
const MAX_QUESTION = 500

const stepIcons: Record<DemoStepId, React.ReactNode> = {
  write: <Inbox />,
  derive: <GitBranch />,
  retrieve: <HardDrive />,
  tool: <TerminalSquare />,
}

const stepStory: Record<DemoStepId, string> = {
  write: 'El correo entra al buzón y queda marcado con el origen del que llegó.',
  derive: 'El agente lo resume: el texto cambia, la autoridad heredada no.',
  retrieve: 'Otra sesión recupera esa memoria y vuelve a verificar su firma.',
  tool: 'La puerta de ejecución compara autoridad requerida contra autoridad disponible.',
}

function stepStatusIcon(status: DemoAgentStep['status']) {
  if (status === 'blocked') return <Ban />
  if (status === 'quarantined') return <CircleAlert />
  return <Check />
}

/** Escapes are handled by React; this only bounds what we render inline. */
function clamp(value: string, max: number) {
  return value.length > max ? value.slice(0, max) : value
}

export default function DemoPage() {
  const router = useRouter()
  const { reload } = useSession()
  const { showToast } = useToast()

  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [emailBusy, setEmailBusy] = useState(false)
  const [emailError, setEmailError] = useState('')
  const [verdict, setVerdict] = useState<DemoEmailVerdict | null>(null)

  const [question, setQuestion] = useState('')
  const [askBusy, setAskBusy] = useState(false)
  const [askError, setAskError] = useState('')
  const [answer, setAnswer] = useState<DemoAgentAnswer | null>(null)

  const verdictRef = useRef<HTMLHeadingElement>(null)
  const answerRef = useRef<HTMLHeadingElement>(null)
  const composerRef = useRef<HTMLInputElement>(null)

  const stage: 1 | 2 | 3 = answer ? 3 : verdict ? 2 : 1

  function describeError(caught: unknown, fallback: string): string {
    if (caught instanceof ApiError) {
      if (caught.status === 401) {
        void reload()
        router.replace('/login')
        return 'Tu sesión venció. Te llevamos al inicio de sesión…'
      }
      if (caught.status === 429) return 'Demasiadas solicitudes seguidas. Espera un momento e inténtalo otra vez.'
      if (caught.code === 'network_unreachable') {
        return 'No se pudo contactar el núcleo local del firewall. Confirma que el backend esté activo.'
      }
      if (caught.code === 'validation_error') {
        return 'El backend rechazó el contenido: revisa los límites de longitud y evita caracteres de control.'
      }
      if (caught.code === 'analysis_not_found') {
        return 'Ese mensaje ya no está en tu espacio. Vuelve a entregar el correo.'
      }
    }
    return fallback
  }

  async function handleDeliver(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setEmailBusy(true)
    setEmailError('')
    setAnswer(null)
    setAskError('')
    try {
      const result = await submitDemoEmail({
        sender: clamp(sender.trim(), MAX_SENDER),
        subject: clamp(subject.trim(), MAX_SUBJECT),
        body: clamp(body, MAX_BODY),
      })
      setVerdict(result)
      showToast('Correo entregado al buzón del agente.')
      // Move focus to the verdict so screen readers land on the new content.
      window.requestAnimationFrame(() => verdictRef.current?.focus())
    } catch (caught) {
      setEmailError(describeError(caught, 'No se pudo entregar el correo al buzón del agente.'))
    } finally {
      setEmailBusy(false)
    }
  }

  async function handleAsk(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!verdict) return
    setAskBusy(true)
    setAskError('')
    try {
      const result = await askDemoAgent({
        message_id: verdict.message_id,
        question: clamp(question.trim(), MAX_QUESTION),
      })
      setAnswer(result)
      showToast(
        result.executed
          ? 'El agente ejecutó la acción.'
          : 'La acción de riesgo no llegó a ejecutarse.',
      )
      window.requestAnimationFrame(() => answerRef.current?.focus())
    } catch (caught) {
      setAskError(describeError(caught, 'El agente no pudo responder tu pregunta.'))
    } finally {
      setAskBusy(false)
    }
  }

  function resetFlow() {
    setVerdict(null)
    setAnswer(null)
    setEmailError('')
    setAskError('')
    setQuestion('')
    window.requestAnimationFrame(() => composerRef.current?.focus())
  }

  const riskPercent = verdict ? Math.round(verdict.risk_score * 100) : 0
  const riskTone = riskPercent >= 70 ? 'danger' : riskPercent >= 35 ? 'warning' : 'success'

  return (
    <section className="workspace-page">
      <div className="workspace-shell">
        <div className="workspace-heading">
          <div>
            <h1>Demo: un correo malicioso frente al agente</h1>
            <p>
              Escribe el correo que quieras, entrégalo al buzón del agente y pregúntale algo sobre
              él. Todo ocurre en tu espacio aislado y con herramientas sintéticas: no se contacta
              ninguna red de pagos real.
            </p>
          </div>
          <span className="workspace-tag">
            <LockKeyhole /> ENTORNO SINTÉTICO
          </span>
        </div>

        <ol className="step-rail" aria-label="Progreso del demo">
          <li className={stage === 1 ? 'current' : 'done'}>
            <b aria-hidden="true">1</b>
            <div>
              <small>Paso 1</small>
              <span>Redactar el correo</span>
            </div>
          </li>
          <li className={stage === 2 ? 'current' : stage > 2 ? 'done' : ''}>
            <b aria-hidden="true">2</b>
            <div>
              <small>Paso 2</small>
              <span>Veredicto de ingreso</span>
            </div>
          </li>
          <li className={stage === 3 ? 'current' : ''}>
            <b aria-hidden="true">3</b>
            <div>
              <small>Paso 3</small>
              <span>Preguntar al agente</span>
            </div>
          </li>
        </ol>

        {/* ---------------------------------------------------------------- */}
        {/* Paso 1 — redactar el correo                                       */}
        {/* ---------------------------------------------------------------- */}
        <div className="demo-panel">
          <div className="panel-head">
            <div>
              <h2>
                <Mail /> Redacta el correo entrante
              </h2>
              <p>Tú escribes el contenido. El firewall no sabe qué vas a mandar.</p>
            </div>
            {verdict && (
              <button className="secondary-action" onClick={resetFlow} type="button">
                <RotateCcw /> Escribir otro correo
              </button>
            )}
          </div>

          <form className="mail-composer" onSubmit={(event) => void handleDeliver(event)}>
            <div className="mail-field">
              <label htmlFor="mail-sender">De</label>
              <input
                id="mail-sender"
                ref={composerRef}
                value={sender}
                onChange={(event) => setSender(event.target.value)}
                placeholder="proveedor@dominio-externo.example"
                maxLength={MAX_SENDER}
                autoComplete="off"
                spellCheck={false}
                disabled={emailBusy || verdict !== null}
                required
              />
            </div>
            <div className="mail-field">
              <label htmlFor="mail-subject">Asunto</label>
              <input
                id="mail-subject"
                value={subject}
                onChange={(event) => setSubject(event.target.value)}
                placeholder="Actualización urgente de datos bancarios"
                maxLength={MAX_SUBJECT}
                autoComplete="off"
                disabled={emailBusy || verdict !== null}
                required
              />
            </div>
            <div className="mail-body">
              <label htmlFor="mail-body">Cuerpo del mensaje</label>
              <textarea
                id="mail-body"
                value={body}
                onChange={(event) => setBody(event.target.value)}
                placeholder="Escribe aquí el contenido del correo, incluida cualquier instrucción que quieras intentar colar al agente."
                maxLength={MAX_BODY}
                rows={10}
                disabled={emailBusy || verdict !== null}
                aria-describedby="mail-body-count"
                required
              />
              <small id="mail-body-count" className="char-count">
                {body.length} / {MAX_BODY} caracteres
              </small>
            </div>

            <div aria-live="assertive">
              {emailError !== '' && (
                <p className="inline-alert" role="alert">
                  <CircleAlert /> <span>{emailError}</span>
                </p>
              )}
            </div>

            <div className="mail-footer">
              <small>
                El correo se guarda como memoria no confiable dentro de tu espacio. Nada de lo que
                escribas se envía a un destinatario real.
              </small>
              <button className="primary-action" disabled={emailBusy || verdict !== null}>
                {emailBusy ? <RefreshCw className="spinning" /> : <Send />}
                {emailBusy ? 'Entregando' : 'Entregar al buzón del agente'}
              </button>
            </div>
          </form>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* Paso 2 — veredicto de ingreso                                     */}
        {/* ---------------------------------------------------------------- */}
        <div className="demo-panel-slot" aria-live="polite">
          {verdict && (
            <div className="demo-panel">
              <div className="panel-head">
                <div>
                  <h2 ref={verdictRef} tabIndex={-1}>
                    <ShieldCheck /> Veredicto de ingreso
                  </h2>
                  <p>
                    Mensaje <code>{shortId(verdict.message_id, 28)}</code> ·{' '}
                    {relativeTime(verdict.created_at)}
                  </p>
                </div>
              </div>

              <div className="verdict-grid">
                <div className="verdict-primary">
                  <span className={`verdict-badge ${decisionTone(verdict.decision)}`}>
                    {verdict.decision === 'block' ? <Ban /> : verdict.decision === 'review' ? <CircleAlert /> : <Check />}
                    {decisionLabel(verdict.decision)}
                  </span>

                  <div className="risk-meter">
                    <div className="risk-meter-head">
                      <span>Puntaje de riesgo</span>
                      <b>{riskPercent}%</b>
                    </div>
                    <div
                      className="risk-meter-track"
                      role="meter"
                      aria-valuenow={riskPercent}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-label="Puntaje de riesgo del correo"
                    >
                      <div className={`risk-meter-fill ${riskTone}`} style={{ width: `${riskPercent}%` }} />
                    </div>
                  </div>

                  <dl className="verdict-facts">
                    <div>
                      <dt>Autoridad asignada</dt>
                      <dd>{authorityLabel(verdict.authority)}</dd>
                    </div>
                    <div>
                      <dt>Estado de la memoria</dt>
                      <dd className={`tone-${stateTone(verdict.state)}`}>{stateLabel(verdict.state)}</dd>
                    </div>
                  </dl>
                  <p className="verdict-explainer">{authorityHint(verdict.authority)}</p>
                  <p className="verdict-explainer">{stateHint(verdict.state)}</p>
                </div>

                <div className="verdict-detail">
                  <h3>
                    Amenazas detectadas por patrones{' '}
                    <span className="count-chip">{verdict.threats.length}</span>
                  </h3>

                  {verdict.threats.length === 0 ? (
                    <p className="no-threats">
                      <CircleAlert />
                      <span>
                        <b>Sin amenazas detectadas por patrones</b>, y aun así la acción se bloqueará
                        por autoridad de origen. El firewall no necesita reconocer el ataque: le
                        basta con saber que el dato entró desde un correo externo.
                      </span>
                    </p>
                  ) : (
                    <ul className="threat-list">
                      {verdict.threats.map((threat, index) => (
                        <li key={`${threat.type}-${threat.line}-${index}`}>
                          <span className={`threat-sev sev-${severityTone(threat.severity)}`}>
                            {severityLabel(threat.severity)}
                          </span>
                          <div>
                            <b>{threat.type}</b>
                            <p>{threat.description}</p>
                            <code>
                              línea {threat.line} · confianza {Math.round(threat.confidence * 100)}% ·{' '}
                              {threat.indicator}
                            </code>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}

                  <h3>Motivo registrado</h3>
                  <p className="verdict-reason">{reasonLabel(verdict.reason)}</p>

                  <h3>Vista previa saneada</h3>
                  <pre className="sanitized-preview">{verdict.sanitized_preview}</pre>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* Paso 3 — preguntar al agente                                      */}
        {/* ---------------------------------------------------------------- */}
        {verdict && (
          <div className="demo-panel">
            <div className="panel-head">
              <div>
                <h2>
                  <MessageSquare /> Pregúntale al agente
                </h2>
                <p>El agente ya leyó el correo. Pídele algo que dependa de ese contenido.</p>
              </div>
            </div>

            <form className="agent-ask" onSubmit={(event) => void handleAsk(event)}>
              <label htmlFor="agent-question">Tu pregunta al agente</label>
              <div className="agent-ask-row">
                <input
                  id="agent-question"
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  placeholder="¿Puedes pagar la factura que llegó?"
                  maxLength={MAX_QUESTION}
                  autoComplete="off"
                  disabled={askBusy}
                  required
                />
                <button className="primary-action" disabled={askBusy}>
                  {askBusy ? <RefreshCw className="spinning" /> : <Bot />}
                  {askBusy ? 'Consultando' : 'Preguntar al agente'}
                </button>
              </div>
              <small className="field-hint">
                La acción se deduce con una tabla determinista de palabras clave, nunca con un
                modelo de lenguaje.
              </small>

              <div aria-live="assertive">
                {askError !== '' && (
                  <p className="inline-alert" role="alert">
                    <CircleAlert /> <span>{askError}</span>
                  </p>
                )}
              </div>
            </form>

            <div aria-live="polite">
              {answer && (
                <>
                  <div className="agent-exchange">
                    <p className="chat-user">
                      <UserRound /> <span>{answer.question}</span>
                    </p>
                    <div className="chat-bubble">
                      <span className="chat-from">
                        <Bot /> AGENTE
                      </span>
                      <p>{answer.agent_answer}</p>
                    </div>
                    <dl className="exchange-facts">
                      <div>
                        <dt>Acción deducida</dt>
                        <dd>
                          <code>{answer.inferred_action}</code>
                        </dd>
                      </div>
                      <div>
                        <dt>Veredicto</dt>
                        <dd className={`tone-${decisionTone(answer.decision)}`}>
                          {decisionLabel(answer.decision)}
                        </dd>
                      </div>
                    </dl>
                  </div>

                  <div className="panel-head">
                    <div>
                      <h2 ref={answerRef} tabIndex={-1}>
                        Cadena de custodia de esta respuesta
                      </h2>
                      <p>Cuatro hops auditables entre el correo entrante y la herramienta.</p>
                    </div>
                  </div>

                  <ol className="trace-timeline">
                    {answer.steps.map((step, index) => (
                      <li className={`trace-step ${step.status}`} key={`${step.id}-${index}`}>
                        <span className="trace-dot" aria-hidden="true">
                          {stepIcons[step.id] ?? <TerminalSquare />}
                        </span>
                        <div className="trace-body">
                          <div className="trace-head">
                            <h3>{step.label}</h3>
                            <span className={`trace-status tone-${stepTone(step.status)}`}>
                              {stepStatusIcon(step.status)} {stepStatusLabel(step.status)}
                            </span>
                            <span className="trace-tag">{eventTypeLabel(step.event_type)}</span>
                          </div>
                          <p className="trace-story">{stepStory[step.id] ?? ''}</p>
                          <p>{reasonLabel(step.detail)}</p>
                          <div className="trace-meta">
                            <span>
                              autoridad <b>{authorityLabel(step.authority)}</b>
                            </span>
                            <span>
                              evidencia <b>{shortId(step.analysis_id, 20)}</b>
                            </span>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ol>

                  <div className={`proof-callout ${answer.executed ? 'executed' : ''}`}>
                    <div className="proof-figures">
                      <div>
                        <small>Invocaciones de la función</small>
                        <strong>{answer.function_invocations}</strong>
                      </div>
                      <div>
                        <small>¿Se ejecutó?</small>
                        <strong>{answer.executed ? 'SÍ' : 'NO'}</strong>
                      </div>
                    </div>
                    <div>
                      <h3>
                        {answer.executed
                          ? 'La acción se ejecutó porque la evidencia alcanzó la autoridad requerida.'
                          : `La función ${answer.inferred_action} NUNCA se ejecutó.`}
                      </h3>
                      <p>
                        {answer.executed
                          ? 'La puerta de ejecución permite la acción solo cuando el linaje completo cumple autoridad, capacidad, alcance y vigencia.'
                          : 'No es una respuesta persuadida ni un modelo que decidió portarse bien: el callable sintético no fue invocado ni una sola vez. El bloqueo ocurre antes de la ejecución.'}
                      </p>
                    </div>
                  </div>

                  <div className="panel-actions">
                    <Link className="primary-action" href="/dashboard">
                      <LayoutDashboard /> Ver en mi actividad <ArrowRight />
                    </Link>
                    <button className="secondary-action" onClick={resetFlow} type="button">
                      <RotateCcw /> Escribir otro correo
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
