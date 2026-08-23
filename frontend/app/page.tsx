'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import {
  ArrowDown,
  ArrowRight,
  Ban,
  Copy,
  Database,
  FileKey,
  Fingerprint,
  GitBranch,
  LockKeyhole,
  Mail,
  PackageCheck,
  Play,
  PlugZap,
  ShieldCheck,
} from 'lucide-react'
import { useToast } from '@/components/toast-provider'
import { type RuntimeAdapterStatus, type RuntimeStatusResponse, getRuntimeStatus } from '@/lib/api'

const cliInstallCommand = `PYTHON_BIN="$(command -v python3.14 || command -v python3.13 || command -v python3.12 || command -v python3.11 || command -v python3)" && "$PYTHON_BIN" -c 'import sys; raise SystemExit("Python 3.11+ is required" if sys.version_info < (3, 11) else 0)' && "$PYTHON_BIN" -m venv ~/.memory-firewall/venv && ~/.memory-firewall/venv/bin/python -m pip install "git+https://github.com/platanus-hack/platanus-hack-26-co-team-13.git#subdirectory=backend"`

/** Shipped adapters, used until (or unless) the local core answers. */
const bundledAdapters: RuntimeAdapterStatus[] = [
  {
    name: 'Pi',
    hook: 'tool_call',
    language: 'TypeScript',
    status: 'bundled_source',
    install_command: '~/.memory-firewall/venv/bin/memory-firewall install pi',
  },
  {
    name: 'Hermes',
    hook: 'pre_tool_call',
    language: 'Python',
    status: 'bundled_source',
    install_command:
      'hermes --version >/dev/null && ~/.memory-firewall/venv/bin/memory-firewall install hermes && hermes plugins enable memory-firewall',
  },
  {
    name: 'OpenClaw',
    hook: 'before_tool_call',
    language: 'JavaScript',
    status: 'bundled_source',
    install_command:
      '~/.memory-firewall/venv/bin/memory-firewall install openclaw && openclaw plugins install --force ~/.memory-firewall/adapters/openclaw && openclaw gateway restart',
  },
]

function runtimeLabel(value: string | undefined, fallback: string) {
  const labels: Record<string, string> = {
    live: 'activo',
    sqlite: 'SQLite',
    'native pre-tool hook': 'control nativo antes de cada herramienta',
  }
  return value ? labels[value.toLowerCase()] ?? value : fallback
}

export default function LandingPage() {
  const { showToast } = useToast()
  const [runtime, setRuntime] = useState<RuntimeStatusResponse | null>(null)
  const [coreOnline, setCoreOnline] = useState<boolean | null>(null)

  useEffect(() => {
    let active = true
    void getRuntimeStatus()
      .then((status) => {
        if (!active) return
        setRuntime(status)
        setCoreOnline(true)
      })
      .catch(() => {
        if (!active) return
        setRuntime(null)
        setCoreOnline(false)
      })
    return () => {
      active = false
    }
  }, [])

  const adapters = runtime?.adapters ?? bundledAdapters
  const effectiveCliInstallCommand = runtime?.cli_install_command ?? cliInstallCommand

  async function copyCommand(command: string, label: string) {
    try {
      await navigator.clipboard.writeText(command)
      showToast(`${label} copiado.`)
    } catch {
      showToast(`Copia manualmente: ${command}`)
    }
  }

  return (
    <>
      <section className="hero" id="top">
        <div className="hero-copy">
          <h1>
            Evita que tus agentes de IA actúen con <em>información no confiable.</em>
          </h1>
          <p>
            Provenance Firewall recuerda de dónde viene cada dato. Antes de que un agente pague,
            envíe o elimine algo, comprueba si esa información tiene permiso y bloquea la acción si
            no lo tiene.
          </p>
          <div className="hero-promises" aria-label="Funciones principales">
            <span>
              <Fingerprint /> Rastrea el origen
            </span>
            <span>
              <GitBranch /> Conserva la autoridad
            </span>
            <span>
              <Ban /> Detiene acciones riesgosas
            </span>
          </div>
          <div className="hero-actions">
            <Link className="primary-action" href="/demo">
              <Play /> Probar el demo del correo
            </Link>
            <a href="#mechanism">
              Cómo funciona <ArrowDown />
            </a>
          </div>
        </div>

        <aside className="custody-hero product-example protected">
          <div className="example-topline">
            <span>EJEMPLO: PAGO A PROVEEDOR</span>
            <strong>PAGO BLOQUEADO</strong>
          </div>
          <h2>Un correo intenta cambiar la cuenta bancaria de un proveedor.</h2>
          <p>
            Aunque otro agente guarde o resuma ese correo, el dato sigue marcado como externo y no
            obtiene permiso para autorizar un pago.
          </p>
          <div className="example-result">
            <span>Resultado</span>
            <strong>0 pagos ejecutados</strong>
          </div>
          <div className="custody-route">
            <span>
              <Mail /> Correo externo
            </span>
            <i />
            <span>
              <Database /> Memoria del agente
            </span>
            <i />
            <span className="route-stop">
              <Ban /> Pago bloqueado
            </span>
          </div>
          <small className="example-proof">
            La información puede cambiar de forma, pero no puede ganar autoridad por sí sola.
          </small>
        </aside>
      </section>

      <section className="proof-bar" aria-label="Evidencia técnica">
        <span>
          <Fingerprint /> Sobres firmados
        </span>
        <span>
          <GitBranch /> Derivación con linaje preservado
        </span>
        <span>
          <PlugZap /> Tres integraciones nativas
        </span>
        <span>
          <LockKeyhole /> Ejecución cerrada ante fallos
        </span>
      </section>

      <section className="mechanism" id="mechanism">
        <div className="section-intro">
          <h2>Memory Firewall y Provenance Firewall comparten una cadena.</h2>
          <p>
            Memory conserva el linaje entre sesiones. Provenance consume esos identificadores
            verificados justo cuando Pi, Hermes u OpenClaw están a punto de ejecutar.
          </p>
        </div>
        <div className="trace-board">
          <article className="source-document">
            <div className="document-meta">
              <span>SESIÓN A / ENTRADA</span>
              <strong>NO CONFIABLE</strong>
            </div>
            <Mail />
            <p>Andina Logistics cambió su cuenta a 8842.</p>
            <small>origen: correo_externo / agente: external:andina-email</small>
          </article>
          <div className="trace-line" aria-hidden="true">
            <i />
            <ArrowRight />
          </div>
          <article className="argument-document">
            <div className="document-meta">
              <span>SQLITE / SESIÓN B</span>
              <strong>VERIFICADA</strong>
            </div>
            <code>analysis_id: sobre firmado</code>
            <code className="trace-hit">padre: correo externo</code>
            <code className="trace-hit">autoridad: NO CONFIABLE</code>
            <code>transformación: resumen</code>
          </article>
          <div className="trace-line" aria-hidden="true">
            <i />
            <ArrowRight />
          </div>
          <article className="decision-document">
            <div className="document-meta">
              <span>PUERTA DE EJECUCIÓN</span>
              <strong>POLÍTICA</strong>
            </div>
            <div className="authority-check">
              <span>NO CONFIABLE</span>
              <b>&lt;</b>
              <span>ORG. VERIFICADA</span>
            </div>
            <p>La misma decisión firmada es consumida por la puerta local y los adaptadores nativos.</p>
            <div className="stamp-mark">
              <ShieldCheck /> CIERRE SEGURO
            </div>
          </article>
        </div>
      </section>

      <section className="evidence-section" id="adapters">
        <div className="evidence-copy">
          <h2>Instálalo donde el agente ejecuta herramientas.</h2>
          <p>
            Cada adaptador se integra al evento nativo que ocurre antes de ejecutar una herramienta y
            lo traduce a un protocolo estricto. La falta de linaje, un tiempo de
            espera agotado, una respuesta inválida o un fallo del núcleo produce un bloqueo en lugar
            de una ejecución.
          </p>
          <Link className="text-action" href="/demo">
            Ver el bloqueo en vivo <ArrowRight />
          </Link>
        </div>
        <div className="adapter-sheet">
          <div className="sheet-number">INSTALACIÓN DE ADAPTADORES NATIVOS / V0.1.0</div>
          <div className="adapter-bootstrap">
            <div>
              <span>1. INSTALA EL CLI</span>
              <small>Solo una vez por entorno</small>
            </div>
            <code>{effectiveCliInstallCommand}</code>
            <button
              onClick={() => void copyCommand(effectiveCliInstallCommand, 'Comando del CLI')}
              aria-label="Copiar comando de instalación del CLI"
            >
              <Copy />
            </button>
          </div>
          {adapters.map((adapter) => (
            <div className="adapter-sheet-row" key={adapter.name}>
              <div>
                <span>{adapter.name}</span>
                <small>
                  Integración alternativa / {adapter.language} / {adapter.hook}
                </small>
              </div>
              <code>{adapter.install_command}</code>
              <button
                onClick={() =>
                  void copyCommand(adapter.install_command, `Comando de instalación de ${adapter.name}`)
                }
                aria-label={`Copiar comando de instalación de ${adapter.name}`}
              >
                <Copy />
              </button>
            </div>
          ))}
          <div className="signature-line">
            <FileKey /> Un protocolo central / control previo a ejecutar
          </div>
        </div>
      </section>

      <section className="control-plane" id="runtime">
        <div className="plane-header">
          <div>
            <h2>Conecta el agente que ya usas.</h2>
            <p>
              Provenance se coloca antes de cada herramienta. Elige una integración para tu runtime;
              Pi, Hermes y OpenClaw son alternativas, no pasos consecutivos.
            </p>
          </div>
          <div className="plane-statuses">
            <div className="connection-state">
              <span className={coreOnline ? 'online' : ''} />
              {coreOnline === null
                ? 'comprobando núcleo'
                : coreOnline
                  ? 'núcleo local activo'
                  : 'núcleo desconectado'}
            </div>
          </div>
        </div>

        <div className="runtime-docket" aria-label="Registro de instalación del entorno de ejecución">
          <div>
            <small>NÚCLEO</small>
            <strong>{runtimeLabel(runtime?.core_status, 'desconocido')}</strong>
          </div>
          <div>
            <small>ALMACÉN DE MEMORIA</small>
            <strong>{runtimeLabel(runtime?.memory_store, 'SQLite esperado')}</strong>
          </div>
          <div>
            <small>CONTROL DE HERRAMIENTAS</small>
            <strong>
              {runtimeLabel(runtime?.execution_boundary, 'control nativo antes de cada herramienta')}
            </strong>
          </div>
          <div>
            <small>INTEGRACIONES</small>
            <strong>{adapters.length} alternativas</strong>
          </div>
        </div>

        <div className="adapter-console">
          <div className="adapter-toolbar">
            <div>
              <h3>1. Instala el CLI una vez</h3>
              <p>Después elige un solo adaptador para el agente que ya usas.</p>
            </div>
            <button
              className="bootstrap-command"
              onClick={() => void copyCommand(effectiveCliInstallCommand, 'Comando del CLI')}
            >
              <code>{effectiveCliInstallCommand}</code>
              <Copy />
            </button>
          </div>
          <div className="adapter-grid">
            {adapters.map((adapter) => (
              <article key={adapter.name}>
                <div className="adapter-heading">
                  <PackageCheck />
                  <div>
                    <small>{adapter.language}</small>
                    <h3>{adapter.name}</h3>
                  </div>
                </div>
                <dl>
                  <div>
                    <dt>Integración nativa</dt>
                    <dd>{adapter.hook}</dd>
                  </div>
                  <div>
                    <dt>Contrato</dt>
                    <dd>tool-call.v1</dd>
                  </div>
                  <div>
                    <dt>Modo ante fallos</dt>
                    <dd>bloquear</dd>
                  </div>
                  <div>
                    <dt>Conexión del entorno</dt>
                    <dd>
                      {runtime?.live_connections.includes(adapter.name.toLowerCase())
                        ? 'conectado'
                        : 'no conectado'}
                    </dd>
                  </div>
                </dl>
                <button
                  className="install-command"
                  onClick={() =>
                    void copyCommand(
                      adapter.install_command,
                      `Comando de instalación de ${adapter.name}`,
                    )
                  }
                >
                  <code>{adapter.install_command}</code>
                  <Copy />
                </button>
              </article>
            ))}
          </div>
          <p className="adapter-disclaimer">
            Adaptador verificado significa que su traducción de eventos nativos y su contrato de
            cierre seguro están probados en este repositorio. No significa que haya un proceso de
            agente conectado en este momento.
          </p>
        </div>
      </section>

      <section className="closing-section">
        <div>
          <h2>El texto puede cambiar de forma. Su autoridad no puede aumentar en silencio.</h2>
          <p>
            Crea tu cuenta, envía un correo malicioso al buzón del agente y revisa en tu actividad
            qué movimientos quedaron bloqueados.
          </p>
        </div>
        <div className="closing-actions">
          <Link className="primary-action" href="/demo">
            Probar el demo <ArrowRight />
          </Link>
          <Link className="ghost-action" href="/login">
            Crear cuenta
          </Link>
        </div>
      </section>
    </>
  )
}
