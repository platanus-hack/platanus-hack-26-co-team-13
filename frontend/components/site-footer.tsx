import Link from 'next/link'
import { BrandMark } from '@/components/brand-mark'

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <Link className="site-brand" href="/" aria-label="Inicio de Provenance">
        <BrandMark />
      </Link>
      <p>Creado para Platanus Hack 26 / categoría Seguridad de IA.</p>
      <span>Linaje de memoria + puerta de ejecución por procedencia.</span>
    </footer>
  )
}
