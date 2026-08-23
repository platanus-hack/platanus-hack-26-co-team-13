export function BrandMark() {
  return (
    <span className="provenance-mark" aria-hidden="true">
      <svg viewBox="0 0 48 48" fill="none">
        <circle className="mark-segment mark-blue" cx="24" cy="24" r="18" pathLength="100" />
        <circle className="mark-segment mark-green" cx="24" cy="24" r="18" pathLength="100" />
        <circle className="mark-segment mark-yellow" cx="24" cy="24" r="18" pathLength="100" />
        <path className="mark-check" d="m14 24 7 7 15-17" />
      </svg>
    </span>
  )
}
