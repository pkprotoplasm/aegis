import React from 'react'

export default function DryRunBanner() {
  return (
    <div
      className="alert alert-warning mb-0 rounded-0 border-0 border-bottom border-warning d-flex align-items-center gap-2"
      role="alert"
      style={{
        background:
          'repeating-linear-gradient(45deg, rgba(255,193,7,0.15), rgba(255,193,7,0.15) 10px, rgba(255,193,7,0.05) 10px, rgba(255,193,7,0.05) 20px)',
      }}
    >
      <i className="bi bi-cone-striped fs-5 text-warning"></i>
      <span>
        <strong>Test mode active (DRY_RUN=1)</strong> — abuse emails and Netcraft submissions will
        be logged but not sent.
      </span>
    </div>
  )
}
