import React from 'react'
import DryRunBanner from './DryRunBanner.jsx'

const ERROR_MESSAGES = {
  unauthorized:  'Your Discord account is not authorised to access this dashboard. Contact the super admin to be added.',
  oauth_failed:  'Discord login failed — please try again.',
}

export default function LoginPage({ dryRun }) {
  const params = new URLSearchParams(window.location.search)
  const errorKey = params.get('error')
  const errorMsg = ERROR_MESSAGES[errorKey] || null

  return (
    <div className="d-flex flex-column min-vh-100">
      {dryRun && <DryRunBanner />}
      <div className="d-flex flex-grow-1 align-items-center justify-content-center flex-column gap-3">
        <div className="card border-secondary" style={{ width: '100%', maxWidth: 420 }}>
          <div className="card-body text-center p-5">
            <div className="mb-3">
              <i className="bi bi-shield-fill-check text-warning" style={{ fontSize: '3rem' }}></i>
            </div>
            <h4 className="fw-bold mb-1" style={{ letterSpacing: '0.05em' }}>Aegis Dashboard</h4>
            <p className="text-muted small mb-4">Sign in with Discord to continue</p>

            {errorMsg && (
              <div className="alert alert-danger small text-start mb-4">
                <i className="bi bi-exclamation-triangle me-2"></i>
                {errorMsg}
              </div>
            )}

            <a href="/api/auth/login" className="btn btn-primary w-100 d-flex align-items-center justify-content-center gap-2">
              <i className="bi bi-discord"></i>
              Login with Discord
            </a>
          </div>
        </div>
        <div className="d-flex gap-3">
          <a href="/tos" className="text-muted small">Terms of Service</a>
          <a href="/privacy" className="text-muted small">Privacy Policy</a>
        </div>
      </div>
    </div>
  )
}
