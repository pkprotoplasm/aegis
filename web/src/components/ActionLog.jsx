import React from 'react'
import { formatTime } from '../utils.js'

function actionIcon(status) {
  switch (status) {
    case 'sent':
    case 'success':
      return <i className="bi bi-check-circle-fill text-success me-1"></i>
    case 'failed':
    case 'error':
      return <i className="bi bi-x-circle-fill text-danger me-1"></i>
    default:
      return <i className="bi bi-clock-fill text-warning me-1"></i>
  }
}

function actionLabel(action) {
  switch (action) {
    case 'whois':
      return 'Email Registrar'
    case 'hosting':
      return 'Email Host'
    case 'netcraft':
      return 'Submit to Netcraft'
    case 'safebrowsing':
      return 'Report to Google'
    case 'github':
      return 'Report to GitHub'
    default:
      return action
  }
}

export default function ActionLog({ actions }) {
  if (!actions || actions.length === 0) {
    return <p className="text-muted small mb-0">No actions taken yet.</p>
  }

  return (
    <ul className="list-unstyled mb-0">
      {actions.map((a, i) => (
        <li key={i} className="action-log-item d-flex align-items-start gap-1 mb-1">
          {actionIcon(a.status)}
          <div>
            <span className="fw-semibold">{actionLabel(a.action_type)}</span>
            {a.target && (
              <span className="text-muted ms-1">→ {a.target}</span>
            )}
            {a.sent_at && (
              <span className="text-muted ms-1">
                ({formatTime(a.sent_at)})
              </span>
            )}
            {a.notes && (
              <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                {a.notes}
              </div>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}
