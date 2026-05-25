import React, { useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../api.js'
import StatusBadge from './StatusBadge.jsx'
import IntelPanel from './IntelPanel.jsx'
import ActionLog from './ActionLog.jsx'
import { formatTime } from '../utils.js'

// ─── Flash Alert ──────────────────────────────────────────────────────────────

function FlashAlert({ flash, onDismiss }) {
  useEffect(() => {
    if (!flash) return
    const timer = setTimeout(onDismiss, 4000)
    return () => clearTimeout(timer)
  }, [flash, onDismiss])

  if (!flash) return null

  return (
    <div
      className={`alert alert-${flash.type === 'error' ? 'danger' : 'success'} alert-dismissible d-flex align-items-center gap-2`}
      role="alert"
    >
      <i className={`bi ${flash.type === 'error' ? 'bi-x-circle' : 'bi-check-circle'}`}></i>
      <span>{flash.message}</span>
      <button type="button" className="btn-close" onClick={onDismiss}></button>
    </div>
  )
}

// ─── Status Update Buttons ────────────────────────────────────────────────────

const STATUS_OPTIONS = ['pending', 'reviewed', 'actioned', 'dismissed']
const STATUS_COLORS = {
  pending: 'warning',
  reviewed: 'info',
  actioned: 'success',
  dismissed: 'secondary',
}

function StatusButtons({ reportId, currentStatus, onUpdated, onFlash }) {
  const [updating, setUpdating] = useState(false)

  async function handleStatus(status) {
    if (status === currentStatus || updating) return
    setUpdating(true)
    try {
      await api.updateReportStatus(reportId, status)
      onFlash({ type: 'success', message: `Status updated to "${status}".` })
      onUpdated()
    } catch (err) {
      onFlash({ type: 'error', message: `Failed to update status: ${err.message}` })
    } finally {
      setUpdating(false)
    }
  }

  return (
    <div className="d-flex gap-2 flex-wrap">
      {STATUS_OPTIONS.map((s) => {
        const color = STATUS_COLORS[s]
        const isActive = s === currentStatus
        return (
          <button
            key={s}
            className={`btn btn-sm ${isActive ? `btn-${color}` : `btn-outline-${color}`}`}
            disabled={updating || isActive}
            onClick={() => handleStatus(s)}
          >
            {s}
          </button>
        )
      })}
    </div>
  )
}

// ─── Link Card ────────────────────────────────────────────────────────────────

function isGitHubUrl(url) {
  return url && (url.includes('github.com/') || (url.includes('github.io') && !url.match(/\w+\.github\.io/)))
}

function LinkCard({ link, onAction, onFlash }) {
  const [actionLoading, setActionLoading] = useState({})

  async function handleAction(action) {
    setActionLoading((prev) => ({ ...prev, [action]: true }))
    try {
      const result = await api.linkAction(link.id, action)
      if (result.redirect_url) {
        window.open(result.redirect_url, '_blank', 'noreferrer')
      }
      onFlash({
        type: 'success',
        message: result.notes || `Action "${action}" completed successfully.`,
      })
      onAction()
    } catch (err) {
      onFlash({ type: 'error', message: `Action failed: ${err.message}` })
    } finally {
      setActionLoading((prev) => ({ ...prev, [action]: false }))
    }
  }

  const borderColor = link.is_github_pages ? 'danger' : 'secondary'
  const showGitHubReportBtn = isGitHubUrl(link.url)

  return (
    <div className={`card border-${borderColor} mb-3`}>
      <div className="card-header d-flex align-items-start justify-content-between flex-wrap gap-2">
        <div>
          <div
            className="font-monospace text-break"
            style={{ wordBreak: 'break-all', fontSize: '0.9rem' }}
          >
            {link.url}
          </div>
          <div className="text-muted small mt-1">{link.domain}</div>
        </div>
        <div className="d-flex gap-2 flex-wrap">
          {link.is_github_pages && (
            <span className="badge bg-danger">
              <i className="bi bi-github me-1"></i>
              GitHub Pages
              {link.github_pages_user && `: ${link.github_pages_user}`}
            </span>
          )}
        </div>
      </div>

      <div className="card-body">
        {/* GitHub Pages alert */}
        {link.is_github_pages && (
          <div className="alert alert-danger py-2 mb-3" role="alert" style={{ fontSize: '0.88rem' }}>
            <i className="bi bi-info-circle me-2"></i>
            This domain uses a GitHub Pages CNAME. The actual content is hosted by GitHub.
            "Email Host" will send directly to{' '}
            <strong>abuse@github.com</strong> to request page takedown.
          </div>
        )}

        {/* Intelligence section */}
        <div className="mb-3">
          <IntelPanel linkId={link.id} />
        </div>

        {/* Action buttons */}
        <div className="mb-3">
          <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
            Actions
          </div>
          <div className="d-flex gap-2 flex-wrap">
            <button
              className="btn btn-sm btn-outline-primary"
              disabled={!!actionLoading['whois']}
              onClick={() => handleAction('whois')}
            >
              {actionLoading['whois'] ? (
                <span className="spinner-border spinner-border-sm me-1" />
              ) : (
                <i className="bi bi-envelope me-1"></i>
              )}
              Email Registrar
            </button>

            {link.is_github_pages ? (
              <button
                className="btn btn-sm btn-danger"
                disabled={!!actionLoading['hosting']}
                onClick={() => handleAction('hosting')}
              >
                {actionLoading['hosting'] ? (
                  <span className="spinner-border spinner-border-sm me-1" />
                ) : (
                  <i className="bi bi-github me-1"></i>
                )}
                Email abuse@github.com
              </button>
            ) : (
              <button
                className="btn btn-sm btn-outline-primary"
                disabled={!!actionLoading['hosting']}
                onClick={() => handleAction('hosting')}
              >
                {actionLoading['hosting'] ? (
                  <span className="spinner-border spinner-border-sm me-1" />
                ) : (
                  <i className="bi bi-envelope me-1"></i>
                )}
                Email Host
              </button>
            )}

            <button
              className="btn btn-sm btn-outline-warning"
              disabled={!!actionLoading['netcraft']}
              onClick={() => handleAction('netcraft')}
            >
              {actionLoading['netcraft'] ? (
                <span className="spinner-border spinner-border-sm me-1" />
              ) : (
                <i className="bi bi-cloud-upload me-1"></i>
              )}
              Submit to Netcraft
            </button>

            <button
              className="btn btn-sm btn-outline-secondary"
              disabled={!!actionLoading['safebrowsing']}
              onClick={() => handleAction('safebrowsing')}
            >
              {actionLoading['safebrowsing'] ? (
                <span className="spinner-border spinner-border-sm me-1" />
              ) : (
                <i className="bi bi-google me-1"></i>
              )}
              Report to Google
            </button>

            {showGitHubReportBtn && (
              <button
                className="btn btn-sm btn-outline-light"
                disabled={!!actionLoading['github']}
                onClick={() => handleAction('github')}
              >
                {actionLoading['github'] ? (
                  <span className="spinner-border spinner-border-sm me-1" />
                ) : (
                  <i className="bi bi-github me-1"></i>
                )}
                Report to GitHub
              </button>
            )}
          </div>
        </div>

        {/* Dropbox findings */}
        {link.dropbox_findings && link.dropbox_findings.length > 0 && (
          <div className="mb-3">
            <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
              <i className="bi bi-cloud-fill me-1" style={{ color: '#0061fe' }}></i>
              Dropbox Links Found
            </div>
            {link.dropbox_findings.map((d) => (
              <div key={d.id} className="d-flex align-items-start gap-2 mb-1 small">
                {d.status === 'reported'
                  ? <i className="bi bi-check-circle-fill text-success mt-1"></i>
                  : <i className="bi bi-exclamation-triangle text-warning mt-1"></i>}
                <div>
                  <a href={d.dropbox_url} target="_blank" rel="noreferrer"
                     className="font-monospace text-break text-info">
                    {d.dropbox_url}
                  </a>
                  <span className="ms-2 text-muted">
                    {d.status === 'reported' ? 'Abuse report sent to abuse@dropbox.com' : d.notes}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Triage results */}
        {link.triage_results && link.triage_results.length > 0 && (
          <div className="mb-3">
            <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
              <i className="bi bi-bug-fill text-danger me-1"></i>
              Malware Analysis (Recorded Future Triage)
            </div>
            {link.triage_results.map((t) => (
              <div key={t.id} className="d-flex align-items-start gap-2 mb-1 small">
                {t.status === 'error'
                  ? <i className="bi bi-exclamation-triangle text-warning mt-1"></i>
                  : <i className="bi bi-bug text-danger mt-1"></i>}
                <div>
                  <span className="font-monospace text-break">{t.exe_url}</span>
                  {t.report_url && (
                    <a href={t.report_url} target="_blank" rel="noreferrer"
                       className="ms-2 text-info text-nowrap">
                      Triage report ↗
                    </a>
                  )}
                  {t.error && <span className="ms-2 text-warning">{t.error}</span>}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Action log */}
        {link.actions && link.actions.length > 0 && (
          <div>
            <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
              Action Log
            </div>
            <ActionLog actions={link.actions} />
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Case Notes ──────────────────────────────────────────────────────────────

function NotesPanel({ reportId, notes, onUpdated, onFlash }) {
  const [text, setText] = useState('')
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!text.trim() || saving) return
    setSaving(true)
    try {
      await api.addNote(reportId, text.trim())
      setText('')
      onFlash({ type: 'success', message: 'Note added.' })
      onUpdated()
    } catch (err) {
      onFlash({ type: 'error', message: `Failed to add note: ${err.message}` })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mb-4">
      <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
        Internal Notes
      </div>
      {notes && notes.length > 0 ? (
        <div className="mb-3">
          {notes.map((n) => (
            <div key={n.id} className="card border-secondary mb-2">
              <div className="card-header d-flex justify-content-between align-items-center py-1 px-3 small text-muted">
                <span className="fw-semibold">{n.admin_name}</span>
                <span>{formatTime(n.created_at)}</span>
              </div>
              <div className="card-body py-2 px-3" style={{ fontSize: '0.9rem', whiteSpace: 'pre-wrap' }}>
                {n.note}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-muted small">No notes yet.</p>
      )}
      <form onSubmit={handleSubmit} className="d-flex gap-2 align-items-start">
        <textarea
          className="form-control form-control-sm"
          rows={2}
          placeholder="Add an internal note…"
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={saving}
          style={{ resize: 'vertical' }}
        />
        <button className="btn btn-sm btn-outline-secondary text-nowrap" type="submit" disabled={saving || !text.trim()}>
          {saving ? <span className="spinner-border spinner-border-sm" /> : 'Add Note'}
        </button>
      </form>
    </div>
  )
}

// ─── Reporter Message ─────────────────────────────────────────────────────────

function ReporterMessagePanel({ reportId, currentMessage, onUpdated, onFlash }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(currentMessage || '')
  const [saving, setSaving] = useState(false)

  function startEdit() {
    setText(currentMessage || '')
    setEditing(true)
  }

  function cancelEdit() {
    setEditing(false)
    setText(currentMessage || '')
  }

  async function handleSave() {
    if (saving) return
    setSaving(true)
    try {
      await api.setReporterMessage(reportId, text)
      onFlash({ type: 'success', message: 'Reporter message updated.' })
      setEditing(false)
      onUpdated()
    } catch (err) {
      onFlash({ type: 'error', message: `Failed to update message: ${err.message}` })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mb-4">
      <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
        Reporter Message
      </div>
      {!editing ? (
        <div className="d-flex align-items-start gap-2">
          <div className="flex-grow-1" style={{ fontSize: '0.9rem' }}>
            {currentMessage ? (
              <span style={{ whiteSpace: 'pre-wrap' }}>{currentMessage}</span>
            ) : (
              <span className="text-muted fst-italic">No message set — reporter sees a generic status update.</span>
            )}
          </div>
          <button className="btn btn-sm btn-outline-secondary text-nowrap" onClick={startEdit}>
            {currentMessage ? 'Edit' : 'Set message'}
          </button>
        </div>
      ) : (
        <div>
          <textarea
            className="form-control form-control-sm mb-2"
            rows={3}
            placeholder="Enter a message to show the reporter in status updates…"
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={saving}
            style={{ resize: 'vertical' }}
            autoFocus
          />
          <div className="d-flex gap-2">
            <button className="btn btn-sm btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? <span className="spinner-border spinner-border-sm me-1" /> : null}
              Save
            </button>
            <button className="btn btn-sm btn-outline-secondary" onClick={cancelEdit} disabled={saving}>
              Cancel
            </button>
            {currentMessage && (
              <button
                className="btn btn-sm btn-outline-danger ms-auto"
                disabled={saving}
                onClick={async () => {
                  setSaving(true)
                  try {
                    await api.setReporterMessage(reportId, '')
                    onFlash({ type: 'success', message: 'Reporter message cleared.' })
                    setEditing(false)
                    onUpdated()
                  } catch (err) {
                    onFlash({ type: 'error', message: `Failed to clear message: ${err.message}` })
                  } finally {
                    setSaving(false)
                  }
                }}
              >
                Clear message
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Provider Responses ───────────────────────────────────────────────────────

function ProviderResponses({ responses }) {
  if (!responses || responses.length === 0) {
    return <p className="text-muted">No provider responses yet.</p>
  }

  return responses.map((r) => (
    <div key={r.id} className="card border-success mb-3">
      <div className="card-header d-flex justify-content-between align-items-center">
        <div>
          <span className="fw-semibold">{r.from_addr}</span>
          {r.subject && (
            <span className="text-muted ms-2">— {r.subject}</span>
          )}
        </div>
        {r.received_at && (
          <span className="text-muted small">
            {formatTime(r.received_at)}
          </span>
        )}
      </div>
      <div className="card-body p-0">
        <pre className="provider-body m-0 p-3 text-light">{r.body}</pre>
      </div>
    </div>
  ))
}

// ─── Info Card ────────────────────────────────────────────────────────────────

function InfoCard({ title, children }) {
  return (
    <div className="card mb-3">
      <div className="card-header text-muted small text-uppercase fw-semibold" style={{ letterSpacing: '0.05em' }}>
        {title}
      </div>
      <div className="card-body py-2">{children}</div>
    </div>
  )
}

// ─── Main ReportDetail ────────────────────────────────────────────────────────

export default function ReportDetail() {
  const { id } = useParams()
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [flash, setFlash] = useState(null)

  const loadReport = useCallback(() => {
    setLoading(true)
    api
      .getReport(id)
      .then((data) => {
        setReport(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [id])

  useEffect(() => {
    loadReport()
  }, [loadReport])

  const dismissFlash = useCallback(() => setFlash(null), [])

  if (loading) {
    return (
      <div className="text-center py-5">
        <div className="spinner-border text-secondary" role="status">
          <span className="visually-hidden">Loading…</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div>
        <Link to="/" className="btn btn-sm btn-outline-secondary mb-3">
          <i className="bi bi-arrow-left me-1"></i>Back
        </Link>
        <div className="alert alert-danger">
          <i className="bi bi-exclamation-triangle me-2"></i>
          Failed to load report: {error}
        </div>
      </div>
    )
  }

  if (!report) return null

  return (
    <div>
      {/* Back link */}
      <Link to="/" className="btn btn-sm btn-outline-secondary mb-3">
        <i className="bi bi-arrow-left me-1"></i>Back to Reports
      </Link>

      {/* Flash */}
      <FlashAlert flash={flash} onDismiss={dismissFlash} />

      {/* Header */}
      <div className="d-flex align-items-center flex-wrap gap-3 mb-4">
        <div>
          <h4 className="mb-0">
            Report #{report.id}
            <span className="font-monospace text-warning ms-3" style={{ fontSize: '1rem' }}>
              {report.case_id}
            </span>
          </h4>
        </div>
        <StatusBadge status={report.status} />
        {report.provider_responses && report.provider_responses.length > 0 && (
          <span className="badge bg-info text-dark">
            <i className="bi bi-envelope-open me-1"></i>
            {report.provider_responses.length} response{report.provider_responses.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Info cards — two column on md+ */}
      <div className="row g-3 mb-4">
        <div className="col-md-6">
          <InfoCard title="Reporter">
            <div className="fw-semibold">{report.reporter_name || '—'}</div>
            {report.reporter_id && (
              <div className="text-muted font-monospace small">{report.reporter_id}</div>
            )}
          </InfoCard>
        </div>

        <div className="col-md-6">
          <InfoCard title="Scammer">
            {report.scammer_name ? (
              <div className="fw-semibold">{report.scammer_name}</div>
            ) : (
              <div className="text-muted fst-italic">Not specified</div>
            )}
          </InfoCard>
        </div>

        <div className="col-md-6">
          <InfoCard title="Server">
            <div className="fw-semibold">{report.guild_name || '—'}</div>
            {report.reported_at && (
              <div className="text-muted small mt-1">
                <i className="bi bi-clock me-1"></i>
                {formatTime(report.reported_at)}
              </div>
            )}
          </InfoCard>
        </div>

        <div className="col-md-6">
          <InfoCard title="Context">
            {report.context ? (
              <div style={{ fontSize: '0.9rem' }}>{report.context}</div>
            ) : (
              <div className="text-muted fst-italic">No context provided.</div>
            )}
          </InfoCard>
        </div>
      </div>

      {/* Status update */}
      <div className="mb-4">
        <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
          Update Status
        </div>
        <StatusButtons
          reportId={report.id}
          currentStatus={report.status}
          onUpdated={loadReport}
          onFlash={setFlash}
        />
      </div>

      {/* Internal Notes */}
      <NotesPanel
        reportId={report.id}
        notes={report.case_notes}
        onUpdated={loadReport}
        onFlash={setFlash}
      />

      {/* Reporter Message */}
      <ReporterMessagePanel
        reportId={report.id}
        currentMessage={report.reporter_message}
        onUpdated={loadReport}
        onFlash={setFlash}
      />

      {/* Reported Links */}
      <div className="mb-4">
        <h5 className="mb-3">
          Reported Links{' '}
          <span className="badge bg-secondary">{report.links ? report.links.length : 0}</span>
        </h5>
        {!report.links || report.links.length === 0 ? (
          <p className="text-muted">No links attached to this report.</p>
        ) : (
          report.links.map((link) => (
            <LinkCard
              key={link.id}
              link={link}
              onAction={loadReport}
              onFlash={setFlash}
            />
          ))
        )}
      </div>

      {/* Provider Responses */}
      <div className="mb-4">
        <h5 className="mb-3">
          Provider Responses{' '}
          <span className="badge bg-secondary">
            {report.provider_responses ? report.provider_responses.length : 0}
          </span>
        </h5>
        <ProviderResponses responses={report.provider_responses} />
      </div>
    </div>
  )
}
