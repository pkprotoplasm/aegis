import React, { useState, useEffect } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { api } from '../api.js'
import StatusBadge from './StatusBadge.jsx'

const TABS = [
  { label: 'Pending', value: 'pending' },
  { label: 'Reviewed', value: 'reviewed' },
  { label: 'Actioned', value: 'actioned' },
  { label: 'Dismissed', value: 'dismissed' },
  { label: 'All', value: 'all' },
]

export default function ReportList() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const { status = 'all' } = useParams()
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    setError(null)
    api
      .getReports(status)
      .then((data) => {
        setReports(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [status])

  return (
    <div>
      {/* Filter tabs */}
      <ul className="nav nav-tabs mb-3">
        {TABS.map((tab) => (
          <li className="nav-item" key={tab.value}>
            <Link
              className={`nav-link${status === tab.value ? ' active' : ''}`}
              to={`/${tab.value}`}
            >
              {tab.label}
            </Link>
          </li>
        ))}
      </ul>

      {loading && (
        <div className="text-center py-5">
          <div className="spinner-border text-secondary" role="status">
            <span className="visually-hidden">Loading…</span>
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-danger">
          <i className="bi bi-exclamation-triangle me-2"></i>
          Failed to load reports: {error}
        </div>
      )}

      {!loading && !error && (
        <div className="table-responsive">
          <table className="table table-hover table-dark align-middle">
            <thead className="table-dark">
              <tr>
                <th>Case ID</th>
                <th>Reporter</th>
                <th>Server</th>
                <th>Status</th>
                <th className="text-center">Links</th>
                <th>Reported At</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center text-muted py-5">
                    No reports found.
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr
                    key={r.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/report/${r.id}`)}
                  >
                    <td>
                      <span className="font-monospace text-warning fw-semibold">{r.case_id}</span>
                    </td>
                    <td>{r.reporter_name || r.reporter_id || '—'}</td>
                    <td>{r.guild_name || '—'}</td>
                    <td>
                      <StatusBadge status={r.status} />
                    </td>
                    <td className="text-center">
                      <span className="badge bg-secondary">{r.link_count}</span>
                    </td>
                    <td className="text-muted" style={{ whiteSpace: 'nowrap' }}>
                      {r.reported_at ? r.reported_at.substring(0, 16).replace('T', ' ') : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
