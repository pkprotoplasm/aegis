import React, { useState } from 'react'
import { api } from '../api.js'

// ─── WHOIS Panel ─────────────────────────────────────────────────────────────

function DomainAgeBadge({ days }) {
  if (days == null) return null
  let cls = 'bg-success'
  if (days < 30) cls = 'bg-danger'
  else if (days < 180) cls = 'bg-warning text-dark'
  return (
    <span className={`badge ${cls} ms-2`}>
      {days} day{days !== 1 ? 's' : ''} old
    </span>
  )
}

function WhoisPanel({ data }) {
  if (data.error) {
    return (
      <div className="alert alert-warning mb-0">
        <i className="bi bi-exclamation-triangle me-2"></i>
        {data.error}
      </div>
    )
  }

  const rows = [
    ['Registrar', data.registrar],
    ['Created', data.created],
    ['Expires', data.expires],
    ['Updated', data.updated],
    ['Status', Array.isArray(data.status) ? data.status.join(', ') : data.status],
    ['Name Servers', Array.isArray(data.name_servers) ? data.name_servers.join(', ') : data.name_servers],
    ['Registrant', [data.registrant_name, data.registrant_org, data.registrant_country].filter(Boolean).join(', ') || null],
    ['Abuse Email', data.abuse_email],
  ]

  return (
    <div>
      <div className="d-flex align-items-center mb-2">
        <strong>{data.domain}</strong>
        <DomainAgeBadge days={data.domain_age_days} />
      </div>
      <table className="table table-sm table-dark mb-2">
        <tbody>
          {rows.map(([label, value]) =>
            value ? (
              <tr key={label}>
                <td className="text-muted" style={{ width: '30%' }}>{label}</td>
                <td className="font-monospace" style={{ fontSize: '0.82rem' }}>{value}</td>
              </tr>
            ) : null
          )}
        </tbody>
      </table>

      {data.dns_records && Object.keys(data.dns_records).length > 0 && (
        <div>
          <div className="text-muted small text-uppercase fw-semibold mb-1">DNS Records</div>
          <table className="table table-sm table-dark mb-0">
            <tbody>
              {Object.entries(data.dns_records).map(([type, values]) => {
                const vals = Array.isArray(values) ? values : [values]
                return vals.map((v, i) => {
                  const isGhCname = type === 'CNAME' && typeof v === 'string' && v.endsWith('.github.io')
                  return (
                    <tr key={`${type}-${i}`}>
                      <td className="text-muted" style={{ width: '80px' }}>{type}</td>
                      <td className="font-monospace" style={{ fontSize: '0.82rem' }}>
                        {v}
                        {isGhCname && (
                          <span className="badge bg-danger ms-2">GitHub Pages CNAME</span>
                        )}
                      </td>
                    </tr>
                  )
                })
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Host Panel ──────────────────────────────────────────────────────────────

function HostPanel({ data }) {
  if (data.error) {
    return (
      <div className="alert alert-warning mb-0">
        <i className="bi bi-exclamation-triangle me-2"></i>
        {data.error}
      </div>
    )
  }

  const rows = [
    ['IP', data.ip],
    ['ASN', data.asn ? `AS${data.asn}${data.asn_description ? ' — ' + data.asn_description : ''}` : null],
    ['Network (CIDR)', data.asn_cidr],
    ['Country', data.asn_country],
    ['Organisation', data.org],
    ['Provider', data.provider_name],
    ['Abuse Email', data.abuse_email],
  ]

  return (
    <div>
      <div className="d-flex align-items-center mb-2">
        <strong>{data.domain}</strong>
        {data.github_pages && (
          <span className="badge bg-danger ms-2">
            <i className="bi bi-github me-1"></i>
            GitHub Pages{data.github_pages_user ? `: ${data.github_pages_user}` : ''}
          </span>
        )}
      </div>
      <table className="table table-sm table-dark mb-2">
        <tbody>
          {rows.map(([label, value]) =>
            value ? (
              <tr key={label}>
                <td className="text-muted" style={{ width: '30%' }}>{label}</td>
                <td className="font-monospace" style={{ fontSize: '0.82rem' }}>{value}</td>
              </tr>
            ) : null
          )}
          {data.abuse_form && (
            <tr>
              <td className="text-muted">Abuse Form</td>
              <td>
                <a href={data.abuse_form} target="_blank" rel="noreferrer" style={{ fontSize: '0.82rem' }}>
                  {data.abuse_form}
                </a>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

// ─── Reputation Panel ────────────────────────────────────────────────────────

function reputationIcon(status) {
  switch (status) {
    case 'listed':
      return <i className="bi bi-x-octagon-fill text-danger me-2"></i>
    case 'not_listed':
      return <i className="bi bi-check-circle-fill text-success me-2"></i>
    case 'not_found':
      return <i className="bi bi-dash-circle text-secondary me-2"></i>
    case 'not_configured':
      return <i className="bi bi-gear text-muted me-2"></i>
    case 'error':
      return <i className="bi bi-exclamation-triangle text-warning me-2"></i>
    default:
      return <i className="bi bi-dash-circle text-secondary me-2"></i>
  }
}

function ReputationPanel({ data }) {
  const listedCount = data.listed_count || 0
  const checkedCount = data.checked_count || 0

  return (
    <div>
      <div className="d-flex align-items-center mb-2">
        <strong>{data.domain}</strong>
        <span className={`badge ms-2 ${listedCount > 0 ? 'bg-danger' : 'bg-success'}`}>
          {listedCount > 0
            ? `${listedCount} listed`
            : `Clean on ${checkedCount} source${checkedCount !== 1 ? 's' : ''}`}
        </span>
      </div>

      {data.checks && data.checks.map((check, i) => (
        <div key={i} className="mb-2 pb-2 border-bottom border-secondary">
          <div className="d-flex align-items-center">
            {reputationIcon(check.status)}
            <span className="fw-semibold">{check.source}</span>
            <span className="text-muted ms-2 small">{check.status.replace('_', ' ')}</span>
          </div>

          {check.status === 'listed' && (
            <div className="ms-4 mt-1" style={{ fontSize: '0.82rem' }}>
              {check.threat && (
                <span className="badge bg-danger me-2">{check.threat}</span>
              )}
              {check.reason && (
                <span className="text-muted">{check.reason}</span>
              )}
              {check.url_status && (
                <span className="badge bg-secondary ms-1">{check.url_status}</span>
              )}
              {check.tags && check.tags.length > 0 && (
                <div className="mt-1">
                  {check.tags.map((t, j) => (
                    <span key={j} className="badge bg-secondary me-1">{t}</span>
                  ))}
                </div>
              )}
              {check.return_ips && check.return_ips.length > 0 && (
                <div className="font-monospace text-muted mt-1">
                  Return IPs: {check.return_ips.join(', ')}
                </div>
              )}
              {check.reference && (
                <div className="mt-1">
                  <a href={check.reference} target="_blank" rel="noreferrer">
                    View on {check.source}
                  </a>
                </div>
              )}
              {check.malicious != null && check.total_engines != null && (
                <div className="text-muted mt-1">
                  {check.malicious} malicious, {check.suspicious ?? 0} suspicious / {check.total_engines} engines
                  {check.vt_link && (
                    <a href={check.vt_link} target="_blank" rel="noreferrer" className="ms-2">
                      View on VirusTotal
                    </a>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ─── urlscan.io Panel ────────────────────────────────────────────────────────

function UrlscanVerdictBadge({ verdict }) {
  if (!verdict || verdict.score == null) return null
  const { score, malicious } = verdict
  if (malicious) {
    return <span className="badge bg-danger ms-2">Malicious · score {score}</span>
  }
  if (score > 50) {
    return <span className="badge bg-warning text-dark ms-2">Suspicious · score {score}</span>
  }
  return <span className="badge bg-success ms-2">Clean · score {score}</span>
}

function UrlscanPanel({ data }) {
  if (data.status === 'no_key') {
    return (
      <div className="alert alert-secondary mb-0" style={{ fontSize: '0.88rem' }}>
        <i className="bi bi-info-circle me-2"></i>
        No existing scan found. Set <code>URLSCAN_API_KEY</code> to auto-submit new scans.
      </div>
    )
  }
  if (data.status === 'rate_limited') {
    return (
      <div className="alert alert-warning mb-0">
        <i className="bi bi-exclamation-triangle me-2"></i>
        urlscan.io rate limit reached — try again later.
      </div>
    )
  }
  if (data.status === 'error') {
    return (
      <div className="alert alert-warning mb-0">
        <i className="bi bi-exclamation-triangle me-2"></i>
        urlscan.io lookup failed
      </div>
    )
  }
  if (data.status === 'pending') {
    return (
      <div>
        <div className="alert alert-info mb-2" style={{ fontSize: '0.88rem' }}>
          <i className="bi bi-hourglass-split me-2"></i>
          Scan submitted — still processing. Check back shortly.
        </div>
        {data.report_url && (
          <a href={data.report_url} target="_blank" rel="noreferrer" className="btn btn-sm btn-outline-info">
            <i className="bi bi-box-arrow-up-right me-1"></i>View on urlscan.io
          </a>
        )}
      </div>
    )
  }
  if (data.status !== 'found') return null

  const { verdict, page, screenshot_url, report_url, scanned_at } = data
  const cats   = verdict?.categories || []
  const brands = verdict?.brands || []
  const tags   = verdict?.tags || []

  const rows = [
    ['Page Title', page?.title],
    ['Final URL',  page?.url],
    ['Domain',     page?.domain],
    ['IP',         page?.ip],
    ['Country',    page?.country],
    ['Server',     page?.server],
    ['Scanned',    scanned_at ? new Date(scanned_at).toLocaleString() : null],
  ]

  return (
    <div>
      <div className="d-flex align-items-center flex-wrap gap-2 mb-2">
        <strong>urlscan.io</strong>
        <UrlscanVerdictBadge verdict={verdict} />
        {report_url && (
          <a href={report_url} target="_blank" rel="noreferrer"
             className="btn btn-sm btn-outline-secondary ms-auto">
            <i className="bi bi-box-arrow-up-right me-1"></i>Full report
          </a>
        )}
      </div>

      {screenshot_url && (
        <div className="mb-2">
          <a href={report_url} target="_blank" rel="noreferrer">
            <img
              src={screenshot_url}
              alt="Page screenshot"
              style={{ maxWidth: '100%', borderRadius: 4, border: '1px solid #444' }}
            />
          </a>
        </div>
      )}

      <table className="table table-sm table-dark mb-2">
        <tbody>
          {rows.map(([label, value]) =>
            value ? (
              <tr key={label}>
                <td className="text-muted" style={{ width: '30%' }}>{label}</td>
                <td className="font-monospace" style={{ fontSize: '0.82rem' }}>{value}</td>
              </tr>
            ) : null
          )}
        </tbody>
      </table>

      {(cats.length > 0 || brands.length > 0 || tags.length > 0) && (
        <div className="d-flex flex-wrap gap-1">
          {cats.map((c, i)   => <span key={i} className="badge bg-danger">{c}</span>)}
          {brands.map((b, i) => <span key={i} className="badge bg-warning text-dark">{b}</span>)}
          {tags.map((t, i)   => <span key={i} className="badge bg-secondary">{t}</span>)}
        </div>
      )}
    </div>
  )
}

// ─── Main IntelPanel Component ───────────────────────────────────────────────

export default function IntelPanel({ linkId }) {
  const [panels, setPanels] = useState({
    whois:      { open: false, loading: false, data: null, error: null },
    host:       { open: false, loading: false, data: null, error: null },
    reputation: { open: false, loading: false, data: null, error: null },
    urlscan:    { open: false, loading: false, data: null, error: null },
  })

  async function toggle(type) {
    const panel = panels[type]

    // If already has data, just toggle visibility
    if (panel.data || panel.error) {
      setPanels((prev) => ({
        ...prev,
        [type]: { ...prev[type], open: !prev[type].open },
      }))
      return
    }

    // First open: fetch data
    setPanels((prev) => ({
      ...prev,
      [type]: { ...prev[type], open: true, loading: true },
    }))

    try {
      let data
      if (type === 'whois')           data = await api.getWhois(linkId)
      else if (type === 'host')       data = await api.getHost(linkId)
      else if (type === 'reputation') data = await api.getReputation(linkId)
      else if (type === 'urlscan')    data = await api.getUrlscan(linkId)

      setPanels((prev) => ({
        ...prev,
        [type]: { ...prev[type], loading: false, data },
      }))
    } catch (err) {
      setPanels((prev) => ({
        ...prev,
        [type]: { ...prev[type], loading: false, error: err.message },
      }))
    }
  }

  function renderPanel(type) {
    const panel = panels[type]
    if (!panel.open) return null

    if (panel.loading) {
      const msg = type === 'urlscan' ? 'Scanning… (may take up to 40s)' : 'Fetching…'
      return (
        <div className="intel-panel text-center py-3">
          <div className="spinner-border spinner-border-sm text-info" role="status">
            <span className="visually-hidden">Loading…</span>
          </div>
          <span className="text-muted ms-2">{msg}</span>
        </div>
      )
    }

    if (panel.error) {
      return (
        <div className="intel-panel">
          <div className="text-danger">
            <i className="bi bi-exclamation-triangle me-2"></i>
            {panel.error}
          </div>
        </div>
      )
    }

    if (!panel.data) return null

    return (
      <div className="intel-panel">
        {type === 'whois'      && <WhoisPanel data={panel.data} />}
        {type === 'host'       && <HostPanel data={panel.data} />}
        {type === 'reputation' && <ReputationPanel data={panel.data} />}
        {type === 'urlscan'    && <UrlscanPanel data={panel.data} />}
      </div>
    )
  }

  function activeStyle(type) {
    return panels[type].open ? 'btn-info' : 'btn-outline-info'
  }

  return (
    <div>
      <div className="text-muted small text-uppercase fw-semibold mb-2" style={{ letterSpacing: '0.05em' }}>
        Intelligence
      </div>
      <div className="d-flex gap-2 flex-wrap">
        <button
          className={`btn btn-sm ${activeStyle('whois')}`}
          onClick={() => toggle('whois')}
        >
          <i className="bi bi-search me-1"></i>
          WHOIS
        </button>
        <button
          className={`btn btn-sm ${activeStyle('host')}`}
          onClick={() => toggle('host')}
        >
          <i className="bi bi-hdd-network me-1"></i>
          Host Info
        </button>
        <button
          className={`btn btn-sm ${activeStyle('reputation')}`}
          onClick={() => toggle('reputation')}
        >
          <i className="bi bi-shield-exclamation me-1"></i>
          RBL Check
        </button>
        <button
          className={`btn btn-sm ${activeStyle('urlscan')}`}
          onClick={() => toggle('urlscan')}
          title="Search urlscan.io for screenshots and verdicts (may submit a new scan)"
        >
          <i className="bi bi-camera me-1"></i>
          urlscan.io
        </button>
      </div>
      {renderPanel('whois')}
      {renderPanel('host')}
      {renderPanel('reputation')}
      {renderPanel('urlscan')}
    </div>
  )
}
