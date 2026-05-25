import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import Markdown from 'react-markdown'
import { api } from '../api.js'

export default function PrivacyPage() {
  const [content, setContent] = useState(null)
  const [error, setError]     = useState(null)

  useEffect(() => {
    api.getPrivacyPolicy()
      .then((data) => setContent(data.content))
      .catch((err) => setError(err.message))
  }, [])

  return (
    <div className="min-vh-100 d-flex flex-column" style={{ background: 'var(--bs-body-bg, #212529)' }}>
      <div className="container py-5" style={{ maxWidth: 760 }}>
        <div className="mb-4">
          <Link to="/" className="text-muted text-decoration-none small">
            <i className="bi bi-arrow-left me-1"></i>Back to dashboard
          </Link>
        </div>

        {error && (
          <div className="alert alert-danger">
            <i className="bi bi-exclamation-triangle me-2"></i>
            Failed to load privacy policy: {error}
          </div>
        )}

        {content === null && !error && (
          <div className="text-center py-5">
            <div className="spinner-border text-secondary" role="status">
              <span className="visually-hidden">Loading…</span>
            </div>
          </div>
        )}

        {content !== null && content === '' && (
          <p className="text-muted fst-italic">No privacy policy has been published yet.</p>
        )}

        {content !== null && content !== '' && (
          <div className="privacy-content text-light">
            <Markdown>{content}</Markdown>
          </div>
        )}
      </div>
    </div>
  )
}
