import React, { useState, useEffect } from 'react'
import MDEditor from '@uiw/react-md-editor'
import '@uiw/react-md-editor/markdown-editor.css'
import '@uiw/react-markdown-preview/markdown.css'
import { api } from '../api.js'
import { formatDate } from '../utils.js'

function PrivacyEditor({ showFlash }) {
  const [content, setContent]   = useState('')
  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)

  useEffect(() => {
    api.getPrivacyPolicy()
      .then((data) => setContent(data.content))
      .catch((err) => showFlash('error', `Failed to load privacy policy: ${err.message}`))
      .finally(() => setLoading(false))
  }, [])

  async function handleSave() {
    setSaving(true)
    try {
      await api.setPrivacyPolicy(content)
      showFlash('success', 'Privacy policy saved.')
    } catch (err) {
      showFlash('error', `Failed to save: ${err.message}`)
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border spinner-border-sm text-secondary"></div>
      </div>
    )
  }

  return (
    <div data-color-mode="dark">
      <MDEditor value={content} onChange={setContent} height={400} />
      <div className="d-flex align-items-center gap-3 mt-3">
        <button className="btn btn-sm btn-primary" onClick={handleSave} disabled={saving}>
          {saving ? <span className="spinner-border spinner-border-sm me-1" /> : null}
          Save
        </button>
        <a href="/privacy" target="_blank" rel="noreferrer" className="text-muted small">
          <i className="bi bi-box-arrow-up-right me-1"></i>Preview public page
        </a>
      </div>
    </div>
  )
}

function RoleBadge({ role }) {
  return role === 'super_admin'
    ? <span className="badge bg-warning text-dark"><i className="bi bi-star-fill me-1"></i>Super Admin</span>
    : <span className="badge bg-secondary">Admin</span>
}

export default function AdminPage({ currentUser }) {
  const [admins, setAdmins]     = useState([])
  const [loading, setLoading]   = useState(true)
  const [flash, setFlash]       = useState(null)
  const [newId, setNewId]       = useState('')
  const [newName, setNewName]   = useState('')
  const [adding, setAdding]     = useState(false)
  const [removing, setRemoving] = useState(null)

  function showFlash(type, message) {
    setFlash({ type, message })
    setTimeout(() => setFlash(null), 4000)
  }

  function load() {
    setLoading(true)
    api.listAdmins()
      .then(setAdmins)
      .catch((err) => showFlash('error', `Failed to load admins: ${err.message}`))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function handleAdd(e) {
    e.preventDefault()
    if (!newId.trim() || !newName.trim()) return
    setAdding(true)
    try {
      await api.addAdmin(newId.trim(), newName.trim())
      showFlash('success', `${newName} added as admin.`)
      setNewId('')
      setNewName('')
      load()
    } catch (err) {
      showFlash('error', err.message)
    } finally {
      setAdding(false)
    }
  }

  async function handleRemove(admin) {
    if (!window.confirm(`Remove ${admin.discord_name} as admin?`)) return
    setRemoving(admin.discord_id)
    try {
      await api.removeAdmin(admin.discord_id)
      showFlash('success', `${admin.discord_name} removed.`)
      load()
    } catch (err) {
      showFlash('error', err.message)
    } finally {
      setRemoving(null)
    }
  }

  return (
    <div style={{ maxWidth: 900 }}>
      <h4 className="mb-4">Admin Management</h4>

      {flash && (
        <div className={`alert alert-${flash.type === 'error' ? 'danger' : 'success'} alert-dismissible`}>
          {flash.message}
          <button className="btn-close" onClick={() => setFlash(null)}></button>
        </div>
      )}

      {/* Current admins */}
      <div className="card border-secondary mb-4">
        <div className="card-header text-muted small text-uppercase fw-semibold" style={{ letterSpacing: '0.05em' }}>
          Current Admins
        </div>
        <div className="card-body p-0">
          {loading ? (
            <div className="text-center py-4">
              <div className="spinner-border spinner-border-sm text-secondary"></div>
            </div>
          ) : (
            <table className="table table-dark table-sm mb-0">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Discord ID</th>
                  <th>Role</th>
                  <th>Added</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {admins.map((a) => (
                  <tr key={a.discord_id}>
                    <td className="fw-semibold">
                      {a.discord_name}
                      {a.discord_id === currentUser.discord_id && (
                        <span className="badge bg-info text-dark ms-2 small">you</span>
                      )}
                    </td>
                    <td className="font-monospace text-muted small">{a.discord_id}</td>
                    <td><RoleBadge role={a.role} /></td>
                    <td className="text-muted small">{formatDate(a.added_at)}</td>
                    <td className="text-end">
                      {a.role !== 'super_admin' && (
                        <button
                          className="btn btn-sm btn-outline-danger"
                          disabled={removing === a.discord_id}
                          onClick={() => handleRemove(a)}
                        >
                          {removing === a.discord_id
                            ? <span className="spinner-border spinner-border-sm"></span>
                            : <i className="bi bi-person-dash"></i>}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Privacy policy editor */}
      <div className="card border-secondary mb-4">
        <div className="card-header text-muted small text-uppercase fw-semibold" style={{ letterSpacing: '0.05em' }}>
          Privacy Policy
        </div>
        <div className="card-body">
          <p className="text-muted small mb-3">
            This content is shown at{' '}
            <a href="/privacy" target="_blank" rel="noreferrer" className="text-muted">
              /privacy
            </a>
            {' '}and is publicly accessible without login. Use Markdown to format the document.
          </p>
          <PrivacyEditor showFlash={showFlash} />
        </div>
      </div>

      {/* Add admin */}
      <div className="card border-secondary">
        <div className="card-header text-muted small text-uppercase fw-semibold" style={{ letterSpacing: '0.05em' }}>
          Add Admin
        </div>
        <div className="card-body">
          <p className="text-muted small mb-3">
            The easiest way to add admins is the <code>/add-admin</code> slash command in Discord
            — it has a built-in user picker so no IDs are needed. Use the form below only if the
            person isn't in a shared server with the bot. You can find a Discord ID by enabling
            Developer Mode in Discord settings (<strong>Settings → Advanced → Developer Mode</strong>),
            then right-clicking the user's profile and selecting <strong>Copy User ID</strong>.
          </p>
          <form onSubmit={handleAdd} className="d-flex gap-2 flex-wrap">
            <input
              className="form-control form-control-sm"
              style={{ maxWidth: 200 }}
              placeholder="Discord user ID"
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              pattern="\d{17,20}"
              title="Discord user ID (17–20 digits)"
              required
            />
            <input
              className="form-control form-control-sm"
              style={{ maxWidth: 200 }}
              placeholder="Display name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              required
            />
            <button className="btn btn-sm btn-primary" type="submit" disabled={adding}>
              {adding
                ? <span className="spinner-border spinner-border-sm me-1"></span>
                : <i className="bi bi-person-plus me-1"></i>}
              Add
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
