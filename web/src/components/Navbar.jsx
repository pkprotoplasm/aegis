import React from 'react'
import { Link, useParams, useLocation } from 'react-router-dom'

const TABS = [
  { label: 'Pending',   value: 'pending'   },
  { label: 'Reviewed',  value: 'reviewed'  },
  { label: 'Actioned',  value: 'actioned'  },
  { label: 'All',       value: 'all'       },
]

export default function Navbar({ user }) {
  const { status: currentStatus } = useParams()
  const location = useLocation()

  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-dark border-bottom border-secondary">
      <div className="container-fluid px-4">
        <Link className="navbar-brand d-flex align-items-center gap-2" to="/" style={{ fontWeight: 700, letterSpacing: '0.08em' }}>
          <img src="/aegis-logo.svg" alt="" width="32" height="32" style={{ flexShrink: 0 }}/>
          Aegis Dashboard
        </Link>
        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#navbarNav"
        >
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav me-auto">
            {TABS.map((tab) => {
              const isActive = currentStatus === tab.value
              return (
                <li className="nav-item" key={tab.value}>
                  <Link
                    className={`nav-link${isActive ? ' active fw-semibold' : ''}`}
                    to={`/${tab.value}`}
                  >
                    {tab.label}
                  </Link>
                </li>
              )
            })}
          </ul>

          {user && (
            <ul className="navbar-nav ms-auto align-items-center gap-2">
              {user.role === 'super_admin' && (
                <li className="nav-item">
                  <Link
                    className={`nav-link${location.pathname === '/admins' ? ' active' : ''}`}
                    to="/admins"
                  >
                    <i className="bi bi-people me-1"></i>
                    Admins
                  </Link>
                </li>
              )}
              <li className="nav-item">
                <span className="nav-link text-muted pe-0" style={{ fontSize: '0.875rem' }}>
                  <i className="bi bi-person-circle me-1"></i>
                  {user.discord_name}
                  {user.role === 'super_admin' && (
                    <span className="badge bg-warning text-dark ms-2" style={{ fontSize: '0.65rem' }}>super admin</span>
                  )}
                </span>
              </li>
              <li className="nav-item">
                <a className="nav-link text-secondary" href="/privacy" target="_blank" rel="noreferrer" style={{ fontSize: '0.875rem' }}>
                  Privacy
                </a>
              </li>
              <li className="nav-item">
                <a className="nav-link text-secondary" href="/api/auth/logout">
                  <i className="bi bi-box-arrow-right me-1"></i>
                  Logout
                </a>
              </li>
            </ul>
          )}
        </div>
      </div>
    </nav>
  )
}
