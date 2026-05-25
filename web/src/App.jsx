import React, { useState, useEffect } from 'react'
import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import DryRunBanner from './components/DryRunBanner.jsx'
import LoginPage from './components/LoginPage.jsx'
import ReportList from './components/ReportList.jsx'
import ReportDetail from './components/ReportDetail.jsx'
import AdminPage from './components/AdminPage.jsx'
import PrivacyPage from './components/PrivacyPage.jsx'
import { api } from './api.js'

export default function App() {
  const location = useLocation()
  const [user, setUser]     = useState(undefined) // undefined = loading
  const [dryRun, setDryRun] = useState(false)

  if (location.pathname === '/privacy') {
    return <PrivacyPage />
  }

  useEffect(() => {
    api.getConfig()
      .then((c) => setDryRun(c.dry_run))
      .catch(() => {})

    api.getMe()
      .then(setUser)
      .catch(() => setUser(null))
  }, [])

  // Still resolving session
  if (user === undefined) {
    return (
      <div className="d-flex align-items-center justify-content-center min-vh-100">
        <div className="spinner-border text-secondary" role="status">
          <span className="visually-hidden">Loading…</span>
        </div>
      </div>
    )
  }

  // Not logged in
  if (!user) {
    return <LoginPage dryRun={dryRun} />
  }

  return (
    <>
      <Navbar user={user} />
      {dryRun && <DryRunBanner />}
      <div className="container-fluid py-4 px-4">
        <Routes>
          <Route path="/"            element={<Navigate to="/all" replace />} />
          <Route path="/:status"     element={<ReportList />} />
          <Route path="/report/:id"  element={<ReportDetail />} />
          {user.role === 'super_admin' && (
            <Route path="/admins" element={<AdminPage currentUser={user} />} />
          )}
        </Routes>
      </div>
    </>
  )
}
