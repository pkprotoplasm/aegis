import React from 'react'

const STATUS_COLORS = {
  pending: 'warning',
  reviewed: 'info',
  actioned: 'success',
  dismissed: 'secondary',
}

export default function StatusBadge({ status }) {
  const color = STATUS_COLORS[status] || 'secondary'
  return (
    <span className={`badge bg-${color} text-${color === 'warning' ? 'dark' : 'white'}`}>
      {status}
    </span>
  )
}
