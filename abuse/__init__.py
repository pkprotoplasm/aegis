def triage_section(triage_results):
    """Return a formatted triage block for inclusion in abuse email bodies."""
    if not triage_results:
        return ""
    lines = ["\nMalware analysis (Recorded Future Triage):"]
    for t in triage_results:
        if t.get("report_url"):
            lines.append(f"  • {t['exe_url']}\n    Report: {t['report_url']}")
        else:
            lines.append(f"  • {t['exe_url']} (analysis pending or failed)")
    return "\n".join(lines)
