"""
report/html_generator.py
Generates a self-contained HTML pentest-style report.
No external dependencies — all CSS is embedded in the <style> tag.
"""

import json
from datetime import datetime
from pathlib import Path
from utils.finding import Finding, Severity

SEVERITY_COLOR = {
    Severity.CRITICAL: "#ff4444",
    Severity.HIGH:     "#ff8800",
    Severity.MEDIUM:   "#f0c040",
    Severity.INFO:     "#4a90d9",
}

SEVERITY_BG = {
    Severity.CRITICAL: "rgba(255,68,68,0.12)",
    Severity.HIGH:     "rgba(255,136,0,0.12)",
    Severity.MEDIUM:   "rgba(240,192,64,0.10)",
    Severity.INFO:     "rgba(74,144,217,0.10)",
}


def _severity_badge(sev: Severity) -> str:
    color = SEVERITY_COLOR[sev]
    return (
        f'<span style="background:{SEVERITY_BG[sev]};color:{color};'
        f'border:1px solid {color};border-radius:4px;'
        f'padding:2px 10px;font-size:11px;font-weight:700;'
        f'letter-spacing:1px;font-family:monospace">'
        f'{sev.value}</span>'
    )


def _evidence_table(rows: list[dict]) -> str:
    if not rows:
        return '<p style="color:#8b949e;font-style:italic">No evidence data.</p>'
    headers = list(rows[0].keys())
    th = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(
            f'<td style="max-width:400px;word-break:break-all">{_safe(row.get(h,""))}</td>'
            for h in headers
        )
        trs += f"<tr>{tds}</tr>"
    return f"""
    <div style="overflow-x:auto;margin-top:12px">
    <table>
      <thead><tr>{th}</tr></thead>
      <tbody>{trs}</tbody>
    </table>
    </div>"""


def _safe(val) -> str:
    if isinstance(val, (dict, list)):
        return f"<pre style='margin:0;font-size:11px'>{json.dumps(val, indent=2)}</pre>"
    return str(val) if val is not None else "—"


def _finding_card(f: Finding) -> str:
    color = SEVERITY_COLOR[f.severity]
    bg = SEVERITY_BG[f.severity]

    if f.error:
        body = f'<p style="color:#f85149">⚠ Check failed to run: {f.error}</p>'
    elif f.passed:
        body = '<p style="color:#3fb950">✓ No issues found.</p>'
    else:
        evidence_html = _evidence_table(f.evidence)
        ref_html = (
            f'<p style="margin-top:12px;font-size:12px;color:#8b949e">'
            f'Reference: <a href="{f.reference}" target="_blank" style="color:#58a6ff">{f.reference}</a></p>'
            if f.reference else ""
        )
        body = f"""
        <p style="color:#c9d1d9;margin-bottom:12px">{f.description}</p>
        {evidence_html}
        <div style="margin-top:16px;padding:12px;background:rgba(63,185,80,0.08);
                    border-left:3px solid #3fb950;border-radius:4px">
          <span style="color:#3fb950;font-weight:700;font-size:12px">RECOMMENDATION</span>
          <p style="color:#c9d1d9;margin:6px 0 0">{f.recommendation}</p>
        </div>
        {ref_html}
        """

    return f"""
    <div style="border:1px solid {color};border-radius:8px;margin-bottom:20px;
                background:{bg};overflow:hidden">
      <div style="padding:16px 20px;border-bottom:1px solid {color};
                  display:flex;align-items:center;gap:12px">
        <span style="font-family:monospace;color:{color};font-weight:700;font-size:13px">{f.id}</span>
        {_severity_badge(f.severity)}
        <span style="color:#e6edf3;font-weight:600;font-size:15px">{f.title}</span>
      </div>
      <div style="padding:16px 20px">{body}</div>
    </div>"""


def _section(severity: Severity, findings: list[Finding]) -> str:
    relevant = [f for f in findings if f.severity == severity]
    if not relevant:
        return ""
    color = SEVERITY_COLOR[severity]
    cards = "".join(_finding_card(f) for f in relevant)
    return f"""
    <section style="margin-bottom:40px">
      <h2 style="color:{color};border-bottom:2px solid {color};
                 padding-bottom:8px;font-size:18px;letter-spacing:1px">
        {severity.value} ({len(relevant)})
      </h2>
      {cards}
    </section>"""


CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #0d1117;
  color: #c9d1d9;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}
a { color: #58a6ff; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}
th {
  background: #161b22;
  color: #8b949e;
  text-align: left;
  padding: 8px 12px;
  border: 1px solid #30363d;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.5px;
}
td {
  padding: 8px 12px;
  border: 1px solid #21262d;
  color: #c9d1d9;
  vertical-align: top;
}
tr:nth-child(even) td { background: rgba(255,255,255,0.02); }
.container { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }
.score-ring {
  width: 90px; height: 90px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  flex-direction: column;
  border: 4px solid;
  font-size: 28px; font-weight: 800;
}
@media print {
  body { background: white; color: black; }
  table th { background: #eee; color: black; }
  td { color: black; border-color: #ccc; }
}
"""


def generate_report(
    output_path: str,
    findings: list[Finding],
    score: dict,
    tenant_info: dict,
    tenant_id: str,
    auth_method: str,
    run_start: datetime,
    run_end: datetime,
) -> None:
    elapsed = int((run_end - run_start).total_seconds())
    run_date = run_start.strftime("%Y-%m-%d %H:%M:%S UTC")
    tenant_name = tenant_info.get("displayName", "Unknown")

    # Summary counts
    counts = score["counts"]
    badge_color = score["badge_color"]

    summary_cells = "".join(
        f'<td style="text-align:center;padding:12px 20px">'
        f'<div style="font-size:28px;font-weight:800;color:{SEVERITY_COLOR[Severity[k]]}">{v}</div>'
        f'<div style="font-size:11px;color:#8b949e;letter-spacing:1px">{k}</div></td>'
        for k, v in counts.items()
    )

    body_sections = "".join(
        _section(sev, findings)
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IAM Risk Report — {tenant_name}</title>
  <style>{CSS}</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div style="border-bottom:1px solid #21262d;padding-bottom:32px;margin-bottom:32px">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:20px">
      <div>
        <div style="font-size:11px;color:#8b949e;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">
          IAM Risk Analyzer
        </div>
        <h1 style="font-size:28px;font-weight:800;color:#e6edf3">{tenant_name}</h1>
        <p style="color:#8b949e;margin-top:4px;font-family:monospace;font-size:12px">{tenant_id}</p>
        <div style="margin-top:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px">
          <div><span style="color:#8b949e">Date:</span> <span style="color:#c9d1d9">{run_date}</span></div>
          <div><span style="color:#8b949e">Duration:</span> <span style="color:#c9d1d9">{elapsed}s</span></div>
          <div><span style="color:#8b949e">Auth method:</span> <span style="color:#c9d1d9">{auth_method}</span></div>
        </div>
      </div>
      <div style="text-align:center">
        <div class="score-ring" style="border-color:{badge_color};color:{badge_color}">
          {score["value"]}
        </div>
        <div style="margin-top:8px;font-weight:700;color:{badge_color};letter-spacing:1px;font-size:13px">
          {score["label"]} RISK
        </div>
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <section style="margin-bottom:40px">
    <h2 style="color:#e6edf3;font-size:18px;margin-bottom:16px">Executive Summary</h2>
    <table style="width:auto">
      <thead><tr><th>CRITICAL</th><th>HIGH</th><th>MEDIUM</th><th>INFO</th></tr></thead>
      <tbody><tr>{summary_cells}</tr></tbody>
    </table>
  </section>

  <!-- Findings -->
  {body_sections}

  <!-- Footer -->
  <footer style="border-top:1px solid #21262d;padding-top:24px;margin-top:40px;
                 color:#8b949e;font-size:11px;line-height:1.8">
    <p><strong style="color:#c9d1d9">Disclaimer:</strong>
    This report was generated by IAM Risk Analyzer for authorized security assessment purposes only.
    Unauthorized use against systems you do not own or have explicit permission to test is illegal.
    All findings should be validated before remediation.</p>
    <p style="margin-top:8px">Generated by <strong style="color:#c9d1d9">IAM Risk Analyzer v0.1.0</strong>
    · <a href="https://github.com/YOUR_GITHUB/iam-risk-analyzer">GitHub</a></p>
  </footer>

</div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
