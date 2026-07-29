"""
report/html_generator.py
Generates a self-contained, light-theme HTML report with a Spanish/English
toggle, the company logo, and a custom footer. All CSS/JS is embedded so the
file is fully portable.

Finding text (title/description/recommendation) may be either a plain string or
a {"es": ..., "en": ...} dict; both are handled.
"""

import base64
import json
from datetime import datetime
from pathlib import Path

from utils.finding import Finding, Severity

# Light-theme severity palette (accessible contrast on white).
SEVERITY_COLOR = {
    Severity.CRITICAL: "#c1121f",
    Severity.HIGH:     "#bc4c00",
    Severity.MEDIUM:   "#9a6700",
    Severity.INFO:     "#0969da",
}
SEVERITY_BG = {
    Severity.CRITICAL: "#fdeff0",
    Severity.HIGH:     "#fdf1e9",
    Severity.MEDIUM:   "#fdf6e3",
    Severity.INFO:     "#eef4fc",
}

# Bilingual severity names (es, en).
SEVERITY_NAME = {
    Severity.CRITICAL: ("CRÍTICO", "CRITICAL"),
    Severity.HIGH:     ("ALTO", "HIGH"),
    Severity.MEDIUM:   ("MEDIO", "MEDIUM"),
    Severity.INFO:     ("INFORMATIVO", "INFO"),
}

# Bilingual risk-level words for the score ring.
RISK_LABEL = {
    "LOW":      ("BAJO", "LOW"),
    "MEDIUM":   ("MEDIO", "MEDIUM"),
    "HIGH":     ("ALTO", "HIGH"),
    "CRITICAL": ("CRÍTICO", "CRITICAL"),
}

BRAND_NAVY = "#1f3a68"


# ---------------------------------------------------------------------------
# Bilingual helpers
# ---------------------------------------------------------------------------
def L(es: str, en: str) -> str:
    """Render a static bilingual string as two toggled spans."""
    return f'<span class="t-es">{es}</span><span class="t-en">{en}</span>'


def BT(field, block: bool = False) -> str:
    """
    Render a Finding text field (dict {es,en} or plain str) as toggled spans.
    Falls back to showing the same text in both languages if given a str.
    """
    if isinstance(field, dict):
        es = field.get("es", "")
        en = field.get("en", "")
    else:
        es = en = str(field or "")
    cls = "b-es" if block else "t-es"
    cls2 = "b-en" if block else "t-en"
    return f'<span class="{cls}">{es}</span><span class="{cls2}">{en}</span>'


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
def _severity_badge(sev: Severity) -> str:
    color = SEVERITY_COLOR[sev]
    es, en = SEVERITY_NAME[sev]
    return (
        f'<span style="background:{SEVERITY_BG[sev]};color:{color};'
        f'border:1px solid {color};border-radius:4px;padding:2px 10px;font-size:11px;'
        f'font-weight:700;letter-spacing:1px;font-family:monospace">{L(es, en)}</span>'
    )


def _safe(val) -> str:
    if isinstance(val, (dict, list)):
        return f"<pre style='margin:0;font-size:11px'>{json.dumps(val, indent=2, ensure_ascii=False)}</pre>"
    return str(val) if val is not None else "—"


def _evidence_table(rows: list[dict]) -> str:
    if not rows:
        return f'<p style="color:#6e7781;font-style:italic">{L("Sin datos de evidencia.", "No evidence data.")}</p>'
    headers = list(rows[0].keys())
    th = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(
            f'<td style="max-width:420px;word-break:break-all">{_safe(row.get(h, ""))}</td>'
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


def _finding_card(f: Finding) -> str:
    color = SEVERITY_COLOR[f.severity]
    bg = SEVERITY_BG[f.severity]

    if f.error:
        body = (f'<p style="color:{SEVERITY_COLOR[Severity.CRITICAL]}">⚠ '
                f'{L("La comprobación falló:", "Check failed to run:")} {f.error}</p>')
    elif f.passed:
        body = f'<p style="color:#1a7f37">✓ {L("Sin incidencias.", "No issues found.")}</p>'
    else:
        evidence_html = _evidence_table(f.evidence)
        ref_html = (
            f'<p style="margin-top:12px;font-size:12px;color:#6e7781">'
            f'{L("Referencia", "Reference")}: '
            f'<a href="{f.reference}" target="_blank">{f.reference}</a></p>'
            if f.reference else ""
        )
        body = f"""
        <p style="color:#1f2328;margin-bottom:12px">{BT(f.description)}</p>
        {evidence_html}
        <div style="margin-top:16px;padding:12px;background:#eaf6ee;
                    border-left:3px solid #1a7f37;border-radius:4px">
          <span style="color:#1a7f37;font-weight:700;font-size:12px">{L("RECOMENDACIÓN", "RECOMMENDATION")}</span>
          <p style="color:#1f2328;margin:6px 0 0">{BT(f.recommendation)}</p>
        </div>
        {ref_html}
        """

    return f"""
    <div style="border:1px solid {color}44;border-left:4px solid {color};border-radius:8px;
                margin-bottom:20px;background:{bg};overflow:hidden">
      <div style="padding:14px 20px;border-bottom:1px solid {color}22;
                  display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span style="font-family:monospace;color:{color};font-weight:700;font-size:13px">{f.id}</span>
        {_severity_badge(f.severity)}
        <span style="color:#1f2328;font-weight:600;font-size:15px">{BT(f.title)}</span>
      </div>
      <div style="padding:16px 20px">{body}</div>
    </div>"""


def _section(severity: Severity, findings: list[Finding]) -> str:
    relevant = [f for f in findings if f.severity == severity]
    if not relevant:
        return ""
    color = SEVERITY_COLOR[severity]
    es, en = SEVERITY_NAME[severity]
    cards = "".join(_finding_card(f) for f in relevant)
    return f"""
    <section style="margin-bottom:40px">
      <h2 style="color:{color};border-bottom:2px solid {color};
                 padding-bottom:8px;font-size:18px;letter-spacing:1px">
        {L(es, en)} ({len(relevant)})
      </h2>
      {cards}
    </section>"""


_MIME = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif", ".svg": "svg+xml"}


def _logo_data_uri() -> str | None:
    """
    Base64-embed the first image found in assets/ (prefers a file named 'logo',
    otherwise any supported image) so the report stays self-contained.
    """
    base = Path(__file__).resolve().parent.parent / "assets"
    if not base.is_dir():
        return None
    images = [p for p in base.iterdir() if p.suffix.lower() in _MIME]
    if not images:
        return None
    # Prefer a file called logo.* if present, else the first image.
    images.sort(key=lambda p: (0 if p.stem.lower() == "logo" else 1, p.name.lower()))
    chosen = images[0]
    data = base64.b64encode(chosen.read_bytes()).decode()
    return f"data:image/{_MIME[chosen.suffix.lower()]};base64,{data}"


CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #f4f6f8;
  color: #1f2328;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}
a { color: #0969da; text-decoration: none; }
a:hover { text-decoration: underline; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  background: #fff;
}
th {
  background: #f0f3f6;
  color: #57606a;
  text-align: left;
  padding: 8px 12px;
  border: 1px solid #d0d7de;
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 0.5px;
}
td {
  padding: 8px 12px;
  border: 1px solid #d8dee4;
  color: #1f2328;
  vertical-align: top;
}
tr:nth-child(even) td { background: #f6f8fa; }
.container {
  max-width: 1100px; margin: 24px auto;
  background: #fff; border: 1px solid #d0d7de; border-radius: 12px;
  padding: 40px 44px;
  box-shadow: 0 1px 3px rgba(27,31,36,0.06);
}
.score-ring {
  width: 96px; height: 96px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  border: 5px solid; font-size: 30px; font-weight: 800;
}
.logo { max-height: 68px; max-width: 220px; }
.lang-btn {
  position: fixed; top: 16px; right: 16px; z-index: 100;
  background: #1f3a68; color: #fff; border: none; border-radius: 6px;
  padding: 8px 14px; font-size: 12px; font-weight: 700; cursor: pointer;
  letter-spacing: 1px; box-shadow: 0 1px 4px rgba(0,0,0,0.2);
}
.lang-btn:hover { background: #16294a; }

/* Bilingual toggle: default shows Spanish, hides English */
.t-en { display: none; }
.b-en { display: none; }
html.lang-en .t-es { display: none; }
html.lang-en .t-en { display: inline; }
html.lang-en .b-es { display: none; }
html.lang-en .b-en { display: inline; }

@media print {
  .lang-btn { display: none; }
  body { background: #fff; }
  .container { border: none; box-shadow: none; margin: 0; }
}
"""

TOGGLE_JS = """
function toggleLang(){
  var h = document.documentElement;
  h.classList.toggle('lang-en');
  var en = h.classList.contains('lang-en');
  document.getElementById('langBtn').textContent = en ? 'ES | EN' : 'ES | EN';
  h.setAttribute('lang', en ? 'en' : 'es');
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

    counts = score["counts"]
    badge_color = score["badge_color"]
    risk_es, risk_en = RISK_LABEL.get(score["label"], (score["label"], score["label"]))

    summary_cells = "".join(
        f'<td style="text-align:center;padding:12px 22px">'
        f'<div style="font-size:30px;font-weight:800;color:{SEVERITY_COLOR[Severity[k]]}">{v}</div>'
        f'<div style="font-size:11px;color:#57606a;letter-spacing:1px">'
        f'{L(*SEVERITY_NAME[Severity[k]])}</div></td>'
        for k, v in counts.items()
    )

    body_sections = "".join(
        _section(sev, findings)
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO]
    )

    logo_uri = _logo_data_uri()
    logo_html = (
        f'<img src="{logo_uri}" class="logo" alt="Servicios Generales de la Plana">'
        if logo_uri else
        '<div style="font-size:26px;font-weight:800;color:#1f3a68;letter-spacing:1px">SGP</div>'
    )

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Informe de Riesgo IAM / IAM Risk Report — {tenant_name}</title>
  <style>{CSS}</style>
</head>
<body>
<button id="langBtn" class="lang-btn" onclick="toggleLang()">ES | EN</button>
<div class="container">

  <!-- Header -->
  <div style="border-bottom:1px solid #d0d7de;padding-bottom:28px;margin-bottom:32px">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:20px">
      <div style="font-size:11px;color:#57606a;letter-spacing:2px;text-transform:uppercase">
        IAM Risk Analyzer
      </div>
      <div style="text-align:right">{logo_html}</div>
    </div>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:20px">
      <div>
        <h1 style="font-size:27px;font-weight:800;color:#1f2328">{tenant_name}</h1>
        <p style="color:#57606a;margin-top:4px;font-family:monospace;font-size:12px">{tenant_id}</p>
        <div style="margin-top:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px">
          <div><span style="color:#57606a">{L("Fecha", "Date")}:</span> <span>{run_date}</span></div>
          <div><span style="color:#57606a">{L("Duración", "Duration")}:</span> <span>{elapsed}s</span></div>
          <div><span style="color:#57606a">{L("Método de auth", "Auth method")}:</span> <span>{auth_method}</span></div>
        </div>
      </div>
      <div style="text-align:center">
        <div class="score-ring" style="border-color:{badge_color};color:{badge_color}">
          {score["value"]}
        </div>
        <div style="margin-top:8px;font-weight:700;color:{badge_color};letter-spacing:1px;font-size:13px">
          {L("RIESGO " + risk_es, risk_en + " RISK")}
        </div>
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <section style="margin-bottom:40px">
    <h2 style="color:#1f2328;font-size:18px;margin-bottom:16px">{L("Resumen Ejecutivo", "Executive Summary")}</h2>
    <table style="width:auto">
      <thead><tr>
        <th>{L(*SEVERITY_NAME[Severity.CRITICAL])}</th>
        <th>{L(*SEVERITY_NAME[Severity.HIGH])}</th>
        <th>{L(*SEVERITY_NAME[Severity.MEDIUM])}</th>
        <th>{L(*SEVERITY_NAME[Severity.INFO])}</th>
      </tr></thead>
      <tbody><tr>{summary_cells}</tr></tbody>
    </table>
  </section>

  <!-- Findings -->
  {body_sections}

  <!-- Footer -->
  <footer style="border-top:1px solid #d0d7de;padding-top:20px;margin-top:40px;
                 color:#57606a;font-size:12px;line-height:1.8;text-align:center">
    <p style="font-weight:700;color:#1f3a68;font-size:13px;letter-spacing:0.5px">
      Seguridad de la Información · Departamento de IT
    </p>
    <p style="margin-top:6px">{L(
      "Informe generado por IAM Risk Analyzer para fines de evaluación de seguridad autorizada. "
      "Valide todos los hallazgos antes de aplicar cambios.",
      "Report generated by IAM Risk Analyzer for authorized security assessment purposes. "
      "Validate all findings before remediation.")}</p>
  </footer>

</div>
<script>{TOGGLE_JS}</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
