"""
report/pdf_generator.py
Generates a sectioned, data-driven audit report as a PDF (reportlab).

Layout: cover page (logo + score) -> table of contents -> nine sections
(executive summary, methodology, scope, limitations, tool description,
findings, recommendations, mitigations, conclusions). A logo header and an
"Seguridad de la Información · Departamento de IT" footer appear on every page.

Text is taken from each Finding's Spanish ('es') side of its bilingual fields.
"""

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from utils.finding import Severity

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#1F3A68")
MUTED = colors.HexColor("#57606A")
LINE = colors.HexColor("#D0D7DE")
SEV_COLOR = {
    Severity.CRITICAL: colors.HexColor("#C1121F"),
    Severity.HIGH:     colors.HexColor("#BC4C00"),
    Severity.MEDIUM:   colors.HexColor("#9A6700"),
    Severity.INFO:     colors.HexColor("#0969DA"),
}
SEV_ES = {
    Severity.CRITICAL: "CRÍTICO",
    Severity.HIGH:     "ALTO",
    Severity.MEDIUM:   "MEDIO",
    Severity.INFO:     "INFORMATIVO",
}
_MIME = {".jpg", ".jpeg", ".png", ".gif"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _logo_path():
    base = Path(__file__).resolve().parent.parent / "assets"
    if not base.is_dir():
        return None
    imgs = [p for p in base.iterdir() if p.suffix.lower() in _MIME]
    if not imgs:
        return None
    imgs.sort(key=lambda p: (0 if p.stem.lower() == "logo" else 1, p.name.lower()))
    return imgs[0]


def _es(field) -> str:
    """Extract the Spanish text from a bilingual dict, or the string itself."""
    if isinstance(field, dict):
        return field.get("es", "")
    return str(field or "")


def _clean(s) -> str:
    """Make text safe for reportlab: cp1252-encodable + XML-escaped."""
    text = str(s) if s is not None else "—"
    text = text.encode("cp1252", "replace").decode("cp1252")
    return escape(text)


def _hex(color) -> str:
    """reportlab Color -> '#rrggbb' for <font color> markup."""
    return "#" + color.hexval()[2:]


def _short(val, limit: int = 90) -> str:
    if isinstance(val, list):
        val = ", ".join(str(x) for x in val)
    elif isinstance(val, dict):
        val = "; ".join(f"{k}: {v}" for k, v in val.items())
    s = str(val)
    return s if len(s) <= limit else s[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], textColor=NAVY,
                          fontSize=22, leading=27, alignment=TA_CENTER))
    ss.add(ParagraphStyle("CoverSub", parent=ss["Title"], textColor=NAVY,
                          fontSize=15, leading=18, alignment=TA_CENTER, spaceBefore=2))
    ss.add(ParagraphStyle("Kicker", parent=ss["Normal"], textColor=MUTED,
                          fontSize=8.5, leading=12, alignment=TA_CENTER))
    ss.add(ParagraphStyle("ScoreNum", parent=ss["Normal"], fontSize=30, leading=34,
                          alignment=TA_CENTER))
    ss.add(ParagraphStyle("ScoreLbl", parent=ss["Normal"], fontSize=10, leading=13,
                          alignment=TA_CENTER))
    ss.add(ParagraphStyle("Section", parent=ss["Heading1"], textColor=NAVY,
                          fontSize=14, leading=17, spaceBefore=16, spaceAfter=6,
                          borderWidth=0, borderColor=NAVY))
    ss.add(ParagraphStyle("SectionNoTOC", parent=ss["Heading1"], textColor=NAVY,
                          fontSize=14, leading=17, spaceBefore=8, spaceAfter=6))
    ss.add(ParagraphStyle("SubHead", parent=ss["Heading2"], textColor=colors.HexColor("#1F2328"),
                          fontSize=11.5, leading=14, spaceBefore=8, spaceAfter=2))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=10, leading=14,
                          alignment=TA_JUSTIFY, spaceAfter=6))
    ss.add(ParagraphStyle("BulletItem", parent=ss["Normal"], fontSize=10, leading=14,
                          leftIndent=12, bulletIndent=2, spaceAfter=3))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8.5, leading=11))
    ss.add(ParagraphStyle("CellH", parent=ss["Normal"], fontSize=8, leading=10,
                          textColor=MUTED, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("Meta", parent=ss["Normal"], fontSize=9.5, leading=14))
    return ss


# ---------------------------------------------------------------------------
# Document template (header/footer + TOC hooks)
# ---------------------------------------------------------------------------
class _AuditDoc(BaseDocTemplate):
    def __init__(self, filename, **kw):
        super().__init__(filename, pagesize=A4,
                         leftMargin=2*cm, rightMargin=2*cm,
                         topMargin=3*cm, bottomMargin=2.2*cm, **kw)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=self._decorate)])
        self._logo = _logo_path()

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "Section":
            self.notify("TOCEntry", (0, flowable.getPlainText(), self.page))

    def _decorate(self, canvas, doc):
        w, h = A4
        # Header: logo top-right + rule
        if self._logo:
            try:
                canvas.drawImage(str(self._logo), w - doc.rightMargin - 3.0*cm, h - 2.35*cm,
                                 width=3.0*cm, height=1.5*cm, preserveAspectRatio=True,
                                 anchor="ne", mask="auto")
            except Exception:
                pass
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.6)
        canvas.line(doc.leftMargin, h - 2.5*cm, w - doc.rightMargin, h - 2.5*cm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, h - 2.4*cm, "IAM Risk Analyzer · Informe de auditoría")

        # Footer
        canvas.setStrokeColor(LINE)
        canvas.line(doc.leftMargin, doc.bottomMargin - 0.4*cm, w - doc.rightMargin, doc.bottomMargin - 0.4*cm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(NAVY)
        canvas.drawCentredString(w/2, doc.bottomMargin - 0.9*cm,
                                 "Seguridad de la Información · Departamento de IT")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawCentredString(w/2, doc.bottomMargin - 1.25*cm,
                                 "Servicios Generales de la Plana — Documento confidencial de uso interno")
        canvas.drawRightString(w - doc.rightMargin, doc.bottomMargin - 1.25*cm, f"Página {doc.page}")


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
STATIC = {
    "metodologia": [
        "La evaluación se basa en la consulta programática de la Microsoft Graph API mediante una "
        "aplicación registrada con permisos de aplicación de solo lectura y consentimiento de "
        "administrador. El procedimiento fue: (1) autenticación app-only mediante MSAL; (2) "
        "recolección paginada de usuarios, asignaciones de roles, grupos, aplicaciones, service "
        "principals y políticas; (3) evaluación frente a 16 controles en cuatro niveles de severidad, "
        "alineados con las buenas prácticas de Microsoft, el CIS Microsoft 365 Benchmark y MITRE "
        "ATT&amp;CK; (4) cálculo de una puntuación de riesgo agregada (0–100) ponderada por severidad; "
        "(5) generación de informes. Todas las operaciones son de lectura; no se modifica el tenant.",
    ],
    "alcance": [
        "El alcance comprende el plano de identidad y acceso del tenant de Entra ID indicado: "
        "administradores globales y asignaciones de roles; estado de MFA de cuentas privilegiadas y "
        "no privilegiadas; políticas de contraseña de cuentas con privilegios; usuarios invitados con "
        "roles; permisos de Graph y credenciales de service principals; registros de aplicaciones y "
        "URIs de redirección; propiedad de grupos; y políticas de Acceso Condicional.",
        "Fuera de alcance: seguridad de endpoints, red, cargas de trabajo de Azure, contenido de "
        "Exchange/SharePoint y cualquier sistema fuera de Entra ID.",
    ],
    "herramienta": [
        "IAM Risk Analyzer es una utilidad de línea de comandos en Python 3 que evalúa la postura de "
        "seguridad IAM de Microsoft Entra ID y genera informes. Soporta autenticación por client "
        "secret, certificado (PFX/PEM) y device code (MSAL); ejecuta 16 comprobaciones agrupadas por "
        "severidad; opera en modo solo lectura; y produce un informe HTML autocontenido (con selector "
        "de idioma Español/Inglés) y este informe PDF de auditoría.",
        "Permisos de Graph requeridos (aplicación, con consentimiento de administrador): "
        "User.Read.All, Group.Read.All, Directory.Read.All, RoleManagement.Read.Directory, "
        "Policy.Read.All, Application.Read.All, AuditLog.Read.All y UserAuthenticationMethod.Read.All. "
        "Repositorio: https://github.com/mr7security/iam-risk-analyzer",
    ],
}


def _para(text, style):
    return Paragraph(_clean(text) if not isinstance(text, str) else text, style)


def _bullets(items, ss):
    return [Paragraph(f"• {it}", ss["BulletItem"]) for it in items]


def _severity_tag(sev, ss):
    c = SEV_COLOR[sev]
    return Paragraph(
        f'<font color="{_hex(c)}"><b>{SEV_ES[sev]}</b></font>', ss["Cell"]
    )


def _evidence_table(finding, ss):
    rows = finding.evidence or []
    if not rows:
        return []
    headers = list(rows[0].keys())
    max_rows = 8
    data = [[Paragraph(_clean(h), ss["CellH"]) for h in headers]]
    for row in rows[:max_rows]:
        data.append([Paragraph(_clean(_short(row.get(h, ""))), ss["Cell"]) for h in headers])
    n_cols = len(headers)
    avail = 17 * cm
    col_w = [avail / n_cols] * n_cols
    t = Table(data, colWidths=col_w, repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0F3F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    out = [Spacer(1, 3), t]
    if len(rows) > max_rows:
        out.append(Paragraph(
            f"<i>… y {len(rows) - max_rows} fila(s) más. Ver el informe HTML para el detalle completo.</i>",
            ss["Cell"]))
    return out


def _finding_block(finding, ss):
    sev = finding.severity
    c = _hex(SEV_COLOR[sev])
    flow = []
    head = f'<font color="{c}"><b>{_clean(finding.id)} · {SEV_ES[sev]}</b></font> — {_clean(_es(finding.title))}'
    flow.append(Paragraph(head, ss["SubHead"]))
    if finding.error:
        flow.append(Paragraph(f"<i>La comprobación no pudo ejecutarse: {_clean(finding.error)}</i>", ss["Body"]))
        return flow
    if finding.passed:
        flow.append(Paragraph("Sin incidencia.", ss["Body"]))
        return flow
    flow.append(Paragraph(_clean(_es(finding.description)), ss["Body"]))
    flow.extend(_evidence_table(finding, ss))
    rec = _es(finding.recommendation)
    if rec:
        flow.append(Paragraph(f"<b>Recomendación:</b> {_clean(rec)}", ss["Body"]))
    flow.append(Spacer(1, 6))
    return flow


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def generate_pdf(
    output_path: str,
    findings: list,
    score: dict,
    tenant_info: dict,
    tenant_id: str,
    auth_method: str,
    run_start: datetime,
    run_end: datetime,
) -> None:
    ss = _styles()
    tenant_name = tenant_info.get("displayName", "Unknown")
    run_date = run_start.strftime("%d/%m/%Y %H:%M UTC")
    counts = score["counts"]
    badge = colors.HexColor(score["badge_color"])

    issues = [f for f in findings if not f.passed and not f.error]
    by_sev = {s: [f for f in issues if f.severity == s] for s in Severity}

    story = []

    # ---------------- Cover ----------------
    story.append(Paragraph("INFORME DE AUDITORÍA DE SEGURIDAD", ss["Kicker"]))
    story.append(Paragraph("Auditoría de Identidades y Accesos (IAM)", ss["CoverTitle"]))
    story.append(Paragraph("Microsoft Entra ID", ss["CoverSub"]))
    story.append(Spacer(1, 26))

    badge_hex = _hex(badge)
    # Square score badge (number only) + label below, both centred.
    score_box = Table(
        [[Paragraph(f'<font size="30" color="{badge_hex}"><b>{score["value"]}</b></font>', ss["ScoreNum"])]],
        colWidths=[3.4*cm], rowHeights=[3.4*cm])
    score_box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 2, badge),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    score_box.hAlign = "CENTER"
    story.append(score_box)
    story.append(Spacer(1, 5))
    story.append(Paragraph(f'<font color="{badge_hex}"><b>RIESGO {_clean(score["label"])}</b></font>',
                           ss["ScoreLbl"]))
    story.append(Spacer(1, 26))

    meta = [
        ["Organización:", tenant_name],
        ["Tenant ID:", tenant_id],
        ["Dominio:", ", ".join(tenant_info.get("verifiedDomains", []) or ["—"])],
        ["Fecha de ejecución:", run_date],
        ["Método de autenticación:", auth_method],
        ["Herramienta:", "IAM Risk Analyzer v0.1.0"],
        ["Clasificación:", "Confidencial — Uso interno"],
    ]
    meta_tbl = Table([[Paragraph(f"<b>{_clean(k)}</b>", ss["Meta"]), Paragraph(_clean(v), ss["Meta"])]
                      for k, v in meta], colWidths=[4.8*cm, 9*cm])
    meta_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 2),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                                  ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE)]))
    meta_tbl.hAlign = "CENTER"
    story.append(meta_tbl)
    story.append(PageBreak())

    # ---------------- TOC ----------------
    story.append(Paragraph("Índice", ss["SectionNoTOC"]))
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("TOC0", fontSize=10.5, leading=18, leftIndent=6)]
    story.append(toc)
    story.append(PageBreak())

    # ---------------- 1. Resumen ejecutivo ----------------
    story.append(Paragraph("1. Resumen ejecutivo", ss["Section"]))
    story.append(Paragraph(
        f"Se ha evaluado la postura de seguridad de identidades y accesos (IAM) del tenant de "
        f"Microsoft Entra ID de <b>{_clean(tenant_name)}</b>. La herramienta ejecutó 16 "
        f"comprobaciones automatizadas de solo lectura. El resultado global es una puntuación de "
        f"riesgo de <b>{score['value']}/100 ({_clean(score['label'])})</b>.", ss["Body"]))
    summ = [[Paragraph("<b>Severidad</b>", ss["CellH"]), Paragraph("<b>Incidencias</b>", ss["CellH"])]]
    for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO]:
        summ.append([_severity_tag(s, ss), Paragraph(str(counts.get(s.value, 0)), ss["Cell"])])
    st = Table(summ, colWidths=[5*cm, 4*cm])
    st.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0F3F6")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(st)

    # ---------------- 2. Metodología ----------------
    story.append(Paragraph("2. Metodología", ss["Section"]))
    for p in STATIC["metodologia"]:
        story.append(Paragraph(p, ss["Body"]))

    # ---------------- 3. Alcance ----------------
    story.append(Paragraph("3. Alcance", ss["Section"]))
    for p in STATIC["alcance"]:
        story.append(Paragraph(p, ss["Body"]))

    # ---------------- 4. Limitaciones ----------------
    story.append(Paragraph("4. Limitaciones", ss["Section"]))
    lims = []
    if any("P1/P2" in _es(f.description) or "premium" in _es(f.description).lower() for f in findings):
        lims.append("Licenciamiento (Entra ID Free): sin licencia P1/P2 no está disponible la última "
                    "actividad de inicio de sesión, por lo que las comprobaciones de cuentas inactivas "
                    "(HI-02, IN-03) no se pudieron ejecutar.")
    lims.append("Limitación temporal de la API (throttling): las lecturas masivas de métodos de "
                "autenticación por usuario pueden verse limitadas por Microsoft Graph (HTTP 429), lo "
                "que puede afectar a la exactitud de ME-01 en ejecuciones sobre tenants grandes.")
    lims.append("Muestreo: la comprobación ME-01 evalúa una muestra de los primeros 500 usuarios no "
                "privilegiados para acotar el volumen de llamadas.")
    lims.append("Momento puntual: los resultados reflejan el estado del directorio en la fecha y hora "
                "de ejecución.")
    for b in _bullets(lims, ss):
        story.append(b)

    # ---------------- 5. Descripción de la herramienta ----------------
    story.append(Paragraph("5. Descripción de la herramienta", ss["Section"]))
    for p in STATIC["herramienta"]:
        story.append(Paragraph(p, ss["Body"]))

    # ---------------- 6. Hallazgos ----------------
    story.append(Paragraph("6. Hallazgos", ss["Section"]))
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO]
    any_issue = False
    for s in order:
        sev_findings = [f for f in findings if f.severity == s and not f.passed and not f.error]
        for f in sev_findings:
            any_issue = True
            for fl in _finding_block(f, ss):
                story.append(fl)
    if not any_issue:
        story.append(Paragraph("No se detectaron incidencias.", ss["Body"]))
    # Informational + passed summary
    infos = [f for f in findings if f.severity == Severity.INFO]
    if infos:
        story.append(Paragraph("Hallazgos informativos", ss["SubHead"]))
        for f in infos:
            story.append(Paragraph(f"<b>{_clean(f.id)}:</b> {_clean(_es(f.title))}", ss["Body"]))
    passed = [f for f in findings if f.passed or f.error]
    if passed:
        story.append(Paragraph("Comprobaciones sin incidencia o no evaluables", ss["SubHead"]))
        ids = ", ".join(f.id for f in passed)
        story.append(Paragraph(_clean(ids), ss["Body"]))

    # ---------------- 7. Recomendaciones ----------------
    story.append(Paragraph("7. Recomendaciones", ss["Section"]))
    rec_rows = [[Paragraph("<b>ID</b>", ss["CellH"]), Paragraph("<b>Sev.</b>", ss["CellH"]),
                 Paragraph("<b>Recomendación</b>", ss["CellH"])]]
    for s in order:
        for f in [x for x in issues if x.severity == s]:
            rec = _es(f.recommendation)
            if rec:
                rec_rows.append([Paragraph(_clean(f.id), ss["Cell"]), _severity_tag(s, ss),
                                 Paragraph(_clean(rec), ss["Cell"])])
    if len(rec_rows) > 1:
        rt = Table(rec_rows, colWidths=[1.8*cm, 2.4*cm, 12.8*cm], repeatRows=1)
        rt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0F3F6")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        story.append(rt)
    else:
        story.append(Paragraph("Sin recomendaciones: no se detectaron incidencias.", ss["Body"]))

    # ---------------- 8. Mitigaciones ----------------
    story.append(Paragraph("8. Mitigaciones", ss["Section"]))
    story.append(Paragraph("Plan de mitigación escalonado en función de la severidad de los hallazgos:", ss["Body"]))
    stages = [
        ("Inmediato (0–7 días)", by_sev[Severity.CRITICAL]),
        ("Corto plazo (1–4 semanas)", by_sev[Severity.HIGH]),
        ("Medio plazo (1–3 meses)", by_sev[Severity.MEDIUM]),
    ]
    for label, fs in stages:
        ids = ", ".join(f.id for f in fs) if fs else "sin acciones pendientes"
        story.append(Paragraph(f"<b>{label}:</b> abordar {ids}.", ss["BulletItem"]))
    story.append(Paragraph("<b>Estratégico:</b> evaluar la adopción de Entra ID P1/P2 para habilitar "
                           "Acceso Condicional, revisiones de acceso y detección de cuentas inactivas.",
                           ss["BulletItem"]))

    # ---------------- 9. Conclusiones ----------------
    story.append(Paragraph("9. Conclusiones", ss["Section"]))
    n_crit = len(by_sev[Severity.CRITICAL])
    n_high = len(by_sev[Severity.HIGH])
    crit_titles = "; ".join(_es(f.title) for f in by_sev[Severity.CRITICAL]) or "ninguno"
    story.append(Paragraph(
        f"El tenant presenta una puntuación de riesgo de <b>{score['value']}/100 "
        f"({_clean(score['label'])})</b>, con <b>{n_crit}</b> hallazgo(s) crítico(s) y "
        f"<b>{n_high}</b> de severidad alta. Los puntos críticos identificados son: "
        f"{_clean(crit_titles)}.", ss["Body"]))
    story.append(Paragraph(
        "Se recomienda priorizar las acciones inmediatas indicadas en la sección de mitigaciones y "
        "repetir esta auditoría tras aplicarlas para verificar la reducción efectiva del riesgo.",
        ss["Body"]))

    _AuditDoc(output_path).multiBuild(story)
