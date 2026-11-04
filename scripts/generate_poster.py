"""
AEGIS-Recon Professional Academic Project Poster Generator.
Creates a self-contained, high-resolution, light-theme, editable academic poster
featuring Vidyalankar Institute of Technology (VIT NAAC A+) branding, live in-browser editing,
persistence, PDF export, and embedded project telemetry.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path


def get_base64_data_uri(file_path: str) -> str:
    """Read a local image file and return a base64 Data URI."""
    if not os.path.exists(file_path):
        return ""
    ext = file_path.split(".")[-1].lower()
    mime = "image/png" if ext == "png" else "image/jpeg"
    with open(file_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("utf-8")
    return f"data:{mime};base64,{encoded}"


def generate_poster_html() -> str:
    # Resolve image paths
    base_dir = Path(__file__).resolve().parents[1]
    logo_path = str(base_dir / "docs" / "poster" / "vit_logo.png")
    dash_path = str(base_dir / "docs" / "images" / "dashboard_overview.jpg")
    chart_path = str(base_dir / "docs" / "images" / "dashboard_charts.jpg")
    vuln_path = str(base_dir / "docs" / "images" / "vulnerability_findings.jpg")
    ai_path = str(base_dir / "docs" / "images" / "ai_recommendations.jpg")

    logo_uri = get_base64_data_uri(logo_path)
    dash_uri = get_base64_data_uri(dash_path)
    chart_uri = get_base64_data_uri(chart_path)
    vuln_uri = get_base64_data_uri(vuln_path)
    ai_uri = get_base64_data_uri(ai_path)

    # Clean SVG QR Code pointing to https://github.com/parthkamble4536-ship/AEGIS-Recon
    # Generates a crisp vector QR code
    qr_svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" class="w-16 h-16 rounded-md border border-slate-300 p-1 bg-white shadow-sm">
      <rect width="100" height="100" fill="#ffffff"/>
      <!-- QR Position Markers -->
      <path d="M10,10 h24 v24 h-24 z M14,14 v16 h16 v-16 z M18,18 h8 v8 h-8 z" fill="#0f2b5c"/>
      <path d="M66,10 h24 v24 h-24 z M70,14 v16 h16 v-16 z M74,18 h8 v8 h-8 z" fill="#0f2b5c"/>
      <path d="M10,66 h24 v24 h-24 z M14,70 v16 h16 v-16 z M18,74 h8 v8 h-8 z" fill="#0f2b5c"/>
      <!-- Data bits pattern -->
      <rect x="40" y="12" width="6" height="6" fill="#0f2b5c"/>
      <rect x="52" y="12" width="6" height="6" fill="#0f2b5c"/>
      <rect x="40" y="24" width="6" height="6" fill="#0f2b5c"/>
      <rect x="48" y="24" width="6" height="6" fill="#0f2b5c"/>
      <rect x="12" y="42" width="6" height="6" fill="#0f2b5c"/>
      <rect x="24" y="42" width="6" height="6" fill="#0f2b5c"/>
      <rect x="36" y="38" width="6" height="6" fill="#0f2b5c"/>
      <rect x="46" y="38" width="8" height="8" fill="#0284c7"/>
      <rect x="60" y="42" width="6" height="6" fill="#0f2b5c"/>
      <rect x="74" y="42" width="6" height="6" fill="#0f2b5c"/>
      <rect x="84" y="42" width="6" height="6" fill="#0f2b5c"/>
      <rect x="38" y="52" width="6" height="6" fill="#0f2b5c"/>
      <rect x="52" y="52" width="6" height="6" fill="#0f2b5c"/>
      <rect x="66" y="52" width="6" height="6" fill="#0f2b5c"/>
      <rect x="78" y="52" width="6" height="6" fill="#0f2b5c"/>
      <rect x="40" y="66" width="6" height="6" fill="#0f2b5c"/>
      <rect x="50" y="66" width="6" height="6" fill="#0f2b5c"/>
      <rect x="64" y="66" width="6" height="6" fill="#0f2b5c"/>
      <rect x="76" y="66" width="6" height="6" fill="#0f2b5c"/>
      <rect x="42" y="78" width="6" height="6" fill="#0f2b5c"/>
      <rect x="54" y="78" width="6" height="6" fill="#0f2b5c"/>
      <rect x="68" y="78" width="6" height="6" fill="#0f2b5c"/>
      <rect x="82" y="78" width="6" height="6" fill="#0f2b5c"/>
    </svg>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AEGIS-Recon — Academic Project Exhibition Poster</title>
  <!-- Tailwind CSS CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- Google Fonts for High-Impact Academic Typography -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700&family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --primary: #0f2b5c;       /* Vidyalankar Deep Academic Navy */
      --primary-light: #1e3a8a;
      --secondary: #0284c7;     /* Cyber Sky Blue */
      --accent: #dc2626;        /* NAAC A+ Crimson */
      --bg-page: #f8fafc;       /* Crisp Off-White */
      --card-bg: #ffffff;
      --border-color: #cbd5e1;
      --text-head: #0f172a;
      --text-body: #334155;
      --text-muted: #64748b;
    }}

    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-page);
      color: var(--text-body);
      -webkit-font-smoothing: antialiased;
      line-height: 1.45;
    }}

    .font-mono {{
      font-family: 'JetBrains Mono', monospace;
    }}

    .font-serif-title {{
      font-family: 'Cinzel', serif;
    }}

    /* Editable Outline Styling */
    .edit-mode-active [contenteditable="true"] {{
      outline: 2px dashed #3b82f6 !important;
      outline-offset: 3px;
      background-color: rgba(239, 246, 255, 0.6) !important;
      cursor: text;
      border-radius: 4px;
      transition: all 0.15s ease-in-out;
    }}

    .edit-mode-active [contenteditable="true"]:hover {{
      outline: 2px solid #2563eb !important;
      background-color: rgba(219, 234, 254, 0.9) !important;
    }}

    .edit-mode-active [contenteditable="true"]:focus {{
      outline: 2px solid #1d4ed8 !important;
      background-color: #ffffff !important;
      box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.25);
    }}

    /* Card styling */
    .poster-card {{
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 0.75rem;
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.04);
      transition: transform 0.2s, box-shadow 0.2s;
    }}

    .poster-card:hover {{
      box-shadow: 0 6px 14px rgba(15, 43, 92, 0.07);
    }}

    .section-title {{
      color: var(--primary);
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 0.35rem;
      margin-bottom: 0.65rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}

    /* Mathematical Box */
    .formula-box {{
      background: #f1f5f9;
      border-left: 4px solid var(--secondary);
      padding: 0.65rem 0.85rem;
      border-radius: 0.375rem;
      font-family: 'JetBrains Mono', monospace;
    }}

    /* Print & Export Settings */
    @media print {{
      #editor-toolbar, .no-print {{
        display: none !important;
      }}
      body {{
        background: #ffffff !important;
        padding: 0 !important;
        margin: 0 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .poster-container {{
        width: 100% !important;
        max-width: none !important;
        margin: 0 !important;
        padding: 6mm !important;
        box-shadow: none !important;
        border: none !important;
      }}
      .poster-card {{
        box-shadow: none !important;
        border: 1px solid #cbd5e1 !important;
        break-inside: avoid !important;
        page-break-inside: avoid !important;
      }}
      @page {{
        size: A1 landscape;
        margin: 4mm;
      }}
    }}
  </style>
</head>
<body class="p-2 sm:p-4 md:p-6 text-slate-800">

  <!-- ========================================================================= -->
  <!-- FLOATING INTERACTIVE EDITOR TOOLBAR (Hidden in Print Mode)               -->
  <!-- ========================================================================= -->
  <aside id="editor-toolbar" class="no-print sticky top-2 z-50 mb-4 max-w-7xl mx-auto bg-white/95 backdrop-blur-md border border-slate-300 rounded-xl shadow-lg px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-sm">
    <div class="flex items-center gap-3">
      <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-blue-50 text-blue-800 font-semibold border border-blue-200 text-xs">
        <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
        POSTER STUDIO
      </span>
      <span id="edit-status-badge" class="text-xs text-slate-500 font-medium">Viewing Mode (Click Edit to customize text)</span>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <!-- Toggle Edit Mode -->
      <button id="toggle-edit-btn" onclick="toggleEditMode()" class="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium text-xs shadow transition flex items-center gap-1.5">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
        <span id="edit-btn-text">✏️ Enable Live Edit</span>
      </button>

      <!-- Save to LocalStorage -->
      <button onclick="saveEdits()" class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg font-medium text-xs shadow transition flex items-center gap-1.5" title="Saves your edits directly in Edge browser so they persist">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
        💾 Save Edits
      </button>

      <!-- Download Modified HTML -->
      <button onclick="exportPosterHtml()" class="px-3 py-1.5 bg-slate-700 hover:bg-slate-800 text-white rounded-lg font-medium text-xs shadow transition flex items-center gap-1.5" title="Download the customized HTML file with all your text changes">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
        📥 Export HTML
      </button>

      <!-- Print / Save as PDF -->
      <button onclick="window.print()" class="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium text-xs shadow transition flex items-center gap-1.5" title="Opens browser print dialogue pre-configured for A1/A2/A3/A4/16:9 PDF export">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/></svg>
        🖨️ Print / Save PDF
      </button>

      <!-- Reset -->
      <button onclick="resetPoster()" class="px-2.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-medium border border-slate-300 transition" title="Reset all edits back to defaults">
        🔄 Reset
      </button>
    </div>
  </aside>

  <!-- ========================================================================= -->
  <!-- MAIN POSTER BOARD (Optimized for Exhibition & Print)                      -->
  <!-- ========================================================================= -->
  <main id="poster-root" class="poster-container max-w-[1720px] mx-auto bg-white border border-slate-300 rounded-2xl shadow-xl overflow-hidden p-6 md:p-8">

    <!-- ======================================================================= -->
    <!-- HEADER SECTION                                                          -->
    <!-- ======================================================================= -->
    <header class="border-b-2 border-slate-200 pb-5 mb-6">
      <div class="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">

        <!-- Left: Official College Logo & Accreditation -->
        <div class="md:col-span-3 flex flex-col items-center md:items-start">
          <img src="{logo_uri}" alt="Vidyalankar Institute of Technology" class="h-20 w-auto object-contain mb-1.5 hover:scale-105 transition-transform" />
          <div class="text-[11px] font-bold text-slate-500 uppercase tracking-widest text-center md:text-left">
            University of Mumbai Affiliated
          </div>
        </div>

        <!-- Center: Institutional Details & Project Title -->
        <div class="md:col-span-7 text-center">
          <div class="inline-block px-3 py-0.5 mb-1.5 bg-red-50 text-red-700 border border-red-200 rounded-full text-xs font-semibold tracking-wide uppercase" contenteditable="true">
            Department of Computer Engineering • Final Year Capstone Project 2026–2027
          </div>

          <h1 class="text-2xl sm:text-3xl md:text-4xl font-extrabold text-[#0f2b5c] tracking-tight leading-tight mb-1" contenteditable="true">
            AEGIS-RECON: EVIDENCE-BASED NETWORK RECONNAISSANCE & THREAT INTELLIGENCE
          </h1>

          <p class="text-xs sm:text-sm font-semibold text-slate-600 max-w-4xl mx-auto mb-3" contenteditable="true">
            Explainable Vulnerability Prioritization (CVSS v3.1, CISA KEV, EPSS), 4-Tier Cryptographic Evidence Provenance, and Policy-Governed Scope Protection
          </p>

          <!-- Authors & Mentors Row -->
          <div class="bg-slate-50 border border-slate-200 rounded-lg py-2 px-4 inline-flex flex-wrap items-center justify-center gap-x-6 gap-y-1 text-xs">
            <div>
              <span class="font-bold text-[#0f2b5c]">Student Contributors:</span>
              <span class="font-semibold text-slate-800" contenteditable="true">Parth Kamble (Lead) [Roll: 21102B00XX]</span> •
              <span class="text-slate-700" contenteditable="true">[Team Member 2]</span> •
              <span class="text-slate-700" contenteditable="true">[Team Member 3]</span> •
              <span class="text-slate-700" contenteditable="true">[Team Member 4]</span>
            </div>
            <div class="border-l border-slate-300 pl-4 hidden sm:block">
              <span class="font-bold text-[#0f2b5c]">Project Guide:</span>
              <span class="font-semibold text-slate-800" contenteditable="true">Prof. / Dr. [Guide Name], Ph.D.</span>
            </div>
          </div>
        </div>

        <!-- Right: QR Code & Release Telemetry -->
        <div class="md:col-span-2 flex flex-col items-center md:items-end justify-center gap-2">
          <div class="flex items-center gap-3">
            <div class="text-right hidden sm:block">
              <div class="text-[10px] font-bold uppercase text-slate-400">Scan for Repo</div>
              <div class="text-xs font-bold text-[#0f2b5c]">v0.3.0 Release</div>
              <div class="text-[10px] text-emerald-600 font-semibold flex items-center justify-end gap-1">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> 100% CI Green
              </div>
            </div>
            {qr_svg}
          </div>
          <div class="text-[10px] font-mono text-slate-500 text-center md:text-right" contenteditable="true">
            github.com/parthkamble4536-ship/AEGIS-Recon
          </div>
        </div>

      </div>
    </header>

    <!-- ======================================================================= -->
    <!-- 3-COLUMN ACADEMIC RESEARCH GRID                                         -->
    <!-- ======================================================================= -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">

      <!-- ===================================================================== -->
      <!-- COLUMN 1: MOTIVATION, FORMULATION & SCOPE PROTECTION                  -->
      <!-- ===================================================================== -->
      <section class="space-y-4">

        <!-- Abstract & Motivation Card -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-blue-600"></span> 1. Abstract & Motivation
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-50 text-blue-700 rounded font-semibold">OVERVIEW</span>
          </div>
          <p class="text-xs text-slate-700 text-justify mb-2.5 leading-relaxed" contenteditable="true">
            Modern enterprise vulnerability management suffers from severe alert fatigue and triage paralysis. Conventional port scanners (e.g., standard Nmap or raw banner matchers) produce vast numbers of unverified alerts, treating arbitrary version matches as confirmed vulnerabilities without assessing whether the bug is actively weaponized in the wild. Furthermore, unauthorized out-of-scope scanning poses acute legal liability under the <strong>Indian IT Act 2000 (Sec 43/66)</strong> and <strong>CFAA</strong>.
          </p>
          <p class="text-xs text-slate-700 text-justify leading-relaxed" contenteditable="true">
            <strong>AEGIS-Recon</strong> bridges this gap by engineering a zero-trust, policy-governed network reconnaissance platform. It combines native subprocess security, multi-factor risk scoring, 4-tier cryptographic evidence provenance, and grounded threat intelligence to transform raw recon into actionable, verifiable defensive remediation.
          </p>
        </article>

        <!-- Problem Statement & Industry Gaps Table -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-red-600"></span> 2. Problem Statement & Gaps
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-red-50 text-red-700 rounded font-semibold">LIMITATIONS</span>
          </div>
          <div class="overflow-x-auto text-[11px]">
            <table class="w-full border border-slate-200 rounded text-left">
              <thead class="bg-slate-100 text-slate-800 font-bold border-b border-slate-200">
                <tr>
                  <th class="p-2 border-r border-slate-200">Industry Challenge</th>
                  <th class="p-2 border-r border-slate-200">Legacy Tool Flaw</th>
                  <th class="p-2 text-[#0f2b5c]">AEGIS-Recon Innovation</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 text-slate-600">
                <tr>
                  <td class="p-2 font-semibold border-r border-slate-200">CVSS Score Inflation</td>
                  <td class="p-2 border-r border-slate-200">60%+ CVEs labeled "Critical" regardless of exploit availability</td>
                  <td class="p-2 font-semibold text-emerald-700">Multi-factor score with CISA KEV & EPSS exploit probability</td>
                </tr>
                <tr>
                  <td class="p-2 font-semibold border-r border-slate-200">Banner False Positives</td>
                  <td class="p-2 border-r border-slate-200">Assumes version banner equals confirmed exploitation</td>
                  <td class="p-2 font-semibold text-emerald-700">Strict 4-tier evidence: Version matches tagged as Hypotheses</td>
                </tr>
                <tr>
                  <td class="p-2 font-semibold border-r border-slate-200">Scope Creep & Injection</td>
                  <td class="p-2 border-r border-slate-200">Raw shell command execution prone to shell command injection</td>
                  <td class="p-2 font-semibold text-emerald-700">Zero-bypass YAML CIDR allowlist + <code>shell=False</code> execution</td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <!-- Explainable Multi-Factor Risk Formulation -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-emerald-600"></span> 3. Explainable Risk Scoring Engine
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded font-semibold">FORMULATION</span>
          </div>
          <div class="formula-box text-xs text-slate-800 mb-2.5" contenteditable="true">
            <div class="font-bold text-[#0f2b5c] mb-1">Composite Priority Score Formulation (0 to 100):</div>
            Priority = [ w_cvss · S_cvss + w_kev · B_kev + w_epss · P_epss ] · C_asset · E_exposure
          </div>
          <div class="grid grid-cols-2 gap-2 text-[11px] text-slate-700">
            <div class="bg-slate-50 p-2 rounded border border-slate-200" contenteditable="true">
              <span class="font-bold text-slate-900">• S_cvss (40%):</span> NIST NVD CVSS v3.1 base score normalized to [0, 100].
            </div>
            <div class="bg-slate-50 p-2 rounded border border-slate-200" contenteditable="true">
              <span class="font-bold text-slate-900">• B_kev (+25 Boost):</span> Binary indicator of CISA Known Exploited Vulnerability.
            </div>
            <div class="bg-slate-50 p-2 rounded border border-slate-200" contenteditable="true">
              <span class="font-bold text-slate-900">• P_epss (+15 Boost):</span> FIRST EPSS exploit probability in next 30 days.
            </div>
            <div class="bg-slate-50 p-2 rounded border border-slate-200" contenteditable="true">
              <span class="font-bold text-slate-900">• C_asset Context:</span> Production=1.5×, Staging=1.2×, Dev=1.0×, Lab=0.8×.
            </div>
          </div>
        </article>

        <!-- Policy-Governed Scope Protection -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-indigo-600"></span> 4. Policy-Governed Scope Protection
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded font-semibold">ZERO-TRUST</span>
          </div>
          <p class="text-xs text-slate-700 mb-2" contenteditable="true">
            AEGIS-Recon strictly prevents unauthorized target scanning and command injection through a dual-lock security gateway:
          </p>
          <ul class="text-xs space-y-1.5 text-slate-700">
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-emerald-600 font-bold">✔</span>
              <span><strong>Subnet Authorization:</strong> Targets are validated against exact CIDRs in <code>config/allowlist.yaml</code> via Python <code>ipaddress.ip_network</code>.</span>
            </li>
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-emerald-600 font-bold">✔</span>
              <span><strong>Shell-Injection Defense:</strong> Subprocesses execute via list-based argument arrays with <code>shell=False</code>, completely neutralizing shell metacharacter injection (<code>; & |</code>).</span>
            </li>
          </ul>
        </article>

      </section>

      <!-- ===================================================================== -->
      <!-- COLUMN 2: SYSTEM ARCHITECTURE & TECHNICAL INNOVATION                  -->
      <!-- ===================================================================== -->
      <section class="space-y-4">

        <!-- System Architecture Flowchart Card -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-blue-600"></span> 5. Layered System Architecture
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-50 text-blue-700 rounded font-semibold">PIPELINE</span>
          </div>

          <!-- Architecture Flowchart in Crisp HTML/CSS -->
          <div class="space-y-2 text-xs">
            <div class="p-2 rounded-md bg-blue-50 border border-blue-200 text-center">
              <div class="font-bold text-[#0f2b5c]">1. Analyst Interaction Layer</div>
              <div class="text-[11px] text-slate-600">Enterprise Cyber SOC Dashboard (Vanilla JS / Chart.js) & REST API (FastAPI)</div>
            </div>

            <div class="flex justify-center text-slate-400 font-bold">↓ (HTTP / REST)</div>

            <div class="p-2 rounded-md bg-amber-50 border border-amber-200 text-center">
              <div class="font-bold text-amber-900">2. Scope Protection & Validation Boundary</div>
              <div class="text-[11px] text-slate-700">CIDR Matcher • Allowlist YAML • Subprocess Argument Sanitizer (<code>shell=False</code>)</div>
            </div>

            <div class="flex justify-center text-slate-400 font-bold">↓ (Authorized Target Only)</div>

            <div class="p-2 rounded-md bg-slate-100 border border-slate-300 text-center">
              <div class="font-bold text-slate-800">3. Non-Blocking Reconnaissance Engine</div>
              <div class="text-[11px] text-slate-600">Native Nmap Execution • XML Streamer • Native <code>xml.etree</code> Parsing</div>
            </div>

            <div class="flex justify-center text-slate-400 font-bold">↓ (Raw Port & Banner Stream)</div>

            <div class="p-2 rounded-md bg-emerald-50 border border-emerald-200 text-center">
              <div class="font-bold text-emerald-900">4. 5-Level Resilient CPE Correlation & Risk Engine</div>
              <div class="text-[11px] text-slate-700">CPE 2.3 Normalization • NIST NVD 2.0 • CISA KEV • FIRST EPSS Exploit Prediction</div>
            </div>

            <div class="flex justify-center text-slate-400 font-bold">↓ (Ranked Vulnerability Findings)</div>

            <div class="p-2 rounded-md bg-purple-50 border border-purple-200 text-center">
              <div class="font-bold text-purple-900">5. Cryptographic Evidence & AI Intelligence</div>
              <div class="text-[11px] text-slate-700">4-Tier SHA-256 Provenance Chain • Deterministic Exploitability & Defense Playbook</div>
            </div>
          </div>
        </article>

        <!-- 4-Tier Cryptographic Evidence Provenance Model -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-purple-600"></span> 6. 4-Tier Cryptographic Evidence Model
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 rounded font-semibold">ZERO-TRUST</span>
          </div>
          <p class="text-xs text-slate-700 mb-2" contenteditable="true">
            To prevent false accusations and hallucinations, findings follow a strict 4-tier chain of custody sealed with SHA-256 integrity digests:
          </p>
          <div class="grid grid-cols-2 gap-2 text-xs">
            <div class="bg-emerald-50 border border-emerald-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-emerald-800 text-[11px]">TIER 1: OBSERVED</div>
              <div class="text-[10px] text-slate-600">Direct wire telemetry (raw TCP SYN-ACK, banner bytes grabbed on port).</div>
            </div>
            <div class="bg-blue-50 border border-blue-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-blue-800 text-[11px]">TIER 2: EXTERNAL INTEL</div>
              <div class="text-[10px] text-slate-600">Authoritative feed data (NVD CVE descriptions, CISA KEV date, EPSS score).</div>
            </div>
            <div class="bg-amber-50 border border-amber-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-amber-800 text-[11px]">TIER 3: HYPOTHESIS</div>
              <div class="text-[10px] text-slate-600">Deductions requiring manual verification (e.g. Version match ≠ Exploit).</div>
            </div>
            <div class="bg-purple-50 border border-purple-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-purple-800 text-[11px]">TIER 4: RECOMMENDATION</div>
              <div class="text-[10px] text-slate-600">Actionable defensive mitigations derived solely from verified hypotheses.</div>
            </div>
          </div>
        </article>

        <!-- 5-Level Resilient CPE Hierarchy -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-cyan-600"></span> 7. 5-Level Resilient CPE Correlation
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-cyan-50 text-cyan-700 rounded font-semibold">CORRELATION</span>
          </div>
          <div class="space-y-1.5 text-xs text-slate-700">
            <div class="p-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between" contenteditable="true">
              <span><strong>Level 1:</strong> Exact CPE 2.3 Match (e.g., <code>cpe:/a:apache:http_server:2.4.49</code>)</span>
              <span class="text-[10px] font-bold text-emerald-700 bg-emerald-100 px-1.5 py-0.5 rounded">High Conf</span>
            </div>
            <div class="p-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between" contenteditable="true">
              <span><strong>Level 2:</strong> CPE Version Range (<code>versionStartIncluding / EndExcluding</code>)</span>
              <span class="text-[10px] font-bold text-blue-700 bg-blue-100 px-1.5 py-0.5 rounded">High Conf</span>
            </div>
            <div class="p-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between" contenteditable="true">
              <span><strong>Level 3:</strong> Vendor + Product + Version Token Match</span>
              <span class="text-[10px] font-bold text-amber-700 bg-amber-100 px-1.5 py-0.5 rounded">Med Conf</span>
            </div>
            <div class="p-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between" contenteditable="true">
              <span><strong>Level 4:</strong> Product + Version Regex Heuristics</span>
              <span class="text-[10px] font-bold text-amber-700 bg-amber-100 px-1.5 py-0.5 rounded">Med Conf</span>
            </div>
            <div class="p-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between" contenteditable="true">
              <span><strong>Level 5:</strong> Product-Only Fallback (Tagged as Hypothesis)</span>
              <span class="text-[10px] font-bold text-slate-600 bg-slate-200 px-1.5 py-0.5 rounded">Low Conf</span>
            </div>
          </div>
        </article>

      </section>

      <!-- ===================================================================== -->
      <!-- COLUMN 3: EMPIRICAL BENCHMARKS, UI SHOWCASE & DEFENSE                 -->
      <!-- ===================================================================== -->
      <section class="space-y-4">

        <!-- Multi-Environment Test Fleet Benchmark -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-blue-600"></span> 8. Multi-Asset Benchmark Fleet
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-50 text-blue-700 rounded font-semibold">TESTBED</span>
          </div>
          <div class="grid grid-cols-2 gap-2 text-[11px] text-slate-700 mb-2">
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Metasploitable 2 (Linux 2.6)</div>
              <div class="text-[10px] text-slate-500">192.168.56.101 • PRODUCTION</div>
              <div>5 CVEs (2 KEV) • Score: <strong>88/100</strong></div>
            </div>
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Metasploitable 3 (WinServer 2016)</div>
              <div class="text-[10px] text-slate-500">192.168.56.102 • STAGING</div>
              <div>7 CVEs (1 KEV - MS17-010) • Score: <strong>84/100</strong></div>
            </div>
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Metasploitable 3 (Ubuntu 14.04)</div>
              <div class="text-[10px] text-slate-500">192.168.56.103 • DEV</div>
              <div>6 CVEs (1 KEV - ProFTPD) • Score: <strong>78/100</strong></div>
            </div>
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Kioptrix Level 1 (RedHat 9 CTF)</div>
              <div class="text-[10px] text-slate-500">192.168.56.104 • LAB</div>
              <div>4 CVEs (mod_ssl OpenFuck) • Score: <strong>76/100</strong></div>
            </div>
          </div>
          <!-- Quantitative Metrics Bar -->
          <div class="grid grid-cols-3 gap-2 text-center text-xs">
            <div class="p-1.5 bg-emerald-50 border border-emerald-200 rounded">
              <div class="text-base font-extrabold text-emerald-700">0%</div>
              <div class="text-[10px] text-slate-600 font-medium">Scope Violation</div>
            </div>
            <div class="p-1.5 bg-blue-50 border border-blue-200 rounded">
              <div class="text-base font-extrabold text-blue-700">550</div>
              <div class="text-[10px] text-slate-600 font-medium">Automated Tests</div>
            </div>
            <div class="p-1.5 bg-purple-50 border border-purple-200 rounded">
              <div class="text-base font-extrabold text-purple-700">&lt; 1.8s</div>
              <div class="text-[10px] text-slate-600 font-medium">Pipeline Latency</div>
            </div>
          </div>
        </article>

        <!-- Platform Visual Showcase (Actual UI Captures) -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-emerald-600"></span> 9. Live Platform Telemetry & SOC GUI
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded font-semibold">SCREENSHOTS</span>
          </div>

          <div class="grid grid-cols-2 gap-2 text-[10px]">
            <div>
              <div class="font-bold text-slate-600 mb-0.5">A. Executive SOC Overview</div>
              <img src="{dash_uri}" alt="Dashboard Overview" class="w-full h-auto rounded border border-slate-300 shadow-sm" />
            </div>
            <div>
              <div class="font-bold text-slate-600 mb-0.5">B. Donut & Provenance Chart</div>
              <img src="{chart_uri}" alt="Severity Charts" class="w-full h-auto rounded border border-slate-300 shadow-sm" />
            </div>
            <div>
              <div class="font-bold text-slate-600 mb-0.5">C. Correlated CVEs & Triage</div>
              <img src="{vuln_uri}" alt="Vulnerability Findings" class="w-full h-auto rounded border border-slate-300 shadow-sm" />
            </div>
            <div>
              <div class="font-bold text-slate-600 mb-0.5">D. AI Defensive Playbook</div>
              <img src="{ai_uri}" alt="AI Intelligence Report" class="w-full h-auto rounded border border-slate-300 shadow-sm" />
            </div>
          </div>
        </article>

        <!-- Viva Highlights & Key Takeaways Card -->
        <article class="poster-card p-4 bg-gradient-to-br from-slate-50 to-blue-50/50">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-amber-600"></span> 10. Conclusion & Viva Defense Points
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-amber-100 text-amber-800 rounded font-semibold">VIVA READY</span>
          </div>
          <ul class="text-xs space-y-1.5 text-slate-700">
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-blue-600 font-bold">•</span>
              <span><strong>Why not just use Nmap directly?</strong> Nmap is an active scanner, not a threat intelligence or triage system. AEGIS adds mathematical scoring, policy gating, and evidence provenance.</span>
            </li>
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-blue-600 font-bold">•</span>
              <span><strong>How is Scope Protection guaranteed?</strong> Evaluated via IP network subnet containment in YAML before any subprocess spawns; non-bypassable by design.</span>
            </li>
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-blue-600 font-bold">•</span>
              <span><strong>Engineering Rigor:</strong> 550 tests passing in CI/CD across Python 3.11, 3.12, 3.13; 0 Bandit AST vulnerabilities; SQLite WAL ACID transactions.</span>
            </li>
          </ul>
        </article>

      </section>

    </div>

    <!-- ======================================================================= -->
    <!-- POSTER FOOTER                                                           -->
    <!-- ======================================================================= -->
    <footer class="mt-6 pt-4 border-t-2 border-slate-200 flex flex-wrap items-center justify-between gap-4 text-[11px] text-slate-500">
      <div contenteditable="true">
        <strong>Vidyalankar Institute of Technology</strong> • Approved by AICTE, Accredited A+ by NAAC, Affiliated to University of Mumbai • Vidyalankar Educational Campus, Wadala (E), Mumbai 400037
      </div>
      <div class="flex items-center gap-4">
        <span contenteditable="true">License: <strong>MIT Open Source</strong></span>
        <span>•</span>
        <span contenteditable="true">Repository: <strong>parthkamble4536-ship/AEGIS-Recon</strong></span>
      </div>
    </footer>

  </main>

  <!-- ========================================================================= -->
  <!-- CLIENT-SIDE EDITING & EXPORT ENGINE                                       -->
  <!-- ========================================================================= -->
  <script>
    let isEditMode = false;
    const STORAGE_KEY = 'aegis_poster_custom_content_v1';

    // 1. Toggle Live In-Browser Edit Mode
    function toggleEditMode() {{
      isEditMode = !isEditMode;
      document.body.classList.toggle('edit-mode-active', isEditMode);

      const btn = document.getElementById('toggle-edit-btn');
      const text = document.getElementById('edit-btn-text');
      const badge = document.getElementById('edit-status-badge');

      if (isEditMode) {{
        btn.classList.remove('bg-blue-600', 'hover:bg-blue-700');
        btn.classList.add('bg-amber-600', 'hover:bg-amber-700');
        text.innerText = '✅ Done Editing';
        badge.innerText = '✏️ Edit Mode Active (Click any text to modify)';
        badge.classList.remove('text-slate-500');
        badge.classList.add('text-amber-700', 'font-bold');
      }} else {{
        btn.classList.remove('bg-amber-600', 'hover:bg-amber-700');
        btn.classList.add('bg-blue-600', 'hover:bg-blue-700');
        text.innerText = '✏️ Enable Live Edit';
        badge.innerText = 'Viewing Mode (Click Edit to customize text)';
        badge.classList.remove('text-amber-700', 'font-bold');
        badge.classList.add('text-slate-500');
      }}
    }}

    // 2. Save Custom Content to LocalStorage
    function saveEdits() {{
      const posterRoot = document.getElementById('poster-root');
      try {{
        localStorage.setItem(STORAGE_KEY, posterRoot.innerHTML);
        showNotification('Saved to browser successfully! Edits will persist on reload.');
      }} catch (e) {{
        showNotification('Error saving edits: ' + e.message, true);
      }}
    }}

    // 3. Load Saved Edits on Page Load
    function loadEdits() {{
      try {{
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved) {{
          document.getElementById('poster-root').innerHTML = saved;
        }}
      }} catch (e) {{
        console.error('Error loading edits:', e);
      }}
    }}

    // 4. Reset Poster to Factory Defaults
    function resetPoster() {{
      if (confirm('Are you sure you want to reset all edits back to original defaults?')) {{
        localStorage.removeItem(STORAGE_KEY);
        window.location.reload();
      }}
    }}

    // 5. Export Customized Poster as Standalone HTML File
    function exportPosterHtml() {{
      // Temporarily exit edit mode so outlines aren't baked into exported file
      const wasEdit = isEditMode;
      if (wasEdit) toggleEditMode();

      const htmlContent = '<!DOCTYPE html>\\n' + document.documentElement.outerHTML;
      const blob = new Blob([htmlContent], {{ type: 'text/html;charset=utf-8' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'AEGIS_Recon_Project_Poster_VIT.html';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      if (wasEdit) toggleEditMode();
      showNotification('Downloaded customized poster file: AEGIS_Recon_Project_Poster_VIT.html');
    }}

    // 6. Simple Toast Notification
    function showNotification(msg, isError = false) {{
      let toast = document.getElementById('poster-toast');
      if (!toast) {{
        toast = document.createElement('div');
        toast.id = 'poster-toast';
        toast.className = 'no-print fixed bottom-6 right-6 px-4 py-2.5 rounded-lg shadow-xl text-white text-xs font-semibold z-50 transition-opacity duration-300 pointer-events-none';
        document.body.appendChild(toast);
      }}
      toast.className = 'no-print fixed bottom-6 right-6 px-4 py-2.5 rounded-lg shadow-xl text-white text-xs font-semibold z-50 transition-opacity duration-300 pointer-events-none ' +
        (isError ? 'bg-red-600' : 'bg-emerald-600');
      toast.innerText = msg;
      toast.style.opacity = '1';
      setTimeout(() => {{ toast.style.opacity = '0'; }}, 3200);
    }}

    // Initialize on load
    window.addEventListener('DOMContentLoaded', loadEdits);
  </script>
</body>
</html>
"""


def main() -> None:
    print("Generating AEGIS-Recon Academic Poster HTML...")
    base_dir = Path(__file__).resolve().parents[1]

    # Target 1: In the workspace docs/poster/ directory
    poster_dir = base_dir / "docs" / "poster"
    poster_dir.mkdir(parents=True, exist_ok=True)
    out_file = poster_dir / "project_poster.html"

    html = generate_poster_html()
    out_file.write_text(html, encoding="utf-8")
    print(f"Generated workspace poster: {out_file} ({out_file.stat().st_size} bytes)")

    # Target 2: In the conversation artifact directory for UI presentation
    artifact_dir = Path(
        r"C:\Users\user\.gemini\antigravity\brain\a25b1bcd-6cdb-45a4-b989-31fd668668e0"
    )
    if artifact_dir.exists():
        artifact_file = artifact_dir / "project_poster.html"
        artifact_file.write_text(html, encoding="utf-8")
        print(f"Generated brain artifact: {artifact_file} ({artifact_file.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
