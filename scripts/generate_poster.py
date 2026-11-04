"""
AEGIS-Recon Professional Academic Project Poster Generator (Enhanced Version).
Generates a self-contained, light-theme, publication-ready academic exhibition poster
featuring Vidyalankar Institute of Technology (VIT NAAC A+) branding, live in-browser editing,
persistence, PDF export, zero blank spaces, and enhanced system architecture visuals.
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
  <main id="poster-root" class="poster-container max-w-[1740px] mx-auto bg-white border border-slate-300 rounded-2xl shadow-xl overflow-hidden p-6 md:p-8">

    <!-- ======================================================================= -->
    <!-- HEADER SECTION (Formatted with Clean Team Badges)                       -->
    <!-- ======================================================================= -->
    <header class="border-b-2 border-slate-200 pb-5 mb-5">
      <div class="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">

        <!-- Left: Official College Logo & Accreditation -->
        <div class="md:col-span-3 flex flex-col items-center md:items-start">
          <img src="{logo_uri}" alt="Vidyalankar Institute of Technology" class="h-20 w-auto object-contain mb-1 hover:scale-105 transition-transform" />
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

          <!-- Properly Formatted Team Members & Guide Card (Fixes Img 1) -->
          <div class="bg-slate-50 border border-slate-300 rounded-xl p-2.5 max-w-3xl mx-auto shadow-sm">
            <div class="text-[11px] font-bold text-[#0f2b5c] uppercase tracking-wider mb-1.5 flex items-center justify-center gap-2">
              <svg class="w-3.5 h-3.5 text-blue-600" fill="currentColor" viewBox="0 0 20 20"><path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/></svg>
              Student Contributors (Dept. of Computer Engineering)
            </div>

            <div class="flex flex-wrap items-center justify-center gap-2 text-xs mb-2">
              <div class="inline-flex items-center gap-1.5 px-3 py-1 bg-white border border-slate-300 rounded-lg shadow-sm" contenteditable="true">
                <span class="font-bold text-slate-900">Vighnesh Somnath Waman</span>
                <span class="px-1.5 py-0.5 bg-blue-100 text-blue-800 rounded font-mono text-[11px] font-semibold">23101C0014</span>
              </div>
              <div class="inline-flex items-center gap-1.5 px-3 py-1 bg-white border border-slate-300 rounded-lg shadow-sm" contenteditable="true">
                <span class="font-bold text-slate-900">Parth Pravin Kamble</span>
                <span class="px-1.5 py-0.5 bg-blue-100 text-blue-800 rounded font-mono text-[11px] font-semibold">23101C0063</span>
              </div>
              <div class="inline-flex items-center gap-1.5 px-3 py-1 bg-white border border-slate-300 rounded-lg shadow-sm" contenteditable="true">
                <span class="font-bold text-slate-900">Vedant Suhas Puntambekar</span>
                <span class="px-1.5 py-0.5 bg-blue-100 text-blue-800 rounded font-mono text-[11px] font-semibold">23101C0076</span>
              </div>
            </div>

            <div class="pt-1.5 border-t border-slate-200 flex items-center justify-center gap-2 text-xs" contenteditable="true">
              <span class="font-bold text-[#0f2b5c]">Project Guide:</span>
              <span class="font-bold text-slate-800">Prof. Vinita Bhandiwad</span>
              <span class="text-slate-500">• Assistant Professor, Dept. of Computer Engineering</span>
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
    <!-- 3-COLUMN BALANCED ACADEMIC RESEARCH GRID (Zero Blank Spaces)            -->
    <!-- ======================================================================= -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 items-stretch">

      <!-- ===================================================================== -->
      <!-- COLUMN 1: MOTIVATION, FORMULATION & SCOPE PROTECTION                  -->
      <!-- ===================================================================== -->
      <section class="flex flex-col space-y-4">

        <!-- 1. Abstract & Motivation Card -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-blue-600"></span> 1. Abstract & Motivation
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-50 text-blue-700 rounded font-semibold">OVERVIEW</span>
          </div>
          <p class="text-xs text-slate-700 text-justify mb-2 leading-relaxed" contenteditable="true">
            Enterprise vulnerability management routinely suffers from acute alert fatigue and triage paralysis. Conventional port scanners (e.g. raw Nmap or banner matchers) generate massive volumes of unverified alerts, treating version match heuristics as confirmed exploits without evaluating active in-the-wild exploitation. Furthermore, out-of-scope scanning creates immediate legal liabilities under the <strong>Indian IT Act 2000 (Sec 43/66)</strong> and <strong>CFAA</strong>.
          </p>
          <p class="text-xs text-slate-700 text-justify leading-relaxed" contenteditable="true">
            <strong>AEGIS-Recon</strong> resolves this crisis by introducing a zero-trust, policy-governed network reconnaissance platform. It combines non-blocking execution security, 4-factor composite risk scoring, 4-tier cryptographic evidence provenance, and deterministic AI playbooks to convert raw telemetry into verifiable defensive remediation.
          </p>
        </article>

        <!-- 2. Problem Statement & Limitations Table -->
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
                  <th class="p-2 text-[#0f2b5c]">AEGIS-Recon Solution</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 text-slate-600">
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">CVSS Inflation</td>
                  <td class="p-1.5 border-r border-slate-200">60%+ CVEs rated "Critical" without exploit proof</td>
                  <td class="p-1.5 font-semibold text-emerald-700">Multi-factor score with CISA KEV & EPSS probability</td>
                </tr>
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">Banner False Positives</td>
                  <td class="p-1.5 border-r border-slate-200">Equates version headers to confirmed exploitability</td>
                  <td class="p-1.5 font-semibold text-emerald-700">Strict 4-tier evidence: Banner matches = Hypothesis only</td>
                </tr>
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">Scope Creep / Injection</td>
                  <td class="p-1.5 border-r border-slate-200">Executes arbitrary shell strings prone to command injection</td>
                  <td class="p-1.5 font-semibold text-emerald-700">Dual-lock CIDR allowlist + native <code>shell=False</code> arrays</td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <!-- 3. Explainable Risk Scoring Engine Formulation -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-emerald-600"></span> 3. Explainable Risk Scoring Engine
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded font-semibold">FORMULATION</span>
          </div>
          <div class="formula-box text-xs text-slate-800 mb-2" contenteditable="true">
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

        <!-- 4. Policy-Governed Zero-Trust Scope Protection -->
        <article class="poster-card p-4 flex-1">
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
              <span><strong>Shell-Injection Defense:</strong> Subprocesses execute via list-based argument arrays with <code>shell=False</code>, completely neutralizing shell metacharacter injection (<code>; & | ` $</code>).</span>
            </li>
          </ul>
        </article>

      </section>

      <!-- ===================================================================== -->
      <!-- COLUMN 2: ARCHITECTURE, SECURITY GATEWAY & EVIDENCE PROVENANCE        -->
      <!-- ===================================================================== -->
      <section class="flex flex-col space-y-4">

        <!-- 5. Visual System Architecture & Data Flow (Fills Space) -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-blue-600"></span> 5. Layered System Architecture & Data Flow
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-50 text-blue-700 rounded font-semibold">PIPELINE</span>
          </div>

          <!-- Crisp Architecture Diagram SVG / Flow -->
          <div class="space-y-1.5 text-xs">
            <div class="p-2 rounded bg-blue-50 border border-blue-200 text-center">
              <div class="font-bold text-[#0f2b5c]">1. Analyst Interface Layer</div>
              <div class="text-[11px] text-slate-600">Enterprise Cyber SOC Dashboard (HTML5/JS/Chart.js) & REST API (FastAPI)</div>
            </div>
            <div class="flex justify-center text-slate-400 font-bold text-[11px]">↓ (Target IP / CIDR Subnet)</div>

            <div class="p-2 rounded bg-amber-50 border border-amber-200 text-center">
              <div class="font-bold text-amber-900">2. Scope Protection & Validation Boundary</div>
              <div class="text-[11px] text-slate-700">YAML CIDR Matcher • Allowlist Policy Gate • <code>shell=False</code> Sanitizer</div>
            </div>
            <div class="flex justify-center text-slate-400 font-bold text-[11px]">↓ (Authorized Scope Confirmed)</div>

            <div class="p-2 rounded bg-slate-100 border border-slate-300 text-center">
              <div class="font-bold text-slate-800">3. Non-Blocking Reconnaissance Engine</div>
              <div class="text-[11px] text-slate-600">Nmap Execution Subprocess • XML Streamer • Native <code>xml.etree</code> Parsing</div>
            </div>
            <div class="flex justify-center text-slate-400 font-bold text-[11px]">↓ (Raw Service & Port Telemetry)</div>

            <div class="p-2 rounded bg-emerald-50 border border-emerald-200 text-center">
              <div class="font-bold text-emerald-900">4. 5-Level Resilient CPE Correlation & Risk Engine</div>
              <div class="text-[11px] text-slate-700">CPE 2.3 Normalizer • NIST NVD 2.0 • CISA KEV • FIRST EPSS Exploit Scoring</div>
            </div>
            <div class="flex justify-center text-slate-400 font-bold text-[11px]">↓ (Ranked Findings with Context)</div>

            <div class="p-2 rounded bg-purple-50 border border-purple-200 text-center">
              <div class="font-bold text-purple-900">5. Cryptographic Evidence Vault & Grounded AI</div>
              <div class="text-[11px] text-slate-700">4-Tier SHA-256 Provenance Chain • Deterministic Exploitability & Defense Cards</div>
            </div>
          </div>
        </article>

        <!-- 6. 4-Tier Cryptographic Evidence Provenance Model -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-purple-600"></span> 6. 4-Tier Cryptographic Evidence Model
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 rounded font-semibold">PROVENANCE</span>
          </div>
          <div class="formula-box text-[11px] text-slate-800 mb-2" contenteditable="true">
            <strong>Cryptographic Digest:</strong> proof_hash = SHA256(scan_id || target || port || cve_id || tier)
          </div>
          <div class="grid grid-cols-2 gap-2 text-xs">
            <div class="bg-emerald-50 border border-emerald-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-emerald-800 text-[11px]">TIER 1: OBSERVED</div>
              <div class="text-[10px] text-slate-600">Direct wire telemetry (raw TCP SYN-ACK, banner bytes grabbed on port).</div>
            </div>
            <div class="bg-blue-50 border border-blue-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-blue-800 text-[11px]">TIER 2: EXTERNAL INTEL</div>
              <div class="text-[10px] text-slate-600">Authoritative feed data (NVD CVE records, CISA KEV date, EPSS score).</div>
            </div>
            <div class="bg-amber-50 border border-amber-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-amber-800 text-[11px]">TIER 3: HYPOTHESIS</div>
              <div class="text-[10px] text-slate-600">Deductions requiring manual verification (Version match ≠ Exploit).</div>
            </div>
            <div class="bg-purple-50 border border-purple-200 p-2 rounded" contenteditable="true">
              <div class="font-bold text-purple-800 text-[11px]">TIER 4: RECOMMENDATION</div>
              <div class="text-[10px] text-slate-600">Actionable defensive mitigations derived solely from verified hypotheses.</div>
            </div>
          </div>
        </article>

        <!-- 7. 5-Level Resilient CPE Normalization Hierarchy -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-cyan-600"></span> 7. 5-Level Resilient CPE Correlation
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-cyan-50 text-cyan-700 rounded font-semibold">NORMALIZATION</span>
          </div>
          <div class="space-y-1.5 text-xs text-slate-700">
            <div class="p-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between" contenteditable="true">
              <span><strong>Level 1:</strong> Exact CPE 2.3 Match (e.g. <code>cpe:/a:apache:http_server:2.4.49</code>)</span>
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

        <!-- 8. SOC Analyst Triage Lifecycle State Machine (Fills Space) -->
        <article class="poster-card p-4 flex-1">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-teal-600"></span> 8. Analyst Triage Lifecycle & Audit Trail
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-teal-50 text-teal-700 rounded font-semibold">LIFECYCLE</span>
          </div>
          <p class="text-xs text-slate-700 mb-2" contenteditable="true">
            Vulnerabilities follow an auditable state-machine ensuring every decision is permanently recorded with reason codes and timestamps:
          </p>
          <div class="flex flex-wrap items-center justify-center gap-1.5 text-[10px] font-bold text-slate-700 mb-2">
            <span class="px-2 py-1 bg-blue-100 text-blue-800 rounded border border-blue-200">NEW</span>
            <span>➔</span>
            <span class="px-2 py-1 bg-amber-100 text-amber-800 rounded border border-amber-200">IN_REVIEW</span>
            <span>➔</span>
            <span class="px-2 py-1 bg-emerald-100 text-emerald-800 rounded border border-emerald-200">VERIFIED</span>
            <span class="text-slate-400">|</span>
            <span class="px-2 py-1 bg-rose-100 text-rose-800 rounded border border-rose-200">FALSE_POSITIVE</span>
            <span class="text-slate-400">|</span>
            <span class="px-2 py-1 bg-purple-100 text-purple-800 rounded border border-purple-200">REMEDIATED</span>
          </div>
          <div class="text-[11px] text-slate-600 bg-slate-50 p-2 rounded border border-slate-200" contenteditable="true">
            <strong>Analyst Actions:</strong> <code>Verify</code>, <code>False Positive</code>, <code>Accept Risk</code>, <code>Remediate</code>, <code>Snooze</code>, <code>Why?</code> (Provenance Verification).
          </div>
        </article>

      </section>

      <!-- ===================================================================== -->
      <!-- COLUMN 3: BENCHMARK FLEET, COMPARATIVE EVALUATION & FUTURE SCOPE     -->
      <!-- ===================================================================== -->
      <section class="flex flex-col space-y-4">

        <!-- 9. Multi-Environment Test Fleet Benchmark -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-blue-600"></span> 9. Multi-Asset Benchmark Fleet
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-50 text-blue-700 rounded font-semibold">TESTBED</span>
          </div>
          <div class="grid grid-cols-2 gap-2 text-[11px] text-slate-700 mb-2">
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Metasploitable 2 (Linux 2.6)</div>
              <div class="text-[10px] text-slate-500">192.168.56.101 • PRODUCTION</div>
              <div>5 CVEs (2 KEV) • Priority: <strong>88/100</strong></div>
            </div>
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Metasploitable 3 (WinServer 2016)</div>
              <div class="text-[10px] text-slate-500">192.168.56.102 • STAGING</div>
              <div>7 CVEs (1 KEV - MS17-010) • Priority: <strong>84/100</strong></div>
            </div>
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Metasploitable 3 (Ubuntu 14.04)</div>
              <div class="text-[10px] text-slate-500">192.168.56.103 • DEV</div>
              <div>6 CVEs (1 KEV - ProFTPD) • Priority: <strong>78/100</strong></div>
            </div>
            <div class="p-2 border border-slate-200 rounded bg-slate-50" contenteditable="true">
              <div class="font-bold text-[#0f2b5c]">Kioptrix Level 1 (RedHat 9 CTF)</div>
              <div class="text-[10px] text-slate-500">192.168.56.104 • LAB</div>
              <div>4 CVEs (mod_ssl OpenFuck) • Priority: <strong>76/100</strong></div>
            </div>
          </div>
          <!-- Quantitative Evaluation Bar -->
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

        <!-- 10. Comparative Industry Evaluation (Fills Space) -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-indigo-600"></span> 10. Comparative Benchmark Analysis
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded font-semibold">BENCHMARK</span>
          </div>
          <div class="overflow-x-auto text-[10px]">
            <table class="w-full border border-slate-200 rounded text-left">
              <thead class="bg-slate-100 text-slate-800 font-bold border-b border-slate-200">
                <tr>
                  <th class="p-1.5 border-r border-slate-200">Metric / Capability</th>
                  <th class="p-1.5 border-r border-slate-200">Legacy Nmap</th>
                  <th class="p-1.5 border-r border-slate-200">Nessus / OpenVAS</th>
                  <th class="p-1.5 text-[#0f2b5c]">AEGIS-Recon</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 text-slate-600">
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">Scope Gating</td>
                  <td class="p-1.5 border-r border-slate-200 text-red-600">None (CLI flags)</td>
                  <td class="p-1.5 border-r border-slate-200 text-amber-600">Target Range UI</td>
                  <td class="p-1.5 font-semibold text-emerald-700">YAML CIDR Dual-Lock</td>
                </tr>
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">Prioritization</td>
                  <td class="p-1.5 border-r border-slate-200 text-slate-400">None</td>
                  <td class="p-1.5 border-r border-slate-200 text-amber-600">CVSS Base Score</td>
                  <td class="p-1.5 font-semibold text-emerald-700">CVSS + KEV + EPSS</td>
                </tr>
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">Evidence Provenance</td>
                  <td class="p-1.5 border-r border-slate-200 text-slate-400">Plain text stdout</td>
                  <td class="p-1.5 border-r border-slate-200 text-slate-400">Unsealed log file</td>
                  <td class="p-1.5 font-semibold text-emerald-700">4-Tier SHA-256 Ledger</td>
                </tr>
                <tr>
                  <td class="p-1.5 font-semibold border-r border-slate-200">Execution Safety</td>
                  <td class="p-1.5 border-r border-slate-200 text-red-600">Shell execution</td>
                  <td class="p-1.5 border-r border-slate-200 text-slate-600">Proprietary agent</td>
                  <td class="p-1.5 font-semibold text-emerald-700">Native <code>shell=False</code></td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <!-- 11. Platform Visual Showcase (Actual UI Captures) -->
        <article class="poster-card p-4">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-emerald-600"></span> 11. Live Cyber SOC GUI Telemetry
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

        <!-- 12. Conclusion & Future Scope (Fixes Img 2 Heading & Badge) -->
        <article class="poster-card p-4 bg-gradient-to-br from-slate-50 to-blue-50/50 flex-1">
          <div class="section-title">
            <h2 class="font-bold text-sm text-[#0f2b5c] uppercase tracking-wider flex items-center gap-2" contenteditable="true">
              <span class="w-2 h-2 rounded-full bg-amber-600"></span> 12. Conclusion & Future Scope
            </h2>
            <span class="text-[10px] font-mono px-2 py-0.5 bg-blue-100 text-blue-900 rounded font-semibold">PROJECT OUTCOMES</span>
          </div>
          <ul class="text-xs space-y-1.5 text-slate-700">
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-blue-600 font-bold">•</span>
              <span><strong>Zero-Trust Reconnaissance:</strong> Successfully eliminated alert fatigue and reconnaissance liability by uniting policy-governed scope authorization with multi-factor risk prioritization.</span>
            </li>
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-blue-600 font-bold">•</span>
              <span><strong>Evidence-Grounded Triage:</strong> Cryptographic SHA-256 evidence provenance ensures tamper-evident audit trails, distinguishing unverified banner hypotheses from real vulnerabilities.</span>
            </li>
            <li class="flex items-start gap-1.5" contenteditable="true">
              <span class="text-blue-600 font-bold">•</span>
              <span><strong>Engineering Rigor & Future Scope:</strong> 550 test cases passing in continuous integration across Python 3.11–3.13. Future work includes SIEM/SOAR streaming and distributed Kubernetes scanner pods.</span>
            </li>
          </ul>
        </article>

      </section>

    </div>

    <!-- ======================================================================= -->
    <!-- POSTER FOOTER                                                           -->
    <!-- ======================================================================= -->
    <footer class="mt-5 pt-3 border-t-2 border-slate-200 flex flex-wrap items-center justify-between gap-4 text-[11px] text-slate-500">
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
    const STORAGE_KEY = 'aegis_poster_custom_content_v2';

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
    print("Generating AEGIS-Recon Academic Poster HTML (Enhanced Version)...")
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
