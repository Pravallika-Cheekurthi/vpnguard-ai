import io
import os
import zipfile
import re
import xml.sax.saxutils as saxutils
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from pypdf import PdfReader
from pptx import Presentation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from rules import analyze_raw_config

load_dotenv(override=True)

app = FastAPI(title="IPSec Guard AI - Exposure Command Center")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FindingItem(BaseModel):
    severity: str
    title: str
    description: str
    danger: Optional[str] = "Allows attackers to compromise data."
    simple_fix: Optional[str] = "Upgrade to modern encryption standards."
    nist: Optional[str] = "N/A"
    pci_dss: Optional[str] = "N/A"

class DirectPDFRequest(BaseModel):
    target_vendor: str
    score: int
    status: str
    findings: List[FindingItem]
    ai_guidance: str
    source_name: Optional[str] = "Configuration Profile"

def clean_xml(text: str) -> str:
    if not text:
        return ""
    return saxutils.escape(str(text))

def extract_text_from_pdf(pdf_bytes):
    text = ""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        for page in reader.pages:
            t = page.extract_text()
            if t:
                text += t + "\n"
    except Exception as e:
        text = f"Error parsing PDF: {str(e)}"
    return text

def extract_text_from_pptx(pptx_bytes):
    text = ""
    try:
        prs = Presentation(io.BytesIO(pptx_bytes))
        for slide in prs.slides:
            for shape in slide.shapes:
                if hasattr(shape, "text") and shape.text:
                    text += shape.text + "\n"
    except Exception as e:
        text = f"Error parsing Presentation: {str(e)}"
    return text

def scan_apk_internals(apk_bytes):
    findings = []
    penalty = 0
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            file_list = z.namelist()
            for filename in file_list:
                if filename.endswith('.dex'):
                    info = z.getinfo(filename)
                    if info.file_size < 50 * 1024 * 1024:
                        dex_data = z.read(filename).decode('latin-1', errors='ignore').lower()
                        if "des/cbc" in dex_data or "desede" in dex_data or "3des" in dex_data:
                            penalty += 25
                            findings.append({
                                "severity": "Critical",
                                "title": "Outdated Encryption (DES / 3DES)",
                                "description": f"Cipher reference identified in {filename}.",
                                "danger": "Attackers can crack and read confidential user data in transit.",
                                "simple_fix": "Upgrade to modern AES-256 encryption.",
                                "nist": "NIST SP 800-131A",
                                "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
                            })
                        if "md5" in dex_data:
                            penalty += 15
                            findings.append({
                                "severity": "High",
                                "title": "Tamper-Prone Verification (MD5)",
                                "description": f"Bytecode collision flaw detected in {filename}.",
                                "danger": "Attackers can secretly modify data without detection.",
                                "simple_fix": "Switch to SHA-256 for integrity verification.",
                                "nist": "NIST SP 800-131A",
                                "pci_dss": "PCI-DSS v4.0 Req 4.2.2"
                            })
                        if "aes/ecb" in dex_data:
                            penalty += 20
                            findings.append({
                                "severity": "Critical",
                                "title": "Insecure Data Scrambling (ECB Mode)",
                                "description": "Deterministic pattern leakage across block boundaries.",
                                "danger": "Attackers can see clear patterns and decipher data.",
                                "simple_fix": "Use AES-GCM or CBC mode with random IVs.",
                                "nist": "NIST SP 800-38A",
                                "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
                            })

            if "AndroidManifest.xml" in file_list:
                manifest = z.read("AndroidManifest.xml").decode('latin-1', errors='ignore')
                if "usesCleartextTraffic" in manifest:
                    penalty += 20
                    findings.append({
                        "severity": "High",
                        "title": "Unencrypted Web Traffic Permitted",
                        "description": "App permits sending data over unencrypted HTTP channels.",
                        "danger": "Anyone on the same Wi-Fi can spy on user activities.",
                        "simple_fix": "Enforce HTTPS traffic across all network calls.",
                        "nist": "NIST SP 800-52 Rev. 2",
                        "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
                    })
    except Exception as e:
        return {"score": 20, "status": "Critical", "findings": [{
            "severity": "Critical",
            "title": "Inspection Error",
            "description": str(e),
            "danger": "Inspection halted due to internal format issue.",
            "simple_fix": "Ensure file is not corrupt.",
            "nist": "N/A",
            "pci_dss": "N/A"
        }]}

    score = max(15, 100 - penalty) if findings else 100
    status = "Secure" if score >= 80 else ("Warning" if score >= 50 else "Critical")
    return {"score": score, "status": status, "findings": findings, "discovered_file": "IPsec Mobile Client Telemetry"}

def enrich_findings_with_plain_english(audit_findings):
    for f in audit_findings:
        title = f.get("title", "").lower()
        if "des" in title or "3des" in title or "cipher" in title:
            f["title"] = "Outdated Encryption Algorithm (3DES/DES)"
            f["danger"] = "Attackers can break this old cipher and spy on secure communications."
            f["simple_fix"] = "Upgrade to military-grade AES-256 encryption."
        elif "hash" in title or "md5" in title or "sha1" in title:
            f["title"] = "Weak Digital Fingerprint (MD5 / SHA-1)"
            f["danger"] = "Attackers can tamper with network packets without being caught."
            f["simple_fix"] = "Switch to SHA-256 integrity verification."
        elif "aggressive" in title:
            f["title"] = "Unprotected Handshake (Aggressive Mode)"
            f["danger"] = "Sends connection passwords out in the open, allowing easy password theft."
            f["simple_fix"] = "Disable Aggressive Mode and enable IKEv2 Main Mode."
        elif "dh group" in title or "substandard" in title:
            f["title"] = "Weak Secret Key Exchange (Small DH Group)"
            f["danger"] = "Modern computers can guess the encryption keys in minutes."
            f["simple_fix"] = "Upgrade key exchange group to Group 14 (2048-bit) or higher."
        elif "pre-shared key" in title or "default" in title:
            f["title"] = "Guessable Password / Default Key"
            f["danger"] = "Anyone can guess this simple password and enter the private network."
            f["simple_fix"] = "Replace with a strong, randomly generated 32+ character key."
        elif "ikev1" in title or "legacy protocol" in title:
            f["title"] = "Old Handshake Protocol (IKEv1)"
            f["danger"] = "Leaves gateways vulnerable to denial-of-service and connection drop attacks."
            f["simple_fix"] = "Upgrade gateway to the modern IKEv2 protocol."
        else:
            if not f.get("danger"):
                f["danger"] = "Presents security vulnerabilities to unauthorized parties."
            if not f.get("simple_fix"):
                f["simple_fix"] = "Align with updated cryptographic guidelines."
    return audit_findings

def get_static_remediation(findings, vendor):
    if vendor == "Cisco IOS":
        commands = "! Hardened Cisco IOS Configuration\ncrypto ikev2 proposal IKEV2-PROPOSAL\n encryption aes-gcm-256\n integrity sha256\n group 14 19\nexit\ncrypto ipsec transform-set TS-AES256-GCM esp-gcm 256\n mode tunnel\nexit"
    elif vendor == "Fortinet FortiOS":
        commands = "# Hardened Fortinet Configuration\nconfig vpn ipsec phase1-interface\n edit \"SECURE-TUNNEL\"\n  set ike-version 2\n  set proposal aes256-sha256\n  set dhgrp 14 19\n next\nend"
    else:
        commands = "# Modern Linux / Mobile IPsec Service\nconnections {\n  secure-link {\n    version = 2\n    proposals = aes256gcm128-sha256-modp2048\n  }\n}"
    return f"Remediation Brief:\nAutomated hardening applied to deprecate weak ciphers and enforce modern AES-256 with IKEv2.\n\nProduction Drop-in Script:\n{commands}"

def get_ai_remediation(findings, raw_config, vendor):
    if not findings:
        return "✅ Baseline configuration validated. No security risks found."
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return get_static_remediation(findings, vendor)

    prompt = f"Act as Chief IPsec Security Architect. Explain in 2 sentences in simple plain English what security issues exist, then provide the drop-in hardened CLI configuration for {vendor}. Flaws: {findings}."
    for model_name in ["gemma2-9b-it", "mixtral-8x7b-32768", "llama-3.1-70b-versatile"]:
        try:
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model_name, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2, "max_tokens": 500},
                timeout=5
            )
            data = res.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
        except Exception:
            continue
    return get_static_remediation(findings, vendor)

class ConfigRequest(BaseModel):
    raw_config: str
    target_vendor: str = "Cisco IOS"
    source_name: Optional[str] = "Configuration Profile"

@app.post("/api/scan")
def scan_vpn(payload: ConfigRequest):
    audit = analyze_raw_config(payload.raw_config)
    audit["findings"] = enrich_findings_with_plain_english(audit["findings"])
    audit["ai_guidance"] = get_ai_remediation(audit["findings"], payload.raw_config, payload.target_vendor)
    audit["source_name"] = payload.source_name
    return audit

@app.post("/api/extract-file")
def extract_file(file: UploadFile = File(...)):
    filename = file.filename.lower()
    contents = file.file.read()

    if filename.endswith(".apk"):
        audit = scan_apk_internals(contents)
        audit["findings"] = enrich_findings_with_plain_english(audit["findings"])
        audit["ai_guidance"] = get_ai_remediation(audit["findings"], "APK Bytecode SAST", "Android Client")
        return {
            "type": "apk",
            "filename": file.filename,
            "extracted_text": f"// [STAGED ARTIFACT] {file.filename}\n// Android IPsec Client Package ingested.\n// Ready for cryptographic and manifest analysis.",
            "apk_audit": audit
        }

    extracted_text = ""
    if filename.endswith(".pdf"):
        extracted_text = extract_text_from_pdf(contents)
    elif filename.endswith((".pptx", ".ppt")):
        extracted_text = extract_text_from_pptx(contents)
    else:
        extracted_text = contents.decode("utf-8", errors="ignore")

    return {
        "type": "text",
        "filename": file.filename,
        "extracted_text": extracted_text.strip()
    }

@app.post("/api/export-pdf")
def export_pdf(payload: DirectPDFRequest):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()
    story = []
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#4f46e5'))
    story.append(Paragraph("IPSec Guard AI - IPsec Protocol & Cryptographic Health Report", title_style))
    story.append(Spacer(1, 6))

    status_color = "#10b981" if payload.score >= 80 else ("#f59e0b" if payload.score >= 50 else "#ef4444")
    risk_label = "Healthy / Compliant" if payload.score >= 80 else ("Moderate Exposure" if payload.score >= 50 else "High Risk / Vulnerable")
    
    clean_src = clean_xml(payload.source_name)
    summary = f"<b>Inspected Target:</b> {clean_src} &nbsp;|&nbsp; <b>Posture Score:</b> {payload.score}/100 &nbsp;|&nbsp; <b>Status:</b> <font color='{status_color}'><b>{risk_label}</b></font>"
    story.append(Paragraph(summary, styles['Normal']))
    story.append(Spacer(1, 14))

    table_data = [["Security Weakness", "Why is it Dangerous?", "How We Fix It"]]
    if payload.findings:
        for f in payload.findings:
            title_clean = clean_xml(f.title)
            desc_clean = clean_xml(f.description)
            danger_clean = clean_xml(f.danger if f.danger else "Allows attackers to compromise data.")
            fix_clean = clean_xml(f.simple_fix if f.simple_fix else "Upgrade to modern standards.")
            nist_clean = clean_xml(f.nist if f.nist else "N/A")
            
            table_data.append([
                Paragraph(f"<b>{title_clean}</b><br/><font color='#64748b' size=7>{desc_clean}</font>", styles['Normal']),
                Paragraph(f"<font color='#dc2626'>{danger_clean}</font>", styles['Normal']),
                Paragraph(f"<b>{fix_clean}</b><br/><font color='#64748b' size=7>Standard: {nist_clean}</font>", styles['Normal'])
            ])
    else:
        table_data.append(["All Clear", "No IPsec vulnerabilities found.", "System follows NIST & PCI-DSS cryptographic standards."])

    t = Table(table_data, colWidths=[175, 185, 180])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 7),
        ('TOPPADDING', (0, 0), (-1, 0), 7),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>Autonomous Hardening CLI Script:</b>", styles['Heading3']))
    
    clean_guidance = clean_xml(payload.ai_guidance).replace("\n", "<br/>")
    code_style = ParagraphStyle('CodeStyle', parent=styles['Normal'], fontName='Courier', fontSize=8, textColor=colors.HexColor('#1e293b'), leading=11)
    story.append(Paragraph(clean_guidance, code_style))
    
    try:
        doc.build(story)
    except Exception:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        fallback_story = [
            Paragraph("<b>IPSec Guard AI Audit Report</b>", styles['Heading1']),
            Spacer(1, 10),
            Paragraph(f"Score: {payload.score}/100 - {payload.status}", styles['Normal']),
            Spacer(1, 10),
            Paragraph("Audit findings generated successfully.", styles['Normal'])
        ]
        doc.build(fallback_story)

    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=IPSecGuard_Executive_Report.pdf"}
    )

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
      <meta charset="UTF-8">
      <title>IPSec Guard AI | Cryptographic Exposure Command Center</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
      <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #030511; }
        .cyber-card { background-color: #080c21; border: 1px solid #1a224a; }
        .glow-ring { box-shadow: 0 0 35px -5px rgba(99, 102, 241, 0.25); }
      </style>
    </head>
    <body class="text-slate-200 min-h-screen flex antialiased">

      <aside class="w-64 border-r border-slate-800 bg-[#050716] flex flex-col justify-between shrink-0 p-5 z-20">
        <div class="flex flex-col gap-6">
          <div class="flex items-center gap-3 px-2">
            <div class="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center font-bold text-white shadow-md shadow-indigo-500/20">🛡️</div>
            <div class="flex flex-col">
              <span class="font-bold text-white text-base">IPSec Guard AI</span>
              <span class="text-[10px] text-slate-500 font-mono tracking-widest uppercase">IPsec Posture Suite</span>
            </div>
          </div>

          <nav class="flex flex-col gap-1.5 text-xs font-medium">
            <div class="px-3 py-1 text-[10px] uppercase text-slate-500 font-semibold font-mono">Operations</div>
            <a href="#" class="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-indigo-600/15 text-indigo-300 border border-indigo-500/30">
              <span>Exposure Command</span>
            </a>
            <a href="#" onclick="downloadPDF()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900 transition">
              <span>Export Report (PDF)</span>
            </a>
          </nav>
        </div>

        <div class="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
          <span class="text-slate-300 font-semibold block">SIH Prototype</span>
          <span class="text-[10px] text-indigo-400 font-mono">Autonomous Engine</span>
        </div>
      </aside>

      <main class="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
        <header class="h-14 border-b border-slate-800 bg-[#040716] px-8 flex items-center justify-between shrink-0">
          <div class="text-xs text-slate-400">Dashboard / <span class="text-white font-medium">IPsec Exposure Command</span></div>
          <button onclick="downloadPDF()" class="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white transition">Export Report</button>
        </header>

        <div class="p-8 flex flex-col gap-6 max-w-[1450px] w-full mx-auto">
          <div>
            <h1 class="text-2xl font-bold text-white">IPSec Exposure Command Center</h1>
            <p class="text-xs text-slate-400">Deterministic cryptographic posture auditing for IPsec gateways, client APKs, and network architecture documents.</p>
          </div>

          <div class="cyber-card rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-6">
            <div class="flex flex-col gap-2 w-full md:w-60 text-xs">
              <span class="text-[10px] uppercase tracking-wider text-slate-500 font-mono font-semibold">Active Scopes</span>
              <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">IPsec / IKEv2 Engine</div>
              <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">Architecture SAST (PDF/PPT)</div>
              <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">NIST SP 800-77 Controls</div>
            </div>

            <div class="w-48 h-48 rounded-full border border-indigo-500/40 bg-[#06091e] flex flex-col items-center justify-center text-center p-4 glow-ring">
              <span id="orbScore" class="text-5xl font-extrabold text-white">--</span>
              <span class="text-[10px] text-indigo-400 font-mono uppercase mt-1">IPsec Safety Score</span>
              <span id="orbStatus" class="text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-slate-800 text-slate-400">Ready</span>
            </div>

            <div class="flex flex-col gap-3 w-full md:w-64">
              <div class="p-3 rounded-xl bg-rose-950/30 border border-rose-900/40 flex justify-between items-center">
                <span class="text-xs text-slate-300">Critical Risks</span>
                <span id="critCount" class="text-xl font-bold text-rose-400">0</span>
              </div>
              <div class="p-3 rounded-xl bg-amber-950/30 border border-amber-900/40 flex justify-between items-center">
                <span class="text-xs text-slate-300">Moderate Warnings</span>
                <span id="warnCount" class="text-xl font-bold text-amber-400">0</span>
              </div>
              <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex justify-between items-center">
                <span class="text-xs text-slate-300">Total Weaknesses</span>
                <span id="defectTotal" class="text-xl font-bold text-indigo-400">0</span>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div class="lg:col-span-5 cyber-card rounded-2xl p-5 flex flex-col gap-4">
              <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-slate-300">Artifact Ingestion</span>
                <div class="flex gap-2">
                  <button onclick="clearWorkspace()" class="text-xs text-rose-400 hover:underline">Clear</button>
                  <span class="text-slate-600">&bull;</span>
                  <button onclick="loadSample()" class="text-xs text-indigo-400 hover:underline">Sample Insecure</button>
                </div>
              </div>

              <div class="grid grid-cols-3 gap-2">
                <label class="flex items-center justify-center p-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg text-xs font-semibold cursor-pointer text-center">
                  <span>📊 PDF / PPT</span>
                  <input type="file" id="docUpload" accept=".pdf,.ppt,.pptx" class="hidden" onclick="this.value=null" onchange="uploadArtifact(event)">
                </label>
                <label class="flex items-center justify-center p-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-semibold cursor-pointer text-center">
                  <span>📱 APK File</span>
                  <input type="file" id="apkUpload" accept=".apk" class="hidden" onclick="this.value=null" onchange="uploadArtifact(event)">
                </label>
                <label class="flex items-center justify-center p-2 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-lg text-xs font-semibold cursor-pointer text-center">
                  <span>📄 .conf / .txt</span>
                  <input type="file" id="cfgUpload" accept=".conf,.txt,.ovpn,.ipsec" class="hidden" onclick="this.value=null" onchange="uploadArtifact(event)">
                </label>
              </div>

              <textarea id="cfg" class="w-full h-56 bg-[#040614] border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-300 focus:outline-none focus:border-indigo-500 resize-none" placeholder="Extracted IPsec architecture text or raw gateway configurations will display here..."></textarea>

              <div class="flex items-center justify-between text-xs">
                <span class="text-slate-400">Gateway Target:</span>
                <select id="vendorSelect" class="bg-[#040614] border border-slate-800 text-xs text-slate-200 rounded-lg px-2.5 py-1.5">
                  <option value="Cisco IOS">Cisco IOS Gateway</option>
                  <option value="Fortinet FortiOS">Fortinet Firewall</option>
                  <option value="StrongSwan (Linux)">Linux StrongSwan</option>
                  <option value="Android Client">Android Mobile Client</option>
                </select>
              </div>

              <button onclick="runScan()" id="scanBtn" class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition">Execute Cryptographic Audit</button>
            </div>

            <div class="lg:col-span-7 flex flex-col gap-4">
              <div class="cyber-card rounded-2xl p-5 flex flex-col gap-3">
                <div class="flex justify-between items-center border-b border-slate-800 pb-2">
                  <span class="text-xs font-bold text-slate-300">Identified Cryptographic Weaknesses</span>
                  <span id="sourceBadge" class="text-[11px] font-mono text-slate-500">Idle</span>
                </div>
                <div id="findingsContainer" class="flex flex-col gap-2 min-h-[100px] text-xs text-slate-500">
                  Select an IPsec artifact or paste configuration, then click Execute Cryptographic Audit.
                </div>
              </div>

              <div class="cyber-card rounded-2xl p-5 flex flex-col gap-2">
                <span class="text-xs font-bold text-indigo-400">Automated Protocol Hardening CLI</span>
                <pre id="remediationBox" class="text-xs bg-[#040614] border border-slate-900 p-3 rounded-xl font-mono text-slate-300 whitespace-pre-wrap min-h-[140px]">Hardened IPsec remediation configuration will render here...</pre>
              </div>
            </div>
          </div>
        </div>
      </main>

      <script>
        let currentScanResult = null;
        let stagedSource = "Active Session";
        let stagedApkResult = null;

        function resetTelemetryUI() {
          const orb = document.getElementById('orbScore');
          const status = document.getElementById('orbStatus');
          orb.innerText = "--";
          orb.className = "text-5xl font-extrabold text-white";
          status.innerText = "Staged";
          status.className = "text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-slate-800 text-slate-400";
          document.getElementById('defectTotal').innerText = "0";
          document.getElementById('critCount').innerText = "0";
          document.getElementById('warnCount').innerText = "0";
          document.getElementById('findingsContainer').innerHTML = '<div class="text-xs text-slate-500 font-mono py-4">Artifact staged. Click "Execute Cryptographic Audit" to run analysis.</div>';
          document.getElementById('remediationBox').innerText = "Awaiting execution trigger...";
        }

        function clearWorkspace() {
          document.getElementById('cfg').value = "";
          currentScanResult = null;
          stagedApkResult = null;
          stagedSource = "Active Session";
          document.getElementById('sourceBadge').innerText = "Idle";
          
          document.getElementById('docUpload').value = null;
          document.getElementById('apkUpload').value = null;
          document.getElementById('cfgUpload').value = null;

          const orb = document.getElementById('orbScore');
          const status = document.getElementById('orbStatus');
          orb.innerText = "--";
          orb.className = "text-5xl font-extrabold text-white";
          status.innerText = "Ready";
          status.className = "text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-slate-800 text-slate-400";
          document.getElementById('defectTotal').innerText = "0";
          document.getElementById('critCount').innerText = "0";
          document.getElementById('warnCount').innerText = "0";
          document.getElementById('findingsContainer').innerHTML = "Select an IPsec artifact or paste configuration, then click Execute Cryptographic Audit.";
          document.getElementById('remediationBox').innerText = "Hardened IPsec remediation configuration will render here...";
        }

        function loadSample() {
          stagedApkResult = null;
          stagedSource = "Cisco Insecure IPsec Template";
          document.getElementById('sourceBadge').innerText = stagedSource;
          document.getElementById('cfg').value = "crypto isakmp policy 10\\n enc 3des\\n hash md5\\n authentication pre-share\\n group 2\\n crypto isakmp key cisco address 0.0.0.0\\n crypto isakmp aggressive-mode enable";
          resetTelemetryUI();
        }

        async function uploadArtifact(event) {
          const file = event.target.files[0];
          if (!file) return;

          const btn = document.getElementById('scanBtn');
          btn.innerText = "Reading File...";
          btn.disabled = true;

          const formData = new FormData();
          formData.append("file", file);

          try {
            const res = await fetch('/api/extract-file', { method: 'POST', body: formData });
            const data = await res.json();
            
            stagedSource = file.name;
            document.getElementById('sourceBadge').innerText = "Staged: " + file.name;
            
            if (data.type === "apk") {
              stagedApkResult = data.apk_audit;
              stagedApkResult.source_name = "APK: " + file.name;
              document.getElementById('vendorSelect').value = "Android Client";
              document.getElementById('cfg').value = data.extracted_text;
            } else {
              stagedApkResult = null;
              document.getElementById('cfg').value = data.extracted_text;
            }

            resetTelemetryUI();
          } catch(e) {
            alert('File Loading Failed: ' + e);
          } finally {
            btn.innerText = "Execute Cryptographic Audit";
            btn.disabled = false;
            event.target.value = null;
          }
        }

        async function runScan() {
          const cfg = document.getElementById('cfg').value;
          const vendor = document.getElementById('vendorSelect').value;

          if (stagedApkResult) {
            currentScanResult = stagedApkResult;
            currentScanResult.target_vendor = vendor;
            renderTelemetry(currentScanResult);
            return;
          }

          if (!cfg.trim()) {
            alert("Please paste or load an IPsec configuration first.");
            return;
          }

          const btn = document.getElementById('scanBtn');
          btn.innerText = "Auditing Cryptographic Surface...";
          btn.disabled = true;
          
          try {
            const res = await fetch('/api/scan', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ raw_config: cfg, target_vendor: vendor, source_name: stagedSource })
            });
            const data = await res.json();
            currentScanResult = data;
            renderTelemetry(data);
          } catch(e) {
            alert('Audit Pipeline Failed: ' + e);
          } finally {
            btn.innerText = "Execute Cryptographic Audit";
            btn.disabled = false;
          }
        }

        async function downloadPDF() {
          if (!currentScanResult) {
            alert("Run an audit or upload an artifact before exporting.");
            return;
          }
          const payload = {
            target_vendor: document.getElementById('vendorSelect').value,
            score: currentScanResult.score,
            status: currentScanResult.status,
            findings: currentScanResult.findings,
            ai_guidance: currentScanResult.ai_guidance,
            source_name: currentScanResult.source_name || "IPsec Security Audit"
          };

          const res = await fetch('/api/export-pdf', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
          });
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = "IPSecGuard_Executive_Report.pdf";
          a.click();
        }

        function renderTelemetry(data) {
          const orb = document.getElementById('orbScore');
          const status = document.getElementById('orbStatus');
          orb.innerText = data.score;
          status.innerText = data.score >= 80 ? "Healthy" : (data.score >= 50 ? "Moderate Exposure" : "High Risk");

          if (data.score >= 80) {
            orb.className = "text-5xl font-extrabold text-emerald-400";
            status.className = "text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-emerald-500/10 text-emerald-300 border border-emerald-500/30";
          } else if (data.score >= 50) {
            orb.className = "text-5xl font-extrabold text-amber-400";
            status.className = "text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-amber-500/10 text-amber-300 border border-amber-500/30";
          } else {
            orb.className = "text-5xl font-extrabold text-rose-400";
            status.className = "text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-rose-500/10 text-rose-300 border border-rose-500/30";
          }

          document.getElementById('defectTotal').innerText = data.findings.length;
          document.getElementById('critCount').innerText = data.findings.filter(f => f.severity === 'Critical').length;
          document.getElementById('warnCount').innerText = data.findings.filter(f => f.severity !== 'Critical').length;
          document.getElementById('sourceBadge').innerText = data.discovered_file || data.source_name || "Active Session";

          const container = document.getElementById('findingsContainer');
          if (!data.findings.length) {
            container.innerHTML = '<div class="text-xs text-emerald-400 font-mono py-4">✅ All clear. Zero cryptographic exposures detected. Fully compliant with NIST SP 800-77.</div>';
          } else {
            container.innerHTML = data.findings.map(f => `
              <div class="p-3 rounded-lg bg-[#040614] border border-slate-800 flex flex-col gap-1.5">
                <div class="flex justify-between items-center">
                  <span class="text-xs font-semibold text-slate-100">${f.title}</span>
                  <span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${f.severity === 'Critical' ? 'bg-rose-500/10 text-rose-400' : 'bg-amber-500/10 text-amber-400'}">${f.severity}</span>
                </div>
                <div class="text-[11px] text-rose-300/90 font-medium">⚠️ <b>Risk:</b> ${f.danger || 'Attackers can intercept sensitive traffic.'}</div>
                <div class="text-[11px] text-emerald-400/90">💡 <b>Solution:</b> ${f.simple_fix || 'Upgrade to modern encryption standards.'}</div>
              </div>
            `).join('');
          }

          document.getElementById('remediationBox').innerText = data.ai_guidance;
        }
      </script>
    </body>
    </html>
    """
