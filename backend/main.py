import io
import os
import zipfile
import re
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from rules import analyze_raw_config

load_dotenv(override=True)

app = FastAPI(title="VPNGuard AI - Exposure Command Center")

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
    nist: Optional[str] = "N/A"
    pci_dss: Optional[str] = "N/A"

class DirectPDFRequest(BaseModel):
    target_vendor: str
    score: int
    status: str
    findings: List[FindingItem]
    ai_guidance: str
    source_name: Optional[str] = "Configuration Profile"

def scan_apk_internals(apk_bytes):
    findings = []
    score = 100
    extracted_strings = []
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            file_list = z.namelist()
            for filename in file_list:
                if filename.endswith(('.conf', '.ovpn', '.ipsec', '.txt')):
                    content = z.read(filename).decode('utf-8', errors='ignore')
                    if re.search(r'\b(crypto|ike|cipher|vpn|client)\b', content, re.IGNORECASE):
                        extracted_strings.append(content)
                
                # Check dex bytecode streams
                elif filename.endswith('.dex'):
                    info = z.getinfo(filename)
                    if info.file_size < 50 * 1024 * 1024:
                        dex_data = z.read(filename).decode('latin-1', errors='ignore').lower()
                        if "des/cbc" in dex_data or "desede" in dex_data or "3des" in dex_data:
                            score -= 35
                            findings.append({
                                "severity": "Critical",
                                "title": "Legacy 64-Bit Cipher (3DES/DES)",
                                "description": f"Cipher reference identified in {filename}. Vulnerable to Sweet32.",
                                "nist": "NIST SP 800-131A",
                                "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
                            })
                        if "md5" in dex_data:
                            score -= 20
                            findings.append({
                                "severity": "High",
                                "title": "Broken Hash Function (MD5)",
                                "description": f"Bytecode collision flaw detected in {filename}.",
                                "nist": "NIST SP 800-131A",
                                "pci_dss": "PCI-DSS v4.0 Req 4.2.2"
                            })
                        if "aes/ecb" in dex_data:
                            score -= 30
                            findings.append({
                                "severity": "Critical",
                                "title": "ECB Mode Without Diffusion",
                                "description": "Deterministic pattern leakage across block boundaries.",
                                "nist": "NIST SP 800-38A",
                                "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
                            })

            if "AndroidManifest.xml" in file_list:
                manifest = z.read("AndroidManifest.xml").decode('latin-1', errors='ignore')
                if "usesCleartextTraffic" in manifest:
                    score -= 25
                    findings.append({
                        "severity": "High",
                        "title": "Cleartext HTTP Allowed",
                        "description": "Cleartext traffic explicitly permitted in AndroidManifest.",
                        "nist": "NIST SP 800-52 Rev. 2",
                        "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
                    })
    except Exception as e:
        return {"score": 0, "status": "Error", "findings": [{"severity": "Critical", "title": "Inspection Error", "description": str(e), "nist": "N/A", "pci_dss": "N/A"}]}

    if extracted_strings:
        merged = "\n".join(extracted_strings)
        rule_audit = analyze_raw_config(merged)
        findings.extend(rule_audit["findings"])
        score = min(score, rule_audit["score"])

    score = max(0, score)
    status = "Secure" if score >= 80 else ("Warning" if score >= 50 else "Critical")
    return {"score": score, "status": status, "findings": findings, "discovered_file": "APK SAST Bytecode Telemetry"}

def get_static_remediation(findings, vendor):
    if vendor == "Cisco IOS":
        commands = "! Hardened Cisco IOS\ncrypto ikev2 proposal IKEV2-PROPOSAL\n encryption aes-gcm-256\n integrity sha256\n group 14 19\nexit\ncrypto ipsec transform-set TS-AES256-GCM esp-gcm 256\n mode tunnel\nexit"
    elif vendor == "Fortinet FortiOS":
        commands = "# Hardened FortiOS\nconfig vpn ipsec phase1-interface\n edit \"VPN-SECURE\"\n  set ike-version 2\n  set proposal aes256-sha256\n  set dhgrp 14 19\n next\nend"
    else:
        commands = "# StrongSwan / Android VpnService\nconnections {\n  hardened-link {\n    version = 2\n    proposals = aes256gcm128-sha256-modp2048\n  }\n}"
    return f"Executive Brief:\nRemediate non-conforming parameters across {vendor}.\n\nProduction Drop-in Script:\n{commands}"

def get_ai_remediation(findings, raw_config, vendor):
    if not findings:
        return "✅ Baseline configuration validated. No cryptographic exposures detected."
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return get_static_remediation(findings, vendor)

    prompt = f"Act as Principal SOC Architect. Flaws: {findings}. Platform: {vendor}. Config: {raw_config[:300]}. Provide concise remediation with drop-in CLI."
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

@app.post("/api/scan")
def scan_vpn(payload: ConfigRequest):
    audit = analyze_raw_config(payload.raw_config)
    audit["ai_guidance"] = get_ai_remediation(audit["findings"], payload.raw_config, payload.target_vendor)
    audit["source_name"] = "IPsec Ingress Tunnel"
    return audit

@app.post("/api/scan-apk")
def scan_apk(file: UploadFile = File(...)):
    contents = file.file.read()
    audit = scan_apk_internals(contents)
    audit["ai_guidance"] = get_ai_remediation(audit["findings"], "APK SAST Package Scan", "Android Client")
    audit["source_name"] = f"APK: {file.filename}"
    return audit

@app.post("/api/export-pdf")
def export_pdf(payload: DirectPDFRequest):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#6366f1'))
    story.append(Paragraph(f"VPNGuard Command Center Audit ({payload.source_name})", title_style))
    story.append(Spacer(1, 10))
    status_color = "#10b981" if payload.score >= 80 else ("#f59e0b" if payload.score >= 50 else "#ef4444")
    summary = f"<b>Telemetry Score:</b> {payload.score}/100 | <b>Risk Status:</b> <font color='{status_color}'>{payload.status}</font> | <b>Platform:</b> {payload.target_vendor}"
    story.append(Paragraph(summary, styles['Normal']))
    story.append(Spacer(1, 14))

    table_data = [["Severity", "Finding", "Control Compliance"]]
    if payload.findings:
        for f in payload.findings:
            table_data.append([
                f.severity,
                Paragraph(f"<b>{f.title}</b><br/>{f.description}", styles['Normal']),
                Paragraph(f"<b>NIST:</b> {f.nist}<br/><b>PCI-DSS:</b> {f.pci_dss}", styles['Normal'])
            ])
    else:
        table_data.append(["Info", "No Defects Detected", "Compliant"])

    t = Table(table_data, colWidths=[65, 260, 215])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#334155')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))
    story.append(Paragraph("<b>Autonomous Hardening Script:</b>", styles['Heading3']))
    sanitized = payload.ai_guidance.replace("\n", "<br/>")
    story.append(Paragraph(f"<font face='Courier' size=8>{sanitized}</font>", styles['Normal']))
    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=VPNGuard_Exposure_Report.pdf"})

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
      <meta charset="UTF-8">
      <title>VPNGuard AI | Exposure Command Center</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
      <style>
        body {
          font-family: 'Plus Jakarta Sans', sans-serif;
          background-color: #030511;
        }
        .cyber-card {
          background-color: #080c21;
          border: 1px solid #1a224a;
        }
        .glow-ring {
          box-shadow: 0 0 35px -5px rgba(99, 102, 241, 0.25);
        }
      </style>
    </head>
    <body class="text-slate-200 min-h-screen flex antialiased">

      <aside class="w-64 border-r border-slate-800 bg-[#050716] flex flex-col justify-between shrink-0 p-5 z-20">
        <div class="flex flex-col gap-6">
          <div class="flex items-center gap-3 px-2">
            <div class="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center font-bold text-white shadow-md shadow-indigo-500/20">
              🛡️
            </div>
            <div class="flex flex-col">
              <span class="font-bold text-white text-sm">CyberX <span class="text-indigo-400 font-mono text-xs">VPN</span></span>
              <span class="text-[10px] text-slate-500 font-mono tracking-widest">COMMAND CENTER</span>
            </div>
          </div>

          <nav class="flex flex-col gap-1.5 text-xs font-medium">
            <div class="px-3 py-1 text-[10px] uppercase text-slate-500 font-semibold font-mono">Operations</div>
            <a href="#" class="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-indigo-600/15 text-indigo-300 border border-indigo-500/30">
              <span>Exposure Command</span>
            </a>
            <a href="#" onclick="downloadPDF()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900 transition">
              <span>Export Dossier (PDF)</span>
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
          <div class="text-xs text-slate-400">Dashboard / <span class="text-white font-medium">Command Center</span></div>
          <button onclick="downloadPDF()" class="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white transition">Export Dossier</button>
        </header>

        <div class="p-8 flex flex-col gap-6 max-w-[1450px] w-full mx-auto">
          <div>
            <h1 class="text-2xl font-bold text-white">Exposure Command Center</h1>
            <p class="text-xs text-slate-400">Cryptographic surface analysis for IPsec gateways and Android APK artifacts.</p>
          </div>

          <div class="cyber-card rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-6">
            <div class="flex flex-col gap-2 w-full md:w-60 text-xs">
              <span class="text-[10px] uppercase tracking-wider text-slate-500 font-mono font-semibold">Active Scopes</span>
              <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">IPsec Gateway Engine</div>
              <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">Android APK SAST</div>
              <div class="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">NIST SP 800-77 Controls</div>
            </div>

            <div class="w-48 h-48 rounded-full border border-indigo-500/40 bg-[#06091e] flex flex-col items-center justify-center text-center p-4 glow-ring">
              <span id="orbScore" class="text-5xl font-extrabold text-white">--</span>
              <span class="text-[10px] text-indigo-400 font-mono uppercase mt-1">Posture Score</span>
              <span id="orbStatus" class="text-[10px] font-semibold px-2 py-0.5 rounded-full mt-2 bg-slate-800 text-slate-400">Ready</span>
            </div>

            <div class="flex flex-col gap-3 w-full md:w-64">
              <div class="p-3 rounded-xl bg-rose-950/30 border border-rose-900/40 flex justify-between items-center">
                <span class="text-xs text-slate-300">Critical Flaws</span>
                <span id="critCount" class="text-xl font-bold text-rose-400">0</span>
              </div>
              <div class="p-3 rounded-xl bg-amber-950/30 border border-amber-900/40 flex justify-between items-center">
                <span class="text-xs text-slate-300">High / Warnings</span>
                <span id="warnCount" class="text-xl font-bold text-amber-400">0</span>
              </div>
              <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex justify-between items-center">
                <span class="text-xs text-slate-300">Total Findings</span>
                <span id="defectTotal" class="text-xl font-bold text-indigo-400">0</span>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div class="lg:col-span-5 cyber-card rounded-2xl p-5 flex flex-col gap-4">
              <div class="flex justify-between items-center">
                <span class="text-xs font-bold text-slate-300">Config Ingestion</span>
                <button onclick="loadSample()" class="text-xs text-indigo-400 hover:underline">Sample Insecure</button>
              </div>

              <div class="grid grid-cols-2 gap-2">
                <label class="flex items-center justify-center gap-1.5 p-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-semibold cursor-pointer">
                  <span>📱 Upload APK</span>
                  <input type="file" id="apkUpload" accept=".apk" class="hidden" onchange="handleApk(event)">
                </label>
                <label class="flex items-center justify-center gap-1.5 p-2 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-lg text-xs font-semibold cursor-pointer">
                  <span>📄 Upload .conf</span>
                  <input type="file" id="fileUpload" accept=".conf,.txt,.ovpn,.ipsec" class="hidden" onchange="handleFile(event)">
                </label>
              </div>

              <textarea id="cfg" class="w-full h-56 bg-[#040614] border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-300 focus:outline-none focus:border-indigo-500 resize-none" placeholder="Paste IPsec configuration or select an upload option above..."></textarea>

              <div class="flex items-center justify-between text-xs">
                <span class="text-slate-400">Platform Target:</span>
                <select id="vendorSelect" class="bg-[#040614] border border-slate-800 text-xs text-slate-200 rounded-lg px-2.5 py-1.5">
                  <option value="Cisco IOS">Cisco IOS</option>
                  <option value="Fortinet FortiOS">Fortinet FortiOS</option>
                  <option value="StrongSwan (Linux)">StrongSwan (Linux)</option>
                  <option value="Android Client">Android VpnService</option>
                </select>
              </div>

              <button onclick="runScan()" id="scanBtn" class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition">Execute Cryptographic Audit</button>
            </div>

            <div class="lg:col-span-7 flex flex-col gap-4">
              <div class="cyber-card rounded-2xl p-5 flex flex-col gap-3">
                <div class="flex justify-between items-center border-b border-slate-800 pb-2">
                  <span class="text-xs font-bold text-slate-300">Vulnerabilities Detected</span>
                  <span id="sourceBadge" class="text-[11px] font-mono text-slate-500">Idle</span>
                </div>
                <div id="findingsContainer" class="flex flex-col gap-2 min-h-[100px] text-xs text-slate-500">
                  Load a sample or upload a file to view findings.
                </div>
              </div>

              <div class="cyber-card rounded-2xl p-5 flex flex-col gap-2">
                <span class="text-xs font-bold text-indigo-400">Remediation Script</span>
                <pre id="remediationBox" class="text-xs bg-[#040614] border border-slate-900 p-3 rounded-xl font-mono text-slate-300 whitespace-pre-wrap min-h-[140px]">Remediation commands will render here after audit...</pre>
              </div>
            </div>
          </div>
        </div>
      </main>

      <script>
        let currentScanResult = null;

        function loadSample() {
          document.getElementById('cfg').value = "crypto isakmp policy 10\\n enc 3des\\n hash md5\\n authentication pre-share\\n group 2\\n crypto isakmp key cisco address 0.0.0.0\\n crypto isakmp aggressive-mode enable";
        }

        function handleFile(event) {
          const file = event.target.files[0];
          if (!file) return;
          
          // Smart redirection: If user chose an APK through the .conf picker, dispatch to APK engine
          if (file.name.toLowerCase().endsWith('.apk')) {
            processApkFile(file);
            return;
          }

          const reader = new FileReader();
          reader.onload = (e) => {
            document.getElementById('cfg').value = e.target.result;
          };
          reader.readAsText(file);
        }

        async function handleApk(event) {
          const file = event.target.files[0];
          if (!file) return;
          processApkFile(file);
        }

        async function processApkFile(file) {
          const btn = document.getElementById('scanBtn');
          btn.innerText = "Analyzing APK SAST...";
          btn.disabled = true;

          const formData = new FormData();
          formData.append("file", file);

          try {
            const res = await fetch('/api/scan-apk', { method: 'POST', body: formData });
            const data = await res.json();
            currentScanResult = data;
            document.getElementById('vendorSelect').value = "Android Client";
            renderTelemetry(data);
          } catch(e) {
            alert('APK Inspection Failed: ' + e);
          } finally {
            btn.innerText = "Execute Cryptographic Audit";
            btn.disabled = false;
          }
        }

        async function runScan() {
          const cfg = document.getElementById('cfg').value;
          const vendor = document.getElementById('vendorSelect').value;
          if (!cfg.trim()) {
            alert("Please paste or load a configuration first.");
            return;
          }
          const btn = document.getElementById('scanBtn');
          btn.innerText = "Processing Telemetry...";
          btn.disabled = true;
          
          try {
            const res = await fetch('/api/scan', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ raw_config: cfg, target_vendor: vendor })
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
            source_name: currentScanResult.source_name || "Exposure Telemetry"
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
          a.download = "VPNGuard_Exposure_Dossier.pdf";
          a.click();
        }

        function renderTelemetry(data) {
          const orb = document.getElementById('orbScore');
          const status = document.getElementById('orbStatus');
          orb.innerText = data.score;
          status.innerText = data.status;

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
            container.innerHTML = '<div class="text-xs text-emerald-400 font-mono py-4">✅ No cryptographic defects identified. Zero exposures detected.</div>';
          } else {
            container.innerHTML = data.findings.map(f => `
              <div class="p-3 rounded-lg bg-[#040614] border border-slate-800 flex flex-col gap-1">
                <div class="flex justify-between items-center">
                  <span class="text-xs font-semibold text-slate-200">${f.title}</span>
                  <span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${f.severity === 'Critical' ? 'bg-rose-500/10 text-rose-400' : 'bg-amber-500/10 text-amber-400'}">${f.severity}</span>
                </div>
                <p class="text-[11px] text-slate-400">${f.description}</p>
                <div class="flex gap-2 pt-1 font-mono text-[10px] text-slate-500">
                  <span>${f.nist}</span> &bull; <span>${f.pci_dss}</span>
                </div>
              </div>
            `).join('');
          }

          document.getElementById('remediationBox').innerText = data.ai_guidance;
        }
      </script>
    </body>
    </html>
    """
