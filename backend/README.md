# IPSec Guard AI — Autonomous Cryptographic Posture Engine

An enterprise-grade security posture and automated remediation platform designed to audit IPsec configurations, mobile client packages (`.apk`), and network design architectures (`.pdf` / `.pptx`).

---

## Key Capabilities

- **Dual-Engine Hybrid Architecture:** 
  - **Zero-Hallucination Deterministic Core:** Identifies protocol flaws, weak Diffie-Hellman groups, and deprecated ciphers mapped strictly to NIST SP 800-77, NIST SP 800-131A, and PCI-DSS v4.0.
  - **Constrained AI Synthesis:** Uses optimized LLMs to translate mathematical findings into plain-English risk assessments and drop-in vendor CLI scripts.
- **Full-Lifecycle "Shift-Left" Auditing:**
  - **Architecture Reviews:** Ingests `.pdf` blueprints and `.pptx` presentations to catch outdated cryptographic requirements at the design stage.
  - **Gateway Posture:** Audits live configurations for Cisco IOS, Fortinet FortiOS, and StrongSwan (`.conf`, `.ovpn`).
  - **Mobile Endpoints:** Parses Android Dalvik bytecode (`classes.dex`) and manifests inside `.apk` clients to detect cleartext data leaks and obsolete ciphers.
- **Autonomous Remediation:** Generates copy-paste hardened configurations (IKEv2, AES-256-GCM, DH Group 14+) rather than just pointing out flaws.
- **Executive Reporting:** Generates audit-ready PDF compliance reports with non-technical risk explanations.

---

## Quickstart

### 1. Installation
```bash
git clone https://github.com/Pravallika-Cheekurthi/vpnguard-ai.git
cd vpnguard-ai/backend
pip install fastapi uvicorn python-dotenv pydantic requests pypdf python-pptx reportlab
