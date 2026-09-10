import re

RULES = {
    "weak_ciphers": {
        "pattern": r"\b(3des|des)\b",
        "severity": "Critical",
        "deduction": 35,
        "title": "Legacy Symmetric Cipher (DES/3DES)",
        "desc": "Vulnerable to Sweet32 collision attacks (CVE-2016-2183).",
        "compliance": {
            "nist": "NIST SP 800-77 (Minimum AES-GCM-128)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        }
    },
    "weak_hashes": {
        "pattern": r"\b(md5|sha1)\b",
        "severity": "High",
        "deduction": 20,
        "title": "Broken Hash Function (MD5/SHA1)",
        "desc": "Cryptographically compromised integrity hashing.",
        "compliance": {
            "nist": "NIST SP 800-131A (Prohibits MD5/SHA-1)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.2"
        }
    },
    "ikev1": {
        "pattern": r"\bikev1\b",
        "severity": "High",
        "deduction": 20,
        "title": "Deprecated IKEv1 Protocol",
        "desc": "Lacks modern security optimizations, vulnerable to PSK offline cracking.",
        "compliance": {
            "nist": "NIST SP 800-77 (Mandates IKEv2)",
            "pci_dss": "PCI-DSS v4.0 Req 12.3.3"
        }
    },
    "aggressive_mode": {
        "pattern": r"\baggressive\b",
        "severity": "Critical",
        "deduction": 30,
        "title": "IKE Aggressive Mode Active",
        "desc": "Aggressive Mode transmits hashed PSK credentials unencrypted across the network.",
        "compliance": {
            "nist": "NIST SP 800-77 Rev. 1 (Section 4.1: Strictly Prohibited)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        }
    },
    "weak_dh": {
        "pattern": r"\bgroup\s*(1|2|5)\b",
        "severity": "High",
        "deduction": 15,
        "title": "Substandard DH Group (< 2048-bit)",
        "desc": "DH Groups 1, 2, and 5 can be solved with modern state-level computation.",
        "compliance": {
            "nist": "NIST SP 800-57 Part 1 (Minimum Group 14 / 2048-bit)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        }
    },
    "weak_psk": {
        "pattern": r"\b(key\s+(cisco|admin|password|123456|vpn))\b",
        "severity": "Critical",
        "deduction": 30,
        "title": "Default/Trivial Pre-Shared Key",
        "desc": "Dictionary-based pre-shared secret detected in plaintext configuration.",
        "compliance": {
            "nist": "NIST SP 800-63B (Memorized Secrets Minimum Entropy)",
            "pci_dss": "PCI-DSS v4.0 Req 8.3.6"
        }
    }
}

def analyze_raw_config(config_text: str):
    text = config_text.lower()
    findings = []
    score = 100

    for key, rule in RULES.items():
        if re.search(rule["pattern"], text):
            score -= rule["deduction"]
            findings.append({
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["desc"],
                "nist": rule["compliance"]["nist"],
                "pci_dss": rule["compliance"]["pci_dss"]
            })

    score = max(0, score)
    status = "Secure" if score >= 80 else ("Warning" if score >= 50 else "Critical")

    return {
        "score": score,
        "status": status,
        "findings": findings
    }
