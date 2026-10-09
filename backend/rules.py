import re

def analyze_raw_config(config_text: str):
    findings = []
    
    # Check for empty or non-cryptographic inputs
    if not config_text or len(config_text.strip()) < 10:
        return {
            "score": 100,
            "status": "Secure",
            "findings": []
        }

    cfg = config_text.lower()
    
    # Granular penalty tracking
    penalty = 0

    # 1. Deprecated Symmetric Ciphers (DES / 3DES / RC4 / Blowfish)
    if re.search(r'\b(3des|des|des-cbc|3des-cbc|rc4|blowfish)\b', cfg):
        penalty += 25
        findings.append({
            "severity": "Critical",
            "title": "Legacy Symmetric Cipher (DES/3DES/RC4)",
            "description": "64-bit block cipher vulnerable to Sweet32 collision attacks (CVE-2016-2183).",
            "nist": "NIST SP 800-77 (Min AES-GCM-128)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        })

    # 2. Broken Hash Functions (MD5 / SHA-1)
    if re.search(r'\b(hash md5|md5|sha1|hash sha1|sha-1)\b', cfg):
        penalty += 15
        findings.append({
            "severity": "High",
            "title": "Broken Hash Function (MD5/SHA1)",
            "description": "Cryptographically compromised integrity hashing vulnerable to collision attacks.",
            "nist": "NIST SP 800-131A (Prohibits MD5/SHA1)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.2"
        })

    # 3. Aggressive Mode Handshake
    if re.search(r'\b(aggressive|aggressive-mode)\b', cfg):
        penalty += 20
        findings.append({
            "severity": "Critical",
            "title": "IKE Aggressive Mode Active",
            "description": "Aggressive Mode transmits authentication hashes unencrypted across transit paths.",
            "nist": "NIST SP 800-77 Rev. 1 (Sec 4.1: Prohibited)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        })

    # 4. Weak Diffie-Hellman Groups (< 2048-bit)
    if re.search(r'\b(group 1|group 2|group 5|modp768|modp1024|modp1536)\b', cfg):
        penalty += 15
        findings.append({
            "severity": "High",
            "title": "Substandard DH Group (< 2048-bit)",
            "description": "Legacy DH groups 1, 2, and 5 do not meet modern cryptanalytic resistance thresholds.",
            "nist": "NIST SP 800-57 Part 1 (Min Group 14 / 2048-bit)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        })

    # 5. Weak / Trivial Pre-Shared Key
    if re.search(r'\b(key cisco|key admin|key 123456|key password|key test|preshared-key cisco)\b', cfg):
        penalty += 15
        findings.append({
            "severity": "Critical",
            "title": "Default / Trivial Pre-Shared Key",
            "description": "Dictionary-based shared secret detected in configuration parameters.",
            "nist": "NIST SP 800-63B (Entropy Requirements)",
            "pci_dss": "PCI-DSS v4.0 Req 8.3.6"
        })

    # 6. Legacy Protocol Version (IKEv1)
    if re.search(r'\b(isakmp|ikev1)\b', cfg) and not re.search(r'\bikev2\b', cfg):
        penalty += 10
        findings.append({
            "severity": "Medium",
            "title": "Legacy Protocol Implementation (IKEv1)",
            "description": "IKEv1 lacks native cookie protections against amplification and resource exhaustion attacks.",
            "nist": "NIST SP 800-77 Rev. 1 (Recommends IKEv2)",
            "pci_dss": "PCI-DSS v4.0 Req 4.2.1"
        })

    # Calculate final proportional score
    if not findings:
        score = 100
        status = "Secure"
    else:
        # Score decreases proportionally with penalties
        raw_score = 100 - penalty
        # Ensure that even severely flawed configurations show a realistic percentage (e.g., 15%-30%) rather than a flat 0
        score = max(15, raw_score)
        
        if score >= 80:
            status = "Secure"
        elif score >= 50:
            status = "Warning"
        else:
            status = "Critical"

    return {
        "score": score,
        "status": status,
        "findings": findings
    }
