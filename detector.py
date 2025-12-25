import re
import math
from urllib.parse import urlparse
from collections import Counter

def calculate_entropy(text):
    if not text: return 0
    probs = [n/len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)

def analyze_url(url):
    raw_input = url.strip().lower()
    
    # --- 1. PHYSICAL STRUCTURAL SPECS ---
    has_https = raw_input.startswith("https://")
    has_www = "www." in raw_input
    domain_match = re.search(r'\.[a-z]{2,6}(/|$)', raw_input.split('//')[-1])
    has_proper_tld = bool(domain_match)
    
    clean_url = raw_input if ("://" in raw_input) else 'https://' + raw_input
    try:
        parsed = urlparse(clean_url)
        full_domain = parsed.netloc 
    except:
        return {"error": "Malformed URL Structure"}

    # --- 2. THE MULTI-LAYERED AUDIT ---
    score = 0
    forensic_report = []
    detected_threats = []

    # LAYER A: Security & Deception
    safety_keywords = ['secure', 'verify', 'login', 'auth', 'ssl', 'safe', 'bank', 'account']
    found_keywords = [w for w in safety_keywords if w in raw_input]
    
    if not has_https:
        score += 20
        if found_keywords:
            score += 30
            detected_threats.append("Social Engineering")
            forensic_report.append({
                "type": "Deception", 
                "obs": "False Security Context", 
                "thought": f"URL uses trust keywords ({', '.join(found_keywords)}) while lacking encryption."
            })
    
    # LAYER B: Entropy
    entropy = calculate_entropy(full_domain)
    if entropy > 3.8:
        score += 25
        detected_threats.append("Algorithmic Generation")
        forensic_report.append({"type": "Structure", "obs": "High Entropy", "thought": "Domain character distribution suggests bot-generated randomness."})

    # LAYER C: Identity
    brands = {'facebook': r'f.*a.*c.*e.*b.*o.*o.*k', 'paypal': r'p.*a.*y.*p.*a.*[l1i]', 'google': r'g.*o.*o.*g.*l.*e', 'amazon': r'a.*m.*a.*z.*o.*n'}
    brand_match = ""
    for brand, pattern in brands.items():
        if re.search(pattern, full_domain):
            if not (full_domain == f"{brand}.com" or full_domain.endswith(f".{brand}.com")):
                score += 50
                brand_match = brand
                detected_threats.append("Brand Impersonation")
                forensic_report.append({"type": "Identity", "obs": "Brand Mimicry", "thought": f"Structural patterns for '{brand}' detected in unauthorized segment."})
                break

    # LAYER D: Masking & TLD
    at_count = raw_input.count('@')
    risky_tlds = ['.xyz', '.top', '.zip', '.click', '.monster']
    if at_count > 0:
        score += 60
        detected_threats.append("Host Masking")
        forensic_report.append({"type": "Structure", "obs": "Host Masking (@)", "thought": "The '@' symbol is used to hide the actual destination host."})
    
    if any(full_domain.endswith(tld) for tld in risky_tlds):
        score += 30
        detected_threats.append("Low-Reputation TLD")
        forensic_report.append({"type": "Reputation", "obs": "Risky TLD", "thought": "Domain uses an extension with high correlation to phishing."})

    # --- 3. DYNAMIC OPINION GENERATOR ---
    risk_percent = min(score, 100)
    if risk_percent > 70:
        opinion = f"CRITICAL: This URL displays heavy signs of {', '.join(set(detected_threats))}. The structure is intentionally deceptive."
    elif risk_percent > 30:
        opinion = f"WARNING: Audit identified unusual patterns including {detected_threats[0] if detected_threats else 'unverified protocols'}. Proceed with caution."
    else:
        opinion = "CLEAN: URL conforms to standard architecture. No impersonation or masking signatures were identified."

    return {
        "risk_score": risk_percent,
        "verdict": "Anomalous" if risk_percent > 65 else "Irregular" if risk_percent > 25 else "Standard",
        "forensic_report": forensic_report,
        "neutral_opinion": opinion,
        "specs": {
            "length": len(raw_input),
            "has_https": "Detected" if has_https else "Missing",
            "has_www": "Detected" if has_www else "Missing",
            "has_tld": "Standard" if has_proper_tld else "Non-Standard"
        }
    }