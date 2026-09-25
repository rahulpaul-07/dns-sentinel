MITRE_MAPPING = {
    "T1071.004": {
        "Name": "Application Layer Protocol: DNS",
        "Description": "Adversaries may communicate with a C2 server using DNS for tunneling. Typically detected via high domain entropy indicating encoded blocks.",
        "Mitigation": "Implement Strict DNS firewall rules blocking lengthy subdomains. Route critical traffic through verified sinkholes."
    },
    "T1041": {
        "Name": "Exfiltration Over C2 Channel",
        "Description": "Rapid exfiltration detected over the current channel. Characterized by abnormal bursts of query frequency from a single internal IP.",
        "Mitigation": "Isolate the source endpoint IP immediately. Block external unverified name servers on edge firewalls."
    },
    "T1568": {
        "Name": "Dynamic Resolution / DGA",
        "Description": "Adversaries may use Domain Generation Algorithms (DGA) to evade blacklists. Identified by abnormally low n-gram structural probability.",
        "Mitigation": "Enable predictive DGA-blocking on internal DNS resolvers. Analyze endpoint processes calling out to unresolved domains."
    }
}

def map_threat(features, pred_label, iso_pred):
    """Map detections to MITRE ATT&CK techniques (rule-based on the extracted features)."""
    if pred_label == 0 and iso_pred == 1:
        return None
    
    mapping = {}
    entropy = features.get('entropy', 0)
    freq = features.get('frequency', 0)
    ngram_score = features.get('ngram_score', 1.0)
    unique_char = features.get('unique_char', 0)
    
    if entropy > 3.8 or unique_char > 0.8:
        mapping["T1071.004"] = MITRE_MAPPING["T1071.004"]
        
    if ngram_score < 0.01 or (iso_pred == -1 and entropy > 3.5):
         mapping["T1568"] = MITRE_MAPPING["T1568"]
    
    if freq > 30 and entropy > 3.0:
        mapping["T1041"] = MITRE_MAPPING["T1041"]
        
    return mapping

def generate_explanation(features, pred_label, iso_pred, risk_score):
    """Plain-language reasons for a score, built from the features that drove it."""
    if risk_score <= 30:
        return "No structural or behavioural indicators; consistent with normal resolution."
    
    reasons = []
    
    if iso_pred == -1:
        reasons.append("[Anomaly] Isolation Forest rates this name as an outlier relative to the training data.")
        
    if features.get('subdomain_length', 0) > 20 and features.get('entropy', 0) > 4.0:
        reasons.append(f"[Protocol] Subdomain contains high entropy encoded data typical of tunneling ({features['entropy']:.2f}).")
    elif features.get('entropy', 0) > 4.0:
        reasons.append(f"[Payload] High Shannon Entropy ({features['entropy']:.2f}) is consistent with encoded or random data.")
        
    if features.get('labels_max', 0) > 40:
        reasons.append(f"[Protocol] Unusually long DNS label detected ({features['labels_max']} chars). Long labels are typical of encoded tunnelling payloads.")
        
    if features.get('ngram_score', 1.0) < 0.01:
        reasons.append(f"[Structural] Domain has almost no common English bigrams ({features['ngram_score']:.4f}). Consistent with an algorithmically generated (DGA) name.")
        
    if features.get('frequency', 0) > 40:
        reasons.append(f"[Behavioral] Frequent queries to different or deeply nested domains from the same source IP ({features['frequency']} req/min) detected.")
        
    if features.get('max_continuous_consonants_len', 0) > 7:
        reasons.append(f"[Structural] Dense consonant blocks ({features['max_continuous_consonants_len']} in a row) are unusual for human-chosen names.")

    if not reasons:
        reasons.append("The Random Forest score is elevated, but no single structural indicator dominates.")
        
    return " ".join(reasons)
