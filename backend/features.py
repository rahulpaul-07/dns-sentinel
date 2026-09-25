"""Structural feature extraction for DNS query names.

`FEATURE_ORDER` is the single source of truth for the model's input vector. The
trainer, the evaluator, the calibrator, the benchmark and the live API all build
their vectors through `feature_vector()`, so a reordering can never silently
desynchronise training from inference.
"""
import math
import re
from collections import Counter

# The 22-dimensional model input, in order. Changing this invalidates trained
# artifacts: retrain with `python -m backend.train`.
FEATURE_ORDER = [
    "entropy", "length", "subdomain_length", "ngram_score", "frequency",
    "consonant_ratio", "digit_ratio", "unique_char", "vowels_consonant_ratio",
    "max_continuous_numeric_len", "max_continuous_alphabet_len",
    "max_continuous_consonants_len", "max_continuous_same_char",
    "upper_count", "lower_count", "special_count", "labels", "labels_max",
    "labels_average", "entropy_to_length_ratio", "high_entropy_flag",
    "domain_complexity",
]

# Simple baseline bigram frequencies for 'normal' English-like structural domain representation
ENGLISH_BIGRAMS = {
    'er': 0.05, 'th': 0.05, 'in': 0.04, 'on': 0.03, 'an': 0.03, 're': 0.02, 
    'nd': 0.02, 'at': 0.02, 'en': 0.02, 'es': 0.02, 'of': 0.02, 'te': 0.02, 
    'ed': 0.02, 'or': 0.01, 'ti': 0.01, 'al': 0.01, 'is': 0.01, 'ng': 0.01,
    'co': 0.02, 'om': 0.03, 'ne': 0.01, 'et': 0.01, 'it': 0.01
}

def calculate_entropy(domain):
    """Calculates the Shannon Entropy of a domain name to measure randomness."""
    if not domain:
        return 0
    probs = [n/len(domain) for n in Counter(domain).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    return entropy

def calculate_ngram_score(domain, n=2):
    """Calculates bi-gram probability to determine if domain matches human language structures."""
    if not domain or len(domain) < n:
        return 0.01
    domain = domain.lower()
    ngrams = [domain[i:i+n] for i in range(len(domain)-n+1)]
    
    score = 0
    for ng in ngrams:
        # Base reward for known standard structural n-grams, penalize heavily unknown random characters
        score += ENGLISH_BIGRAMS.get(ng, 0.0001) 
    return score / len(ngrams)

def get_max_continuous_len(text, pattern):
    matches = re.findall(pattern, text)
    if not matches: return 0
    return max(len(m) for m in matches)

def get_max_continuous_same_char(text):
    if not text: return 0
    max_len = 1
    current_len = 1
    for i in range(1, len(text)):
        if text[i] == text[i-1]:
            current_len += 1
            max_len = max(max_len, current_len)
        else:
            current_len = 1
    return max_len

def extract_features(dns_record):
    """
    Extracts deep numerical features from a DNS record.
    record format: {'timestamp': ..., 'query': 'example.com', 'source_ip': '...'}
    """
    query = dns_record.get('query', '')
    query_lower = query.lower()
    
    # Extract structural components
    parts = query_lower.split('.')
    subdomain = parts[0] if len(parts) > 2 else ''
    
    # 1. Structural Randomness
    entropy = calculate_entropy(query)
    
    # 2. Length metrics
    length = len(query) if query else 0
    subdomain_length = len(subdomain)
    
    # 3. N-gram Analysis (DGA generated domains have extremely low structural n-gram similarity)
    ngram_score = calculate_ngram_score(query)
    
    # 4. Character Densities and Continuous sequences (Kaggle Dataset Parity)
    consonants = re.findall(r'[^aeiou0-9.-]', query_lower)
    vowels = re.findall(r'[aeiou]', query_lower)
    
    consonant_ratio = len(consonants) / (length or 1)
    digit_ratio = len(re.findall(r'[0-9]', query_lower)) / (length or 1)
    unique_char_ratio = len(set(query_lower)) / (length or 1)
    
    vowels_consonant_ratio = (len(vowels) / len(consonants)) if consonants else 0
    
    max_continuous_numeric_len = get_max_continuous_len(query_lower, r'[0-9]+')
    max_continuous_alphabet_len = get_max_continuous_len(query_lower, r'[a-z]+')
    max_continuous_consonants_len = get_max_continuous_len(query_lower, r'[^aeiou0-9.-]+')
    max_continuous_same_alphabet_len = get_max_continuous_same_char(re.sub(r'[^a-z]', '', query_lower))
    
    # 5. CIC-Bell-DNS-EXF-2021 Stateless Alignments
    upper_count = len(re.findall(r'[A-Z]', query))
    lower_count = len(re.findall(r'[a-z]', query))
    special_count = len(re.findall(r'[^a-zA-Z0-9]', query))
    
    labels = len(parts)
    labels_max = max((len(p) for p in parts), default=0)
    labels_average = sum(len(p) for p in parts) / (labels or 1)
    
    # 6. Advanced Multidimensional Polynomials
    safe_length = length if length > 0 else 1
    entropy_to_length_ratio = entropy / safe_length
    high_entropy_flag = 1 if entropy > 3.8 else 0
    domain_complexity = (safe_length * entropy) - (ngram_score * 10)
    
    return {
        'entropy': entropy,
        'length': length,
        'subdomain_length': subdomain_length,
        'ngram_score': ngram_score,
        'consonant_ratio': consonant_ratio,
        'digit_ratio': digit_ratio,
        'unique_char': unique_char_ratio,
        'vowels_consonant_ratio': vowels_consonant_ratio,
        'max_continuous_numeric_len': max_continuous_numeric_len,
        'max_continuous_alphabet_len': max_continuous_alphabet_len,
        'max_continuous_consonants_len': max_continuous_consonants_len,
        'max_continuous_same_char': max_continuous_same_alphabet_len,
        'upper_count': upper_count,
        'lower_count': lower_count,
        'special_count': special_count,
        'labels': labels,
        'labels_max': labels_max,
        'labels_average': labels_average,
        'entropy_to_length_ratio': entropy_to_length_ratio,
        'high_entropy_flag': high_entropy_flag,
        'domain_complexity': domain_complexity
    }


def feature_vector(features: dict, frequency: float = 1) -> list:
    """Order an `extract_features()` dict into the model's input vector.

    `frequency` is the per-source query rate. Offline datasets have no temporal
    context, so training uses the same default of 1 that a first-seen source
    gets at inference time.
    """
    merged = {**features, "frequency": features.get("frequency", frequency)}
    return [merged[name] for name in FEATURE_ORDER]


def vectorize(domain: str, frequency: float = 1) -> list:
    """Convenience: raw domain string -> model input vector."""
    return feature_vector(extract_features({"query": domain}), frequency)
