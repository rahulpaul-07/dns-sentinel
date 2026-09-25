"""Per-source burst detection over a short sliding window."""
import time
from collections import OrderedDict, deque


class BehavioralAnalyzer:
    MAX_SOURCES = 10_000  # LRU bound on tracked source IPs

    def __init__(self, time_window=30):
        self.time_window = time_window
        self.ip_history = OrderedDict()

    def analyze(self, source_ip, domain):
        current_time = time.time()

        if source_ip not in self.ip_history:
            self.ip_history[source_ip] = deque(maxlen=200)
            if len(self.ip_history) > self.MAX_SOURCES:
                self.ip_history.popitem(last=False)
        self.ip_history.move_to_end(source_ip)

        history = self.ip_history[source_ip]
        history.append((current_time, domain))
        
        # Clean up old window
        while history and history[0][0] < current_time - self.time_window:
            history.popleft()
            
        freq = len(history)
        
        # Track Domain Diversity / Structuring
        domains = [h[1] for h in history]
        unique_domains = len(set(domains))
        
        burst_flag = freq > 10
        # If they are shooting out 10+ completely unique encoded subdomains in 30 seconds
        structured_burst = burst_flag and unique_domains >= (freq * 0.8) 
        
        score = 0
        explanation = ""
        if structured_burst:
            score += 30
            explanation = f"Structured Burst Activity Detected ({freq} distinct DNS requests in 30s window)."
        elif burst_flag:
            score += 15
            explanation = f"High Velocity Query Injection ({freq} rapid requests)."
            
        return {
            'window_frequency': freq,
            'burst_detected': burst_flag,
            'structured_burst': structured_burst,
            'behavior_score': score,
            'explanation': explanation
        }

# Global singleton
analyzer = BehavioralAnalyzer(time_window=30)
