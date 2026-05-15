import math
from collections import Counter, deque
import config

class AnomalyDetector:
    def __init__(self):
        self.recent_dsts = deque(maxlen=config.ENTROPY_WINDOW)
        self.last_id = 0

    def update_entropy_window(self, packet_list):
        if not packet_list:
            return
        
        for pkt in packet_list:
            self.recent_dsts.append(pkt['dst'])
        
        batch_max = max(pkt['id'] for pkt in packet_list)
        if batch_max > self.last_id:
            self.last_id = batch_max

    def calculate_entropy(self):
        if len(self.recent_dsts) == 0:
            return 0.0
        
        counts = Counter(self.recent_dsts)
        total = len(self.recent_dsts)
        probs = [count / total for count in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        return entropy