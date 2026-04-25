"""
Deauthentication Packet Detector
"""
import time
from collections import defaultdict
from scapy.all import Dot11Deauth, Dot11
import logging

logger = logging.getLogger(__name__)


class DeauthDetector:
    
    def __init__(self, alert_manager, threshold=5, time_window=10, alert_cooldown=60):
        self.alert_manager = alert_manager
        self.threshold = threshold
        self.time_window = time_window
        self.alert_cooldown = alert_cooldown
        self.deauth_tracker = defaultdict(list)
        self.alerted_pairs: dict = {} 
        
    def analyze_packet(self, packet):
        if not packet.haslayer(Dot11Deauth):
            return
            
        try:
            src = packet.addr2
            dst = packet.addr1

            _BROADCAST = 'ff:ff:ff:ff:ff:ff'
            if not src or src.lower() == _BROADCAST:
                return

            current_time = time.time()
            
            key = f"{src}->{dst}"

            last_alerted = self.alerted_pairs.get(key)
            if last_alerted is not None:
                if current_time - last_alerted < self.alert_cooldown:
                    return
                del self.alerted_pairs[key]

            self.deauth_tracker[key].append(current_time)
            
            self.deauth_tracker[key] = [
                t for t in self.deauth_tracker[key]
                if current_time - t <= self.time_window
            ]

            if not self.deauth_tracker[key]:
                del self.deauth_tracker[key]
                return

            count = len(self.deauth_tracker[key])
            if count >= self.threshold:
                self.alert_manager.emit_alert(
                    alert_type='DEAUTH_ATTACK',
                    severity='high',
                    message=f'Deauthentication Attack: {count} packets in {self.time_window}s — {src} → {dst}',
                    data={
                        'source': src,
                        'destination': dst,
                        'packet_count': count,
                        'time_window': self.time_window,
                        'note': 'Attacker is forcibly disconnecting a device from its AP'
                    }
                )

                self.alerted_pairs[key] = current_time
                del self.deauth_tracker[key]
            
            logger.debug(f"Deauth packet: {src} -> {dst}")
            
        except Exception as e:
            logger.error(f"Error analyzing deauth packet: {e}")
    
    def get_stats(self):
        """Get deauth detection statistics"""
        now = time.time()

        expired = [k for k, t in self.alerted_pairs.items() if now - t >= self.alert_cooldown]
        for k in expired:
            del self.alerted_pairs[k]
        return {
            'tracked_pairs': len(self.deauth_tracker),
            'pairs_in_cooldown': len(self.alerted_pairs),
            'threshold': self.threshold,
            'time_window': self.time_window,
            'alert_cooldown': self.alert_cooldown,
        }
