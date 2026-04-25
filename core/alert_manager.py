"""
Alert Manager - Handles all security alerts and notifications
"""
import time
from collections import deque
from datetime import datetime
from typing import Dict, List, Callable
import logging

logger = logging.getLogger(__name__)


class AlertManager:
    
    def __init__(self):
        self.alerts: deque = deque(maxlen=1000)
        self.callbacks: List[Callable] = []
        
    def register_callback(self, callback: Callable):
        self.callbacks.append(callback)
        
    def emit_alert(self, alert_type: str, severity: str, message: str, data: Dict = None):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message,
            'data': data or {}
        }
        
        self.alerts.append(alert)
        logger.warning(f"[{severity.upper()}] {alert_type}: {message}")
        
        for callback in self.callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
                
    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        return list(self.alerts)[-limit:]
    
    def clear_alerts(self):
        self.alerts.clear()
        
    _SYSTEM_TYPES = frozenset({
        'BASELINE_COMPLETE', 'SCAN_STARTED', 'SCAN_STOPPED',
        'MONITOR_MODE_FALLBACK', 'OUI_DB_LOADED', 'OUI_DB_MISSING',
    })

    def get_stats(self) -> Dict:
        stats = {
            'total': 0,
            'by_type': {},
            'by_severity': {}
        }

        for alert in self.alerts:
            alert_type = alert['type']
            if alert_type in self._SYSTEM_TYPES:
                continue
            severity = alert['severity']
            stats['total'] += 1
            stats['by_type'][alert_type] = stats['by_type'].get(alert_type, 0) + 1
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

        return stats
