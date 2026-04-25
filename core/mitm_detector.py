"""
Man-in-the-Middle Attack Detector
"""
import json
import os
import time
from collections import defaultdict
from scapy.all import ARP, Dot11Beacon, Dot11Elt, Dot11ProbeResp
import logging

logger = logging.getLogger(__name__)


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


class MITMDetector:
    
    def __init__(self, alert_manager, threshold=None, time_window=None, baseline_file=None):
        self.alert_manager = alert_manager
        self.threshold = threshold if threshold is not None else 50
        self.time_window = time_window if time_window is not None else 10
        self.arp_tracker = defaultdict(list)
        self.mac_ip_mapping = {}
        self.duplicate_ips: dict = {}
        self.alerted_macs: dict = {} 
        self.ARP_FLOOD_COOLDOWN = 60 
        self._arp_start_time: float = 0.0 
        self.ssid_bssid_map = defaultdict(set) 
        self.ssid_first_bssid = {}
        self.ssid_bssid_count = defaultdict(lambda: defaultdict(int)) 
        self.beacon_bssids = defaultdict(set)  
        self.alerted_evil_twins = set() 
        self.CONFIRM_THRESHOLD = 20 
        self.ROGUE_THRESHOLD   = 30 
        self.KARMA_PROBE_THRESHOLD = 5
        self.karma_probe_counts = defaultdict(lambda: defaultdict(int)) 

        self.POST_BASELINE_CONFIRM = 2 
        self.POST_BASELINE_ROGUE   = 10

        self.baseline_mode      = False
        self.baseline_end_time  = 0.0
        self.baseline_duration  = 0
        self.baseline_complete        = False 
        self._baseline_this_session  = False 
        self.baseline_ssids          = {} 

        self._baseline_file = baseline_file or 'baseline.json'
        self._load_baseline()

    def start_baseline(self, duration: int = 300):
        self.baseline_mode      = True
        self.baseline_end_time  = time.time() + duration
        self.baseline_duration  = duration
        self.baseline_complete  = False
        self.baseline_ssids     = {}
        self.ssid_bssid_map     = defaultdict(set)
        self.ssid_first_bssid   = {}
        self.ssid_bssid_count   = defaultdict(lambda: defaultdict(int))
        self.beacon_bssids      = defaultdict(set)
        self.alerted_evil_twins = set()
        self.karma_probe_counts = defaultdict(lambda: defaultdict(int))
        logger.info(f"Baseline learning mode started — duration: {duration}s")

    def _check_baseline_expiry(self):
        """Finalise the baseline when its timer expires."""
        if not self.baseline_mode:
            return
        if time.time() < self.baseline_end_time:
            return

        self.baseline_mode            = False
        self.baseline_complete        = True
        self._baseline_this_session  = True
        baseline_confirm = max(3, self.CONFIRM_THRESHOLD // 4)

        for ssid, bssid_counts in self.ssid_bssid_count.items():
            for bssid, count in bssid_counts.items():
                if count >= baseline_confirm:
                    if ssid not in self.baseline_ssids:
                        self.baseline_ssids[ssid] = set()
                    self.baseline_ssids[ssid].add(bssid.upper())

        self._save_baseline()
        ssid_count = len(self.baseline_ssids)
        logger.info(f"Baseline learning complete — {ssid_count} trusted SSIDs recorded")
        self.ssid_bssid_count = defaultdict(lambda: defaultdict(int))

        self.alert_manager.emit_alert(
            alert_type='BASELINE_COMPLETE',
            severity='info',
            message=f'Environment baseline complete — {ssid_count} trusted SSIDs mapped',
            data={
                'ssid_count': ssid_count,
                'ssids': list(self.baseline_ssids.keys()),
                'note': 'New or duplicate SSIDs appearing after this point will be flagged faster',
            }
        )

    def _save_baseline(self):
        try:
            serialisable = {ssid: list(bssids) for ssid, bssids in self.baseline_ssids.items()}
            with open(self._baseline_file, 'w') as fh:
                json.dump({'baseline_ssids': serialisable, 'saved_at': time.time()}, fh, indent=2)
            logger.info(f"Baseline saved to {self._baseline_file}")
        except Exception as e:
            logger.warning(f"Could not save baseline: {e}")

    def _load_baseline(self):
        if not os.path.exists(self._baseline_file):
            return
        try:
            with open(self._baseline_file) as fh:
                data = json.load(fh)
            raw = data.get('baseline_ssids', {})
            self.baseline_ssids    = {ssid: set(bssids) for ssid, bssids in raw.items()}
            self.baseline_complete = bool(self.baseline_ssids)
            logger.info(f"Baseline loaded from {self._baseline_file} — {len(self.baseline_ssids)} SSIDs")
        except Exception as e:
            logger.warning(f"Could not load baseline: {e}")

    def get_baseline_status(self) -> dict:
        remaining = max(0, int(self.baseline_end_time - time.time())) if self.baseline_mode else 0
        elapsed   = max(0, self.baseline_duration - remaining)       if self.baseline_mode else 0
        progress  = int(elapsed / self.baseline_duration * 100)      if self.baseline_mode and self.baseline_duration else 0
        return {
            'mode':           self.baseline_mode,
            'complete':       self.baseline_complete,
            'ssid_count':     len(self.baseline_ssids),
            'ssids':          list(self.baseline_ssids.keys()),
            'duration':       self.baseline_duration,
            'time_remaining': remaining,
            'progress':       progress,
        }

    @staticmethod
    def _extract_ssid(packet) -> str:
        try:
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    raw = elt.info
                    if not raw or all(b == 0 for b in raw):
                        return ''
                    if b'\x00' in raw:
                        return ''
                    ssid = raw.decode('utf-8', errors='ignore').strip()
                    if any(ord(c) < 32 for c in ssid):
                        return ''
                    if '?' in ssid:
                        return ''
                    printable = sum(1 for c in ssid if c.isprintable() and ord(c) >= 32)
                    if len(ssid) > 0 and printable / len(ssid) < 0.85:
                        return ''
                    return ssid
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return ''

    @staticmethod
    def _oui(mac: str) -> str:
        return mac.upper()[:8] if mac else ''

    def _is_truncated_baseline_ssid(self, ssid: str) -> bool:
        if not self.baseline_ssids:
            return False
        s_lower = ssid.lower()
        for known in self.baseline_ssids:
            k_lower = known.lower()
            if k_lower.startswith(s_lower) and len(known) > len(ssid):
                return True
            if s_lower.startswith(k_lower) and len(ssid) > len(known):
                return True
            max_len = max(len(s_lower), len(k_lower))
            if max_len > 0 and _levenshtein(s_lower, k_lower) / max_len < 0.40:
                return True
        return False

    def _check_evil_twin(self, packet):
        try:
            bssid = packet.addr2 or packet.addr3
            if not bssid:
                return
            ssid = self._extract_ssid(packet)
            if not ssid:
                return
            if len(ssid) < 4:
                return
            if len(ssid) < 8 and ssid[-1] in (' ', '-', '_'):
                return

            bssid_upper = bssid.upper()
            is_beacon = packet.haslayer(Dot11Beacon)

            if is_beacon:
                self.beacon_bssids[ssid].add(bssid_upper)
                if bssid_upper in self.karma_probe_counts.get(ssid, {}):
                    del self.karma_probe_counts[ssid][bssid_upper]

            self._check_baseline_expiry()

            if self.baseline_mode:
                self.ssid_bssid_count[ssid][bssid_upper] += 1
                return

            if not is_beacon:
                if self.baseline_complete and ssid in self.baseline_ssids:
                    if (bssid_upper not in self.baseline_ssids[ssid] and
                            bssid_upper not in self.beacon_bssids.get(ssid, set())):
                        self.karma_probe_counts[ssid][bssid_upper] += 1
                        probe_count = self.karma_probe_counts[ssid][bssid_upper]
                        if probe_count >= self.KARMA_PROBE_THRESHOLD:
                            karma_key = f"KARMA|{ssid}|{bssid_upper}"
                            if karma_key not in self.alerted_evil_twins:
                                self.alerted_evil_twins.add(karma_key)
                                self.alert_manager.emit_alert(
                                    alert_type='KARMA_ATTACK',
                                    severity='high',
                                    message=f'Possible Karma/MITM attack: probe response for "{ssid}" from AP not in baseline that has never beaconed this SSID',
                                    data={
                                        'ssid': ssid,
                                        'rogue_bssid': bssid_upper,
                                        'rogue_oui': self._oui(bssid_upper),
                                        'baseline_bssids': list(self.baseline_ssids[ssid]),
                                        'probe_response_count': probe_count,
                                        'attack_type': 'Karma — probe response without prior beacon',
                                        'confidence': 'High — BSSID absent from baseline and has never beaconed this SSID',
                                    }
                                )
                elif ssid in self.ssid_first_bssid:
                    if (bssid_upper not in self.ssid_bssid_map[ssid] and
                            bssid_upper not in self.beacon_bssids.get(ssid, set())):
                        self.karma_probe_counts[ssid][bssid_upper] += 1
                        probe_count = self.karma_probe_counts[ssid][bssid_upper]
                        if probe_count >= self.KARMA_PROBE_THRESHOLD:
                            karma_key = f"KARMA|{ssid}|{bssid_upper}"
                            if karma_key not in self.alerted_evil_twins:
                                self.alerted_evil_twins.add(karma_key)
                                self.alert_manager.emit_alert(
                                    alert_type='KARMA_ATTACK',
                                    severity='high',
                                    message=f'Possible Karma/MITM attack: probe response for "{ssid}" from BSSID that has never beaconed this SSID',
                                    data={
                                        'ssid': ssid,
                                        'rogue_bssid': bssid_upper,
                                        'rogue_oui': self._oui(bssid_upper),
                                        'confirmed_bssid': self.ssid_first_bssid[ssid],
                                        'probe_response_count': probe_count,
                                        'attack_type': 'Karma — probe response without prior beacon',
                                        'confidence': 'Medium — confirmed BSSID via beacons, this BSSID has never beaconed this SSID',
                                    }
                                )
                return  

            if self.baseline_complete and ssid in self.baseline_ssids:
                baseline_bssids = self.baseline_ssids[ssid]

                if bssid_upper in baseline_bssids:
                    self.ssid_bssid_map[ssid].add(bssid_upper)
                    if ssid not in self.ssid_first_bssid:
                        self.ssid_first_bssid[ssid] = bssid_upper
                    return

                self.ssid_bssid_count[ssid][bssid_upper] += 1
                count = self.ssid_bssid_count[ssid][bssid_upper]
                if count < self.POST_BASELINE_ROGUE:
                    return

                alert_key = f"{ssid}|{bssid_upper}"
                if alert_key not in self.alerted_evil_twins:
                    self.alerted_evil_twins.add(alert_key)
                    self.ssid_bssid_map[ssid].add(bssid_upper)
                    first_bssid = next(iter(baseline_bssids))
                    self.alert_manager.emit_alert(
                        alert_type='EVIL_TWIN',
                        severity='high',
                        message=f'Possible Evil Twin (post-baseline): "{ssid}" broadcast by AP not seen during environment scan',
                        data={
                            'ssid': ssid,
                            'baseline_bssids': list(baseline_bssids),
                            'rogue_bssid': bssid_upper,
                            'rogue_oui': self._oui(bssid_upper),
                            'rogue_beacon_count': count,
                            'attack_type': 'Evil Twin — BSSID absent from trusted baseline',
                            'confidence': 'High — SSID was mapped during environment scan, this BSSID was not',
                        }
                    )
                return

            if self.baseline_complete:
                confirm_thresh = self.POST_BASELINE_CONFIRM
                rogue_thresh   = self.POST_BASELINE_ROGUE
            else:
                confirm_thresh = self.CONFIRM_THRESHOLD
                rogue_thresh   = self.ROGUE_THRESHOLD

            self.ssid_bssid_count[ssid][bssid_upper] += 1
            count = self.ssid_bssid_count[ssid][bssid_upper]

            if ssid not in self.ssid_first_bssid:
                if count >= confirm_thresh:
                    self.ssid_first_bssid[ssid] = bssid_upper
                    self.ssid_bssid_map[ssid].add(bssid_upper)
                    if self.baseline_complete:
                        if self._is_truncated_baseline_ssid(ssid):
                            return
                        rogue_key = f"ROGUE_BEACON|{ssid}|{bssid_upper}"
                        if rogue_key not in self.alerted_evil_twins:
                            self.alerted_evil_twins.add(rogue_key)
                            self.alert_manager.emit_alert(
                                alert_type='ROGUE_BEACON',
                                severity='medium',
                                message=f'New SSID "{ssid}" appeared after environment baseline — possible rogue/lure AP',
                                data={
                                    'ssid': ssid,
                                    'bssid': bssid_upper,
                                    'oui': self._oui(bssid_upper),
                                    'beacon_count': count,
                                    'attack_type': 'Rogue beacon / fake lure AP',
                                    'confidence': 'Medium — SSID was absent from the trusted environment scan',
                                    'note': 'Could be a new legitimate AP or a rogue broadcasting fake SSIDs to lure clients',
                                }
                            )
                return 

            first_bssid = self.ssid_first_bssid[ssid]

            if bssid_upper == first_bssid or bssid_upper in self.ssid_bssid_map[ssid]:
                self.ssid_bssid_map[ssid].add(bssid_upper)
                return

            if count < rogue_thresh:
                return  

            alert_key = f"{ssid}|{bssid_upper}"
            self.ssid_bssid_map[ssid].add(bssid_upper)

            if alert_key not in self.alerted_evil_twins:
                self.alerted_evil_twins.add(alert_key)
                same_oui = self._oui(first_bssid) == self._oui(bssid_upper)
                self.alert_manager.emit_alert(
                    alert_type='EVIL_TWIN',
                    severity='high',
                    message=f'Possible Evil Twin: "{ssid}" broadcast by a second persistent AP ({count} beacons)',
                    data={
                        'ssid': ssid,
                        'legitimate_bssid': first_bssid,
                        'rogue_bssid': bssid_upper,
                        'legitimate_oui': self._oui(first_bssid),
                        'rogue_oui': self._oui(bssid_upper),
                        'rogue_beacon_count': count,
                        'attack_type': 'Evil Twin — possible MITM rogue AP',
                        'confidence': 'Low — same vendor OUI, could be a neighbour AP' if same_oui else 'Medium — different vendor OUI, confirm with RSSI/location',
                        'note': 'Same OUI — could be a neighbouring AP with the same network name.' if same_oui else 'Different vendor OUI broadcasting the same SSID persistently.',
                    }
                )
        except Exception as e:
            logger.debug(f"Evil twin check error: {e}")

    def analyze_packet(self, packet):
        if packet.haslayer(ARP) and not self.baseline_mode:
            self._check_arp(packet)
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            self._check_evil_twin(packet)

    def _check_arp(self, packet):
        if not packet.haslayer(ARP):
            return
            
        try:
            arp = packet[ARP]
            current_time = time.time()
            
            if arp.op == 2:
                ip = arp.psrc
                mac = arp.hwsrc
                if len(self.mac_ip_mapping) > 10000:
                    for _k in list(self.mac_ip_mapping.keys())[:5000]:
                        del self.mac_ip_mapping[_k]

                if ip in self.mac_ip_mapping:
                    existing_mac = self.mac_ip_mapping[ip]
                    if existing_mac != mac:
                        last_alert = self.duplicate_ips.get(ip, 0)
                        if time.time() - last_alert > 300:
                            self.alert_manager.emit_alert(
                                alert_type='ARP_SPOOFING',
                                severity='critical',
                                message=f'Potential ARP Spoofing Detected for IP {ip}',
                                data={
                                    'ip': ip,
                                    'original_mac': existing_mac,
                                    'spoofed_mac': mac,
                                    'note': 'Two different MAC addresses claiming same IP - possible MITM attack',
                                    'recommendation': 'Verify legitimate device MAC address'
                                }
                            )
                            self.duplicate_ips[ip] = time.time()
                            self.mac_ip_mapping[ip] = mac
                else:
                    self.mac_ip_mapping[ip] = mac
            
            if arp.op == 1: 
                src_mac = arp.hwsrc

                if not self._arp_start_time:
                    self._arp_start_time = current_time

                if (current_time - self._arp_start_time) < self.time_window:
                    pass  
                else:
                    self.arp_tracker[src_mac].append(current_time)

                    self.arp_tracker[src_mac] = [
                        t for t in self.arp_tracker[src_mac]
                        if current_time - t <= self.time_window
                    ]

                    count = len(self.arp_tracker[src_mac])
                    last_arp_alert = self.alerted_macs.get(src_mac, 0)
                    if count >= self.threshold and (current_time - last_arp_alert) >= self.ARP_FLOOD_COOLDOWN:
                        self.alert_manager.emit_alert(
                            alert_type='ARP_FLOOD',
                            severity='medium',
                            message=f'Possible ARP flood from {src_mac} ({count} requests in {self.time_window}s)',
                            data={
                                'source_mac': src_mac,
                                'request_count': count,
                                'time_window': self.time_window,
                                'note': 'May be normal network behavior - investigate if persistent'
                            }
                        )
                        self.alerted_macs[src_mac] = current_time
                        self.arp_tracker[src_mac] = []

            if len(self.alerted_macs) > 100:
                expired_macs = [m for m, t in self.alerted_macs.items()
                                if current_time - t >= self.ARP_FLOOD_COOLDOWN]
                for m in expired_macs:
                    del self.alerted_macs[m]
                    
        except Exception as e:
            logger.error(f"Error analyzing ARP packet: {e}")
    
    def get_stats(self):
        evil_twins = sum(
            1 for k in self.alerted_evil_twins
            if not k.startswith(('KARMA|', 'ROGUE_BEACON|'))
        )
        return {
            'tracked_macs': len(self.arp_tracker),
            'known_ip_mac_pairs': len(self.mac_ip_mapping),
            'duplicate_ips': len(self.duplicate_ips),
            'ssids_tracked': len(self.ssid_bssid_map),
            'evil_twins_detected': evil_twins,
            'wireless_threats': len(self.alerted_evil_twins),
            'threshold': self.threshold,
            'time_window': self.time_window,
            'baseline': self.get_baseline_status(),
        }
