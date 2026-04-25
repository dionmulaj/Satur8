"""
Device Fingerprinting Module - Detects WiFi Pineapples and Alpha Adapters
"""
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, Dot11ProbeReq, Dot11Deauth, conf
from config import Config
from collections import defaultdict
from core import oui_db
import json
import os
import platform
import re
import subprocess
import time
import logging

logger = logging.getLogger(__name__)

_ATTACK_ADAPTER_IDS: dict[str, str] = {
    '0bda:8187': 'Realtek RTL8187 (ALFA AWUS036H)',
    '0bda:8189': 'Realtek RTL8187B',
    '0bda:8812': 'Realtek RTL8812AU (ALFA AWUS036ACH / AWUS036AC)',
    '0bda:8813': 'Realtek RTL8814AU (ALFA AWUS1900)',
    '0bda:881a': 'Realtek RTL8812AU variant',
    '0bda:b812': 'Realtek RTL88x2AU',
    '0bda:a812': 'Realtek RTL8812AU (2.4/5 GHz dual-band)',
    '0cf3:9271': 'Qualcomm AR9271 (ALFA AWUS036NHA)',
    '0cf3:7015': 'Qualcomm AR9374 (ALFA AWUS036AC)',
    '148f:5370': 'Ralink RT5370 (ALFA AWUS036NH)',
    '148f:5572': 'Ralink RT5572',
    '148f:7601': 'MediaTek MT7601U',
    '148f:3070': 'Ralink RT3070',
    '148f:3572': 'Ralink RT3572',
    '2357:010c': 'TP-Link Archer T2U (RTL8811AU)',
    '2357:0107': 'TP-Link Archer T4U (RTL8812AU)',
    '7392:7811': 'Edimax EW-7811Un (RTL8188CUS)',
    '0e8d:7610': 'MediaTek MT7610U',
}

_ATTACK_DRIVER_NAMES: frozenset[str] = frozenset({
    'rtl8812au', 'rtl8814au', 'rtl88xxau', 'rtl8812cu',
    'rtl8187',   'rtl8192eu', 'rtl8821au', 'rtl8723bu',
    'rt2800usb', 'rt73usb',   'rt2500usb',
    'ath9k_htc', 'ath10k_usb',
    'mt7601u',   'mt76x2u',   'mt76x0u',
})


class DeviceFingerprinter:
    
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self._mitm_detector = None  
        self.detected_devices = set()
        self.discovered_devices = {}
        self.bssid_ssid_map = defaultdict(lambda: defaultdict(int))
        self.probe_responses = defaultdict(lambda: defaultdict(int))
        self.client_probes = defaultdict(set)
        self.alerted_ouis = set()
        self.MIN_SSID_REPEATS = 5
        self.suspicious_ssids = [
            'Pineapple',
            'pineapple',
            'attwifi',
            'xfinitywifi',
            'Free Public WiFi',
            'HACKED',
            'Pwned',
            'evil_twin',
            'karma',
        ]
        
    def _confirmed_ssid_count(self, ssid_counter: dict) -> int:
        return len(self._confirmed_ssids(ssid_counter))

    def _confirmed_ssids(self, ssid_counter: dict) -> list:
        candidates = sorted(
            [s for s, c in ssid_counter.items() if c >= self.MIN_SSID_REPEATS],
            key=len, reverse=True,
        )
        accepted = []
        for ssid in candidates:
            if not self._is_ssid_variant(ssid, accepted):
                accepted.append(ssid)
        return accepted

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return DeviceFingerprinter._levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(
                    prev[j + 1] + 1, 
                    curr[j] + 1, 
                    prev[j] + (c1 != c2),
                ))
            prev = curr
        return prev[-1]

    @staticmethod
    def _is_ssid_variant(candidate: str, existing: list) -> bool:
        for known in existing:
            if known.startswith(candidate) or candidate.startswith(known):
                return True
            max_len = max(len(known), len(candidate))
            if max_len == 0:
                continue
            dist = DeviceFingerprinter._levenshtein(candidate, known)
            if dist / max_len < 0.3:
                return True
        return False


    _MAX_VENDOR_LEN = 30

    def _get_vendor(self, mac: str) -> str:
        vendor = oui_db.lookup(mac)
        if vendor == 'Unknown':
            try:
                short = conf.manufdb._get_manuf(mac) or ''
                long_ = conf.manufdb._get_manuf_long(mac) or ''
                vendor = long_ or short or 'Unknown'
            except Exception:
                vendor = 'Unknown'
        if len(vendor) > self._MAX_VENDOR_LEN:
            vendor = vendor[:self._MAX_VENDOR_LEN - 1].rstrip() + '…'
        return vendor

    @staticmethod
    def _is_random_mac(mac: str) -> bool:
        try:
            return bool(int(mac.replace(':', '')[1], 16) & 2)
        except Exception:
            return False

    def _extract_ssid(self, packet) -> str:
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
                    if '?' in ssid:
                        return ''
                    if any(ord(c) < 32 for c in ssid):
                        return ''
                    printable = sum(1 for c in ssid if c.isprintable() and ord(c) >= 32)
                    if len(ssid) > 0 and printable / len(ssid) < 0.85:
                        return ''
                    if len(ssid) < 4:
                        return ''
                    if len(ssid) < 8 and ssid[-1] in (' ', '-', '_'):
                        return ''
                    return ssid
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return ''

    def _is_baseline_ssid_fuzzy(self, ssid: str) -> bool:
        if not self._mitm_detector or not self._mitm_detector.baseline_ssids:
            return False
        s_lower = ssid.lower()
        for known in self._mitm_detector.baseline_ssids:
            k_lower = known.lower()
            max_len = max(len(s_lower), len(k_lower))
            if max_len == 0:
                continue
            if self._levenshtein(s_lower, k_lower) / max_len < 0.40:
                return True
        return False

    def _is_baseline_ssid(self, ssid: str) -> bool:
        if not self._mitm_detector:
            return False
        return ssid in self._mitm_detector.baseline_ssids

    def _is_baseline_bssid(self, ssid: str, bssid: str) -> bool:
        if not self._mitm_detector:
            return False
        trusted = self._mitm_detector.baseline_ssids.get(ssid)
        if not trusted:
            return False
        return bssid.upper() in trusted

    def _is_baseline_active(self) -> bool:
        """Return True while baseline learning is in progress (suppress alerts)."""
        if not self._mitm_detector:
            return False
        return self._mitm_detector.baseline_mode

    def analyze_packet(self, packet):
        """Analyze packet for device fingerprinting"""
        if not packet.haslayer(Dot11):
            return

        try:
            current_time = time.time()

            if packet.addr2:
                mac = packet.addr2.upper()
                if mac not in self.discovered_devices:
                    self.discovered_devices[mac] = {
                        'mac': mac,
                        'vendor': self._get_vendor(mac),
                        'is_random': self._is_random_mac(mac),
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'packet_count': 0,
                        'ssids': set(),
                        'type': 'Unknown',
                        'role': 'Unknown',
                        'suspicious': False
                    }
                
                self.discovered_devices[mac]['last_seen'] = current_time
                self.discovered_devices[mac]['packet_count'] += 1
            
            if packet.addr2 and not self._is_baseline_active():
                mac = packet.addr2.upper()
                oui = mac[:8]  
                
                for suspicious_oui in Config.SUSPICIOUS_OUIS:
                    if oui.startswith(suspicious_oui.upper()):
                        device_key = f"oui_{mac}"
                        if device_key not in self.detected_devices and oui not in self.alerted_ouis:
                            self.detected_devices.add(device_key)
                            self.alerted_ouis.add(oui)
                            if mac in self.discovered_devices:
                                self.discovered_devices[mac]['suspicious'] = True
                                self.discovered_devices[mac]['type'] = 'WiFi Pineapple (OUI)'
                            
                            self.alert_manager.emit_alert(
                                alert_type='SUSPICIOUS_DEVICE',
                                severity='critical',
                                message=f'WiFi Pineapple/Attack Device Detected via OUI match',
                                data={
                                    'mac': mac,
                                    'oui': oui,
                                    'device_type': 'WiFi Pineapple',
                                    'confidence': 'High'
                                }
                            )
            
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                bssid = packet.addr2 or packet.addr3
                if not bssid:
                    return

                ssid = self._extract_ssid(packet)

                if ssid and bssid:
                    self.bssid_ssid_map[bssid][ssid] += 1

                    if bssid in self.discovered_devices:
                        confirmed = self._confirmed_ssids(self.bssid_ssid_map[bssid])
                        self.discovered_devices[bssid]['ssids'] = set(confirmed)
                        self.discovered_devices[bssid]['type'] = 'Access Point'
                        self.discovered_devices[bssid]['role'] = 'Access Point'


                    if self._is_baseline_active():
                        return  # still collecting, don't alert
                    is_trusted = self._is_baseline_bssid(ssid, bssid)

                    if packet.haslayer(Dot11ProbeResp) and not is_trusted:
                        self.probe_responses[bssid][ssid] += 1

                        unique_probe_ssids = list(self.probe_responses[bssid].keys())
                        deduped_probes = []
                        for s in sorted(unique_probe_ssids, key=len, reverse=True):

                            if self._is_baseline_ssid_fuzzy(s):
                                continue
                            if not self._is_ssid_variant(s, deduped_probes):
                                deduped_probes.append(s)
                        probe_count = len(deduped_probes)

                        if probe_count >= Config.KARMA_PROBE_THRESHOLD:
                            device_key = f"karma_probe_{bssid}"
                            if device_key not in self.detected_devices:
                                self.detected_devices.add(device_key)
                                if bssid in self.discovered_devices:
                                    self.discovered_devices[bssid]['suspicious'] = True
                                    self.discovered_devices[bssid]['type'] = 'WiFi Pineapple (Karma/ProbeResp)'
                                self.alert_manager.emit_alert(
                                    alert_type='PINEAPPLE_KARMA',
                                    severity='critical',
                                    message=f'WiFi Pineapple Karma Detected - Responding to {probe_count} distinct probe SSIDs',
                                    data={
                                        'bssid': bssid,
                                        'ssid_count': probe_count,
                                        'ssids_responded_to': deduped_probes[:20],
                                        'attack_type': 'Karma - responds to all probe requests',
                                        'confidence': 'Very High'
                                    }
                                )

                    if not is_trusted:
                        ssid_count = self._confirmed_ssid_count(self.bssid_ssid_map[bssid])
                        if ssid_count >= Config.BEACON_THRESHOLD:
                            device_key = f"multi_ssid_{bssid}"
                            if device_key not in self.detected_devices:
                                self.detected_devices.add(device_key)
                                if bssid in self.discovered_devices:
                                    self.discovered_devices[bssid]['suspicious'] = True
                                    self.discovered_devices[bssid]['type'] = 'WiFi Pineapple (Multi-SSID)'
                                    self.discovered_devices[bssid]['role'] = 'Rogue AP'
                                self.alert_manager.emit_alert(
                                    alert_type='PINEAPPLE_MULTI_SSID',
                                    severity='critical',
                                    message=f'WiFi Pineapple Detected - Broadcasting {ssid_count} distinct SSIDs from one device',
                                    data={
                                        'bssid': bssid,
                                        'ssid_count': ssid_count,
                                        'ssids': self._confirmed_ssids(self.bssid_ssid_map[bssid])[:20],
                                        'attack_type': 'Evil Twin / Multi-SSID',
                                        'confidence': 'Very High'
                                    }
                                )

                    if not is_trusted:
                        for suspicious in self.suspicious_ssids:
                            if suspicious.lower() in ssid.lower():
                                device_key = f"ssid_{bssid}_{ssid}"
                                if device_key not in self.detected_devices:
                                    self.detected_devices.add(device_key)
                                    if bssid in self.discovered_devices:
                                        self.discovered_devices[bssid]['suspicious'] = True
                                    self.alert_manager.emit_alert(
                                        alert_type='SUSPICIOUS_SSID',
                                        severity='medium',
                                        message=f'Suspicious SSID: "{ssid}" matches known honeypot pattern',
                                        data={
                                            'ssid': ssid,
                                            'bssid': bssid,
                                            'matched_pattern': suspicious
                                        }
                                    )

            elif packet.haslayer(Dot11ProbeReq):
                client = packet.addr2
                if client:
                    ssid = self._extract_ssid(packet)
                    if client in self.discovered_devices:
                        if self.discovered_devices[client]['role'] == 'Unknown':
                            self.discovered_devices[client]['role'] = 'Station'
                        if self.discovered_devices[client]['type'] == 'Unknown':
                            self.discovered_devices[client]['type'] = 'Station'
                    if ssid and client in self.discovered_devices:
                        self.discovered_devices[client]['ssids'].add(f'[probe] {ssid}')
                        self.client_probes[client].add(ssid)

            elif packet.haslayer(Dot11Deauth):
                src = packet.addr2
                if src and src in self.discovered_devices:
                    self.discovered_devices[src]['type'] = 'Deauth Source'

        except Exception as e:
            logger.error(f"Error in device fingerprinting: {e}")


    MIN_DEVICE_PACKETS = 5

    def get_stats(self):
        devices_snapshot = list(self.discovered_devices.values())

        devices_list = [
            {
                'mac': info['mac'],
                'vendor': info.get('vendor', 'Unknown'),
                'is_random': info.get('is_random', False),
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'packet_count': info['packet_count'],
                'ssids': list(info['ssids']),
                'type': info['type'],
                'role': info.get('role', 'Unknown'),
                'suspicious': info['suspicious'],
            }
            for info in devices_snapshot
            if info['packet_count'] >= self.MIN_DEVICE_PACKETS
        ]

        suspicious_count = sum(
            1 for d in devices_snapshot if d['suspicious']
        )
        return {
            'detected_devices': len(self.detected_devices),
            'monitored_ouis': len(Config.SUSPICIOUS_OUIS),
            'discovered_devices': devices_list,
            'total_discovered': len(devices_list), 
            'suspicious_count': suspicious_count,
        }

    def check_adapter(self, interface_name: str) -> dict | None:
        try:
            if platform.system() == 'Linux':
                return self._check_adapter_linux(interface_name)
            elif platform.system() == 'Darwin':
                return self._check_adapter_macos(interface_name)
        except Exception as e:
            logger.debug(f'Adapter check error: {e}')
        return None


    def _check_adapter_linux(self, iface: str) -> dict | None:
        result = self._linux_sysfs(iface)
        if result:
            return result
        return self._linux_ethtool(iface)

    def _linux_sysfs(self, iface: str) -> dict | None:
        base = f'/sys/class/net/{iface}/device'
        if not os.path.exists(base):
            return None

        path = os.path.realpath(base)
        for _ in range(5):
            vid_path = os.path.join(path, 'idVendor')
            pid_path = os.path.join(path, 'idProduct')
            if os.path.isfile(vid_path) and os.path.isfile(pid_path):
                try:
                    with open(vid_path) as f:
                        vid = f.read().strip().lower()
                    with open(pid_path) as f:
                        pid = f.read().strip().lower()
                    vid_pid = f'{vid}:{pid}'
                    label = _ATTACK_ADAPTER_IDS.get(vid_pid)
                    if label:
                        return {
                            'interface': iface,
                            'vid_pid':   vid_pid,
                            'label':     label,
                            'driver':    self._linux_driver_name(iface),
                            'method':    'sysfs USB id',
                        }
                except OSError:
                    pass
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        return None

    def _linux_driver_name(self, iface: str) -> str:
        try:
            driver_link = f'/sys/class/net/{iface}/device/driver'
            if os.path.islink(driver_link):
                return os.path.basename(os.readlink(driver_link))
        except OSError:
            pass
        return 'unknown'

    def _linux_ethtool(self, iface: str) -> dict | None:
        try:
            out = subprocess.check_output(
                ['ethtool', '-i', iface],
                stderr=subprocess.DEVNULL, timeout=3, text=True,
            )
            for line in out.splitlines():
                if line.startswith('driver:'):
                    driver = line.split(':', 1)[1].strip().lower()
                    if driver in _ATTACK_DRIVER_NAMES:
                        return {
                            'interface': iface,
                            'vid_pid':   'unknown',
                            'label':     f'Known pentest driver: {driver}',
                            'driver':    driver,
                            'method':    'ethtool driver name',
                        }
        except (FileNotFoundError, subprocess.TimeoutExpired,
                subprocess.CalledProcessError):
            pass
        return None


    def _check_adapter_macos(self, iface: str) -> dict | None:
        try:
            raw = subprocess.check_output(
                ['system_profiler', 'SPUSBDataType', '-json'],
                stderr=subprocess.DEVNULL, timeout=10, text=True,
            )
            data = json.loads(raw)
            for entry in self._iter_usb_items(data.get('SPUSBDataType', [])):
                vid = entry.get('vendor_id', '').replace('0x', '').lower().zfill(4)
                pid = entry.get('product_id', '').replace('0x', '').lower().zfill(4)
                if not vid or not pid:
                    continue
                vid_pid = f'{vid}:{pid}'
                label = _ATTACK_ADAPTER_IDS.get(vid_pid)
                if label:
                    return {
                        'interface': iface,
                        'vid_pid':   vid_pid,
                        'label':     label,
                        'driver':    entry.get('_name', 'unknown'),
                        'method':    'macOS system_profiler',
                    }
        except (FileNotFoundError, subprocess.TimeoutExpired,
                json.JSONDecodeError, subprocess.CalledProcessError):
            pass
        return None

    def _iter_usb_items(self, nodes: list):
        for node in nodes:
            if isinstance(node, dict):
                yield node
                yield from self._iter_usb_items(node.get('_items', []))
