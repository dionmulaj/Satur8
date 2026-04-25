"""
Main Packet Sniffer Module
"""
import threading
import logging
import time
import subprocess
import platform
from collections import deque
from scapy.all import sniff, conf, Dot11, Dot11Elt, ARP, Dot11Beacon, Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp
from config import Config
from core.alert_manager import AlertManager
from core.deauth_detector import DeauthDetector
from core.mitm_detector import MITMDetector
from core.device_fingerprint import DeviceFingerprinter
from core import oui_db

logger = logging.getLogger(__name__)

import platform as _platform
if _platform.system() == 'Darwin':
    conf.use_pcap = True


def check_monitor_mode(interface: str) -> bool:
    try:
        if platform.system() == 'Darwin':
            result = subprocess.run(
                ['tcpdump', '-I', '-i', interface, '-c', '1', '--immediate-mode'],
                capture_output=True, timeout=3
            )
            return result.returncode in (0, 1)
        else:
            result = subprocess.run(
                ['iwconfig', interface],
                capture_output=True, text=True, timeout=5
            )
            return 'monitor' in result.stdout.lower()
    except subprocess.TimeoutExpired:
        return True
    except Exception as e:
        logger.debug(f"Could not check monitor mode: {e}")
        return False


def set_channel(interface: str, channel: int):
    try:
        if platform.system() == 'Darwin':
            logger.debug(f"Channel set skipped on macOS (airport removed): requested ch{channel}")
            return
        else:
            subprocess.run(
                ['iwconfig', interface, 'channel', str(channel)],
                capture_output=True, timeout=5
            )
            logger.debug(f"Set {interface} to channel {channel}")
    except Exception as e:
        logger.debug(f"Could not set channel: {e}")


class PacketSniffer:

    def __init__(self, interface=None):
        self.interface = interface or Config.INTERFACE
        self.running = False
        self.packet_count = 0
        self.sniffer_thread = None
        self.channel_hop_thread = None
        self.current_channel = Config.CHANNEL
        self.monitor_mode_active = False

        self.recent_packets = deque(maxlen=100)
        self._start_time: float = 0.0  

        self.alert_manager = AlertManager()

        self.deauth_detector = DeauthDetector(
            self.alert_manager,
            threshold=Config.DEAUTH_THRESHOLD,
            time_window=Config.DEAUTH_WINDOW
        )
        self.mitm_detector = MITMDetector(
            self.alert_manager,
            threshold=Config.ARP_THRESHOLD,
            time_window=Config.ARP_WINDOW,
            baseline_file=Config.BASELINE_FILE,
        )
        self.device_fingerprinter = DeviceFingerprinter(self.alert_manager)
        self.device_fingerprinter._mitm_detector = self.mitm_detector

        logger.info(f"PacketSniffer initialized on interface: {self.interface}")
    
    def packet_handler(self, packet):
        try:
            self.packet_count += 1

            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.recent_packets.append(packet_info)

            baseline_active = self.mitm_detector.baseline_mode

            if not baseline_active:
                self.deauth_detector.analyze_packet(packet)
            self.mitm_detector.analyze_packet(packet)
            self.device_fingerprinter.analyze_packet(packet)

        except Exception as e:
            logger.error(f"Error handling packet: {e}")

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
                    if '?' in ssid or any(ord(c) < 32 for c in ssid):
                        return ''
                    printable = sum(1 for c in ssid if c.isprintable() and ord(c) >= 32)
                    if len(ssid) > 0 and printable / len(ssid) < 0.85:
                        return ''
                    return ssid
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return ''

    def _extract_packet_info(self, packet):
        try:
            packet_info = {
                'timestamp': time.time(),
                'number': self.packet_count,
                'type': 'Unknown',
                'src': None,
                'dst': None,
                'info': '',
                'channel': self.current_channel
            }

            if packet.haslayer(Dot11):
                packet_info['src'] = packet.addr2
                packet_info['dst'] = packet.addr1

                if packet.haslayer(Dot11Beacon):
                    ssid = self._extract_ssid(packet)
                    if not ssid:
                        return None  # Skip hidden beacons
                    packet_info['type'] = 'Beacon'
                    packet_info['info'] = f'SSID: {ssid}'
                    return packet_info

                elif packet.haslayer(Dot11Deauth):
                    packet_info['type'] = 'Deauth'
                    reason_map = {
                        1: 'Unspecified', 2: 'Auth expired', 3: 'Leaving',
                        4: 'Inactivity', 6: 'Class 2 frame', 7: 'Class 3 frame'
                    }
                    try:
                        reason = reason_map.get(packet[Dot11Deauth].reason, f'Code {packet[Dot11Deauth].reason}')
                    except Exception:
                        reason = 'Unknown'
                    packet_info['info'] = f'Reason: {reason}'
                    return packet_info

                elif packet.haslayer(Dot11ProbeReq):
                    ssid = self._extract_ssid(packet)
                    packet_info['type'] = 'ProbeReq'
                    packet_info['info'] = f'Looking for: {ssid if ssid else "(any)"}' 
                    return packet_info

                elif packet.haslayer(Dot11ProbeResp):
                    ssid = self._extract_ssid(packet)
                    if not ssid:
                        return None
                    packet_info['type'] = 'ProbeResp'
                    packet_info['info'] = f'SSID: {ssid}'
                    return packet_info

                else:
                    return None

            elif packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info['type'] = 'ARP'
                packet_info['src'] = arp.hwsrc
                packet_info['dst'] = arp.hwdst

                if arp.op == 1:
                    packet_info['info'] = f'Who has {arp.pdst}? Tell {arp.psrc}'
                elif arp.op == 2:
                    packet_info['info'] = f'{arp.psrc} is at {arp.hwsrc}'

                return packet_info

            else:
                return None

        except Exception as e:
            logger.debug(f"Error extracting packet info: {e}")
            return None

    def start(self):
        if self.running:
            logger.warning("Sniffer already running")
            return

        logger.info(f"Starting packet capture on {self.interface} (channel {self.current_channel})")
        self.running = True
        self._start_time = time.time()

        self.mitm_detector._arp_start_time = 0.0

        self.deauth_detector.alerted_pairs = {}

        set_channel(self.interface, self.current_channel)

        self.sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniffer_thread.start()

        self.alert_manager.emit_alert(
            alert_type='SCAN_STARTED',
            severity='info',
            message=f'Packet capture started on {self.interface}',
            data={
                'interface': self.interface,
                'channel_hopping': Config.CHANNEL_HOP,
                'channel': self.current_channel,
                'platform': platform.system(),
            }
        )

        if oui_db.is_loaded():
            self.alert_manager.emit_alert(
                alert_type='OUI_DB_LOADED',
                severity='info',
                message=f'OUI database loaded — {oui_db.entry_count():,} vendor entries',
                data={
                    'entry_count': oui_db.entry_count(),
                    'source': oui_db.source_path(),
                }
            )
        else:
            self.alert_manager.emit_alert(
                alert_type='OUI_DB_MISSING',
                severity='low',
                message='OUI database not loaded — vendor identification unavailable',
                data={
                    'note': 'Place oui.txt in the project root and restart to enable vendor lookups',
                }
            )

        adapter_info = self.device_fingerprinter.check_adapter(self.interface)
        if adapter_info:
            logger.warning(f"Attack adapter detected on {self.interface}: {adapter_info['label']}")
            self.alert_manager.emit_alert(
                alert_type='SUSPICIOUS_ADAPTER',
                severity='high',
                message=f'Known attack/monitor adapter on capture interface {self.interface}: {adapter_info["label"]}',
                data={
                    'interface':  adapter_info['interface'],
                    'vid_pid':    adapter_info['vid_pid'],
                    'label':      adapter_info['label'],
                    'driver':     adapter_info['driver'],
                    'detected_by': adapter_info['method'],
                    'note': 'This is your own capture interface — reported for awareness, not a threat from a remote device',
                }
            )
        else:
            logger.info(f"Capture interface {self.interface}: no known attack-adapter match")

        if Config.CHANNEL_HOP and platform.system() != 'Darwin':
            self.channel_hop_thread = threading.Thread(target=self._hop_channels, daemon=True)
            self.channel_hop_thread.start()
            logger.info("Channel hopping enabled")
        elif Config.CHANNEL_HOP and platform.system() == 'Darwin':
            logger.info("Channel hopping skipped on macOS 14+ (airport binary removed). Scapy will capture all channels in monitor mode.")

    def _hop_channels(self):
        channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48]
        idx = 0
        while self.running:
            ch = channels[idx % len(channels)]
            self.current_channel = ch
            set_channel(self.interface, ch)
            time.sleep(Config.CHANNEL_HOP_INTERVAL)
            idx += 1

    def _sniff_packets(self):
        try:
            conf.verb = 0
            conf.use_pcap = True

            try:
                logger.info(f"Opening {self.interface} in monitor mode...")
                self.monitor_mode_active = True
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    store=False,
                    monitor=True,
                    stop_filter=lambda x: not self.running
                )
            except Exception as monitor_err:
                logger.warning(
                    f"Monitor mode unavailable on {self.interface} ({monitor_err}). "
                    "Falling back to standard capture — 802.11 frames will be limited."
                )
                self.monitor_mode_active = False
                self.alert_manager.emit_alert(
                    alert_type='MONITOR_MODE_FALLBACK',
                    severity='medium',
                    message=f'Monitor mode unavailable on {self.interface} — using standard capture',
                    data={
                        'interface': self.interface,
                        'error': str(monitor_err),
                        'impact': '802.11 management frames (Beacon, Deauth, ProbeReq) will not be captured',
                        'note': 'Disconnect from WiFi and run with sudo to enable monitor mode',
                    }
                )
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
        except PermissionError:
            logger.error("Permission denied. Please run with sudo/root privileges.")
            self.running = False
        except Exception as e:
            logger.error(f"Error in packet sniffer: {e}")
            self.running = False

    def stop(self):
        logger.info("Stopping packet capture")

        duration = int(time.time() - self._start_time) if self._start_time else 0
        mins, secs = divmod(duration, 60)
        duration_str = f'{mins}m {secs}s' if mins else f'{secs}s'
        self.alert_manager.emit_alert(
            alert_type='SCAN_STOPPED',
            severity='info',
            message=f'Packet capture stopped — {self.packet_count:,} packets in {duration_str}',
            data={
                'interface': self.interface,
                'packets_captured': self.packet_count,
                'session_duration_seconds': duration,
                'session_duration': duration_str,
            }
        )

        self.running = False

        if self.mitm_detector.baseline_mode:
            self.mitm_detector.baseline_mode     = False
            self.mitm_detector.baseline_end_time  = 0.0
            logger.info("Baseline scan cancelled (sniffer stopped)")

        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        if self.channel_hop_thread:
            self.channel_hop_thread.join(timeout=2)

    def get_stats(self):
        return {
            'packet_count': self.packet_count,
            'running': self.running,
            'interface': self.interface,
            'monitor_mode': self.monitor_mode_active,
            'current_channel': self.current_channel,
            'channel_hopping': Config.CHANNEL_HOP,
            'deauth': self.deauth_detector.get_stats(),
            'mitm': self.mitm_detector.get_stats(),
            'devices': self.device_fingerprinter.get_stats(),
            'alerts': self.alert_manager.get_stats(),
            'recent_packets': list(self.recent_packets)[-20:]
        }

    def register_alert_callback(self, callback):
        self.alert_manager.register_callback(callback)
