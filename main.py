#!/usr/bin/env python3
"""
Satur8 - WiFi Security Monitor
Main entry point
"""
import sys
import logging
import signal
from config import Config
from core.packet_sniffer import PacketSniffer
from web.app import set_sniffer, run_server

# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def check_root():
    """Check if running with root privileges"""
    import os
    if os.geteuid() != 0:
        logger.error("This script must be run as root for packet capture")
        print("\n[ERROR] Root privileges required")
        print("Please run with: sudo python main.py\n")
        sys.exit(1)


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nShutting down Satur8...")
    logger.info("Received shutdown signal")
    sys.exit(0)


def print_banner():
    """Print startup banner"""
    banner = """
    ╔═══════════════════════════════════════╗
    ║                                       ║
    ║            SATUR8                     ║
    ║      WiFi Security Monitor            ║
    ║                                       ║
    ║  Real-time Detection:                 ║
    ║   • MITM Attacks                      ║
    ║   • Deauth Packets                    ║
    ║   • WiFi Pineapples                   ║
    ║   • Alpha Adapters                    ║
    ║                                       ║
    ╚═══════════════════════════════════════╝
    
    Interface: {interface}
    Web Dashboard: http://{host}:{port}
    
    [!] Educational purposes only
    [!] Authorized testing only
    
    """.format(
        interface=Config.INTERFACE,
        host=Config.HOST if Config.HOST != '0.0.0.0' else 'localhost',
        port=Config.PORT
    )
    print(banner)


def main():
    """Main entry point"""
    check_root()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print_banner()
    
    try:
        logger.info("Initializing packet sniffer...")
        sniffer = PacketSniffer(interface=Config.INTERFACE)
        
        set_sniffer(sniffer)
        
        logger.info("Sniffer ready. Use web dashboard to start monitoring.")
        
        logger.info("Starting web server...")
        run_server()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if 'sniffer' in locals():
            sniffer.stop()
        logger.info("Satur8 shutdown complete")


if __name__ == '__main__':
    main()
