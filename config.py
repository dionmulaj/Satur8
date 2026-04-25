"""
Configuration module for Satur8
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    
    INTERFACE = os.getenv('INTERFACE', 'wlan0')
    
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 1472))
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    CHANNEL = int(os.getenv('CHANNEL', 6))          
    CHANNEL_HOP = os.getenv('CHANNEL_HOP', 'true').lower() == 'true'  
    CHANNEL_HOP_INTERVAL = float(os.getenv('CHANNEL_HOP_INTERVAL', 0.5))  

    DEAUTH_THRESHOLD = int(os.getenv('DEAUTH_THRESHOLD', 15)) 
    DEAUTH_WINDOW = 10 

    ARP_THRESHOLD = int(os.getenv('ARP_THRESHOLD', 200)) 
    ARP_WINDOW = int(os.getenv('ARP_WINDOW', 10)) 

    # Baseline environment scan
    BASELINE_DURATION = int(os.getenv('BASELINE_DURATION', 300))
    BASELINE_FILE = os.getenv('BASELINE_FILE', 'baseline.json')

    BEACON_THRESHOLD = 3
    BEACON_WINDOW = 30
    KARMA_PROBE_THRESHOLD = 4
    
    SUSPICIOUS_OUIS = [
        '00:13:37',  # Common Pineapple OUI (Hak5)
        'D8:EB:46',  # Another Pineapple variant
        '00:C0:CA',  # Hak5 devices
        '00:8F:DF',  # Some Pineapple Nano units
        '6C:E8:73',  # Some Pineapple units
        '00:0C:43',  # Ralink (often used in Pineapple)
        '00:0F:00',  # Some attack adapters
    ]
    
    ALPHA_ADAPTERS = [
        'Realtek',
        'ALFA Network',
        'RTL8812AU',
        'RTL8187',
    ]
    
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'satur8.log'
