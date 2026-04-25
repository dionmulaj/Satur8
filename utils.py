"""
Network Interface Helper
Utilities for managing network interfaces
"""
import subprocess
import logging
import netifaces

logger = logging.getLogger(__name__)


def get_available_interfaces():
    """Get list of available network interfaces"""
    try:
        interfaces = netifaces.interfaces()
        return [iface for iface in interfaces if iface != 'lo']
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return []


def get_interface_info(interface):
    """Get information about a specific interface"""
    try:
        addrs = netifaces.ifaddresses(interface)
        info = {
            'name': interface,
            'mac': None,
            'ipv4': None,
            'ipv6': None
        }
        
        if netifaces.AF_LINK in addrs:
            info['mac'] = addrs[netifaces.AF_LINK][0].get('addr')
        
        if netifaces.AF_INET in addrs:
            info['ipv4'] = addrs[netifaces.AF_INET][0].get('addr')
        
        if netifaces.AF_INET6 in addrs:
            info['ipv6'] = addrs[netifaces.AF_INET6][0].get('addr')
        
        return info
    except Exception as e:
        logger.error(f"Error getting interface info: {e}")
        return None


def is_monitor_mode(interface):
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True,
            text=True
        )
        return 'Mode:Monitor' in result.stdout
    except Exception as e:
        logger.error(f"Error checking monitor mode: {e}")
        return False


def enable_monitor_mode(interface):
    try:
        commands = [
            ['ip', 'link', 'set', interface, 'down'],
            ['iwconfig', interface, 'mode', 'monitor'],
            ['ip', 'link', 'set', interface, 'up']
        ]
        
        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode != 0:
                logger.error(f"Command failed: {' '.join(cmd)}")
                return False
        
        logger.info(f"Monitor mode enabled on {interface}")
        return True
    except Exception as e:
        logger.error(f"Error enabling monitor mode: {e}")
        return False


def disable_monitor_mode(interface):
    try:
        commands = [
            ['ip', 'link', 'set', interface, 'down'],
            ['iwconfig', interface, 'mode', 'managed'],
            ['ip', 'link', 'set', interface, 'up']
        ]
        
        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode != 0:
                logger.error(f"Command failed: {' '.join(cmd)}")
                return False
        
        logger.info(f"Monitor mode disabled on {interface}")
        return True
    except Exception as e:
        logger.error(f"Error disabling monitor mode: {e}")
        return False


def print_interface_list():
    interfaces = get_available_interfaces()
    
    print("\nAvailable Network Interfaces:\n")
    print(f"{'Interface':<15} {'MAC Address':<20} {'IPv4':<15} {'Monitor':<10}")
    print("-" * 70)
    
    for iface in interfaces:
        info = get_interface_info(iface)
        if info:
            monitor = "Yes" if is_monitor_mode(iface) else "No"
            print(f"{info['name']:<15} {info['mac'] or 'N/A':<20} "
                  f"{info['ipv4'] or 'N/A':<15} {monitor:<10}")
    
    print()


if __name__ == '__main__':
    print_interface_list()
