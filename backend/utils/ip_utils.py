import ipaddress

def is_valid_ip(ip: str) -> bool:
    """
    Checks if the given string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ip_version(ip: str) -> int:
    """
    Returns the version of the IP address (4 or 6), or None if invalid.
    """
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None

def normalize_ip(ip: str) -> str:
    """
    Returns a standardized format for the given IP address.
    """
    try:
        return ipaddress.ip_address(ip).exploded
    except ValueError:
        return ip
