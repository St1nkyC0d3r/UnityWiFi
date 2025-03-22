import re
from urllib.parse import urlparse
from app.utils.database import get_db_connection, put_db_connection
from app.utils.exceptions import APIException

def validate_unique_bssid_ssid(ssid, bssid):
    """
    Checks if a BSSID and SSID combination is unique in the database.

    Args:
        ssid (str): The SSID to check.
        bssid (str): The BSSID to check.

    Raises:
        APIException: If the BSSID and SSID combination is not unique.
    """
    conn, cursor = get_db_connection()
    try:
        cursor.execute(
            "SELECT 1 FROM hotspots WHERE bssid = %s AND ssid = %s",
            (bssid, ssid),
        )
        if cursor.fetchone():
            raise APIException("A hotspot with this BSSID and SSID combination already exists.", 400)
    finally:
        put_db_connection(conn)


def is_valid_url(url: str) -> bool:
    """
    Checks if a given string is a valid URL.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False
    
def is_valid_bssid(bssid: str) -> bool:
    """
    Checks if a given string is a valid BSSID.
    """
    if not isinstance(bssid, str):
        return False
    parts = bssid.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        try:
            int(part, 16)
        except ValueError:
            return False
        if len(part) != 2:
            return False
    return True

def is_security_type_valid(security_type: str) -> bool:
    """
    Checks if a given string is a valid security type.
    """
    return security_type in ["WEP", "WPA", "WPA2", "WPA3", "None"]

def is_valid_email(email: str) -> bool:
    """
    Checks if a given string is a valid email address.
    """
    return ("@" in email) and ('.' in email.split("@")[1])

def is_network_authentication_type_valid(authentication_type: str) -> bool:
    """
    Checks if a given string is a valid network authentication type.
    """
    return authentication_type in ["EAP-SIM", "EAP-AKA", "EAP-TLS", "EAP-TTLS", "PEAP", "LEAP", "EAP-FAST", "EAP-PSK", "EAP-PWD", "EAP-IKEv2", "EAP-GTC", "EAP-MD5", "EAP-MSCHAPv2", "EAP-TLS", "EAP-TTLS", "PEAP", "LEAP", "EAP-FAST", "EAP-PSK", "EAP-PWD", "EAP-IKEv2", "EAP-GTC", "EAP-MD5", "EAP-MSCHAPv2"]
