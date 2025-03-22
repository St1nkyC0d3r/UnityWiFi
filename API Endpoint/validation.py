import os
from flask import Flask, request, g
from flask_restful import Api, Resource
from psycopg2 import connect, extras
from psycopg2.pool import ThreadedConnectionPool
from jwt import encode, decode
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from typing import Tuple, Dict, Any
import bcrypt
from urllib.parse import urlparse, parse_qs
from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow
from flasgger import Swagger  # Import Swagger

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


