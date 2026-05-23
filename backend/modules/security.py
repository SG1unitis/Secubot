import os
import ipaddress
from functools import wraps

from flask import request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def get_allowed_network():
    allowed_network = os.getenv("SECUBOT_ALLOWED_NETWORK", "192.168.1.0/24")
    return ipaddress.ip_network(allowed_network, strict=False)


def require_internal_network(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr or ""

        if client_ip in ["127.0.0.1", "::1"]:
            return f(*args, **kwargs)

        try:
            client_ip_obj = ipaddress.ip_address(client_ip)

            if client_ip_obj not in get_allowed_network():
                raise ValueError("Hors réseau")

        except ValueError:
            print(f"Tentative d'accès externe bloquée - IP: {client_ip}")
            return jsonify({
                "titre": "ACCÈS REFUSÉ",
                "texte": "Connexion rejetée. Ce service est uniquement accessible depuis le réseau interne.",
                "urlscan_uuid": None
            }), 403

        return f(*args, **kwargs)

    return decorated_function