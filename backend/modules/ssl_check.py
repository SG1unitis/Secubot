import socket
import ssl
from datetime import datetime

from modules.intelligence import extraire_hote


def check_ssl_age(target_url: str) -> tuple[bool, int, str]:
    """
    Récupère le certificat SSL et calcule son âge.
    Retourne : est_recent, age_en_jours, message.
    """
    domain = extraire_hote(target_url)

    if not domain:
        return False, 0, ""

    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_dict = ssock.getpeercert()

                if "notBefore" not in cert_dict:
                    return False, 0, ""

                not_before = datetime.strptime(
                    cert_dict["notBefore"],
                    "%b %d %H:%M:%S %Y %Z",
                )
                age = (datetime.utcnow() - not_before).days

                if age < 7:
                    return True, age, f"Certificat très récent ({age} jour(s))."
                if age < 30:
                    return True, age, f"Certificat récent ({age} jour(s))."

                return False, age, f"Âge du certificat rassurant ({age} jour(s))."

    except ssl.SSLCertVerificationError:
        return True, 0, "Certificat SSL invalide ou auto-signé."
    except Exception:
        return True, 0, "Impossible de vérifier le SSL."

    return False, 0, ""