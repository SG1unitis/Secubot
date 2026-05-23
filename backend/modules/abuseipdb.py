import os
import ipaddress
import requests


def is_ip_address(observable: str) -> bool:
    """Vérifie si la chaîne est une adresse IP valide."""
    try:
        ipaddress.ip_address(observable)
        return True
    except ValueError:
        return False


def check_ip_reputation(ip_address_value: str) -> tuple[int, str]:
    """
    Interroge AbuseIPDB.
    Retourne le score d'abus et un message lisible.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return 0, "Clé AbuseIPDB non configurée."

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }
    params = {
        "ipAddress": ip_address_value,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)

        if response.status_code != 200:
            return 0, f"Erreur AbuseIPDB HTTP {response.status_code}."

        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        if score >= 50:
            return score, f"IP malveillante : score AbuseIPDB {score}% ({reports} signalement(s))."

        if score > 0:
            return score, f"IP suspecte : score AbuseIPDB {score}% ({reports} signalement(s))."

        return score, "IP clean selon AbuseIPDB."

    except requests.RequestException as e:
        print(f"[!] Erreur AbuseIPDB : {e}")
        return 0, "Erreur lors de la vérification de l'IP."