import os
import requests
from modules.intelligence import extraire_hote


def check_otx_domain(target_url: str) -> int:
    """
    Vérifie combien de rapports OTX ciblent le domaine.
    Retourne 0 si la clé API est absente ou si l'analyse échoue.
    """
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return 0

    domain = extraire_hote(target_url)
    if not domain:
        return 0

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("pulse_info", {}).get("count", 0)
    except requests.RequestException as e:
        print(f"[!] Erreur OTX : {e}")

    return 0