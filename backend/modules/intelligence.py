import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse


PROTECTED_DOMAINS = ["valabre.com", "microsoft.com", "google.com", "outlook.com"]

URL_PATTERN = re.compile(
    r"(?<!@)\b(?:https?://|www\.)[^\s<>\"']+|"
    r"(?<!@)\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?::\d+)?(?:/[^\s<>\"']*)?"
)


def normaliser_observable(valeur: str) -> str:
    """
    Normalise une URL ou un domaine fourni par l'utilisateur.
    Exemples :
    - google.com -> https://google.com
    - www.google.com -> https://www.google.com
    - https://google.com -> https://google.com
    """
    valeur = valeur.strip()

    if not valeur:
        return ""

    if valeur.startswith(("http://", "https://")):
        return valeur

    return f"https://{valeur}"


def extraire_hote(observable: str) -> str:
    """
    Extrait le domaine ou l'adresse IP d'une URL normalisée.
    """
    observable = normaliser_observable(observable)
    parsed = urlparse(observable)

    if parsed.hostname:
        return parsed.hostname.lower()

    return ""


def est_ip(observable: str) -> bool:
    try:
        ipaddress.ip_address(observable)
        return True
    except ValueError:
        return False


def check_typosquatting(target_url: str) -> tuple[bool, float]:
    """
    Détecte une proximité anormale avec un domaine protégé.
    """
    domain = extraire_hote(target_url)

    if not domain or est_ip(domain):
        return False, 0

    for protected in PROTECTED_DOMAINS:
        if domain == protected or domain.endswith("." + protected):
            return False, 0

    parts = domain.split(".")
    if len(parts) < 2:
        return False, 0

    base = parts[-2]
    base = re.sub(r"[-_](secure|login|verify|account|billing|support)$", "", base)

    for protected in PROTECTED_DOMAINS:
        protected_base = protected.split(".")[0]
        similarity = SequenceMatcher(None, base, protected_base).ratio()

        if similarity > 0.75:
            return True, similarity

    return False, 0


def defang_url(url: str) -> str:
    """
    Neutralise une URL pour la rendre non cliquable.
    """
    url = re.sub(r"^https://", "hXXps://", url, flags=re.IGNORECASE)
    url = re.sub(r"^http://", "hXXp://", url, flags=re.IGNORECASE)
    url = re.sub(r"^ftp://", "fXp://", url, flags=re.IGNORECASE)
    return url.replace(".", "[.]")


def extract_urls(text: str) -> list[str]:
    """
    Extrait les URLs et domaines depuis un texte.
    Évite de récupérer les domaines d'adresses email.
    """
    results = []
    seen = set()

    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,;:!?)]}")

        if cleaned not in seen:
            seen.add(cleaned)
            results.append(normaliser_observable(cleaned))

    return results