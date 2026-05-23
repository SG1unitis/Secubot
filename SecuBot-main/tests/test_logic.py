from modules.intelligence import (
    check_typosquatting,
    defang_url,
    extract_urls,
    extraire_hote,
    normaliser_observable,
)


def test_normaliser_observable_ajoute_https():
    assert normaliser_observable("google.com") == "https://google.com"


def test_extraire_hote_depuis_domaine_simple():
    assert extraire_hote("google.com") == "google.com"


def test_extraire_hote_depuis_url_complete():
    assert extraire_hote("https://example.com/login") == "example.com"


def test_defang_url_http():
    assert defang_url("http://malware.com") == "hXXp://malware[.]com"


def test_defang_url_https():
    assert defang_url("https://malware.com") == "hXXps://malware[.]com"


def test_extract_urls_depuis_mail():
    texte = "Cliquez ici : https://example.com/login puis visitez microsoft.com."
    urls = extract_urls(texte)

    assert "https://example.com/login" in urls
    assert "https://microsoft.com" in urls


def test_typosquatting_microsoft():
    is_squatted, score = check_typosquatting("https://mircosoft-billing.com/pay")

    assert is_squatted is True
    assert score > 0.75


def test_domaine_legitime_non_suspect():
    is_squatted, score = check_typosquatting("https://microsoft.com")

    assert is_squatted is False
    assert score == 0