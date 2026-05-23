import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import requests
from urllib.parse import urlparse

from modules.database import init_db, log_analysis, get_cached_verdict
from modules.otx import check_otx_domain
from modules.ssl_check import check_ssl_age
from modules.abuseipdb import is_ip_address, check_ip_reputation
from modules.security import limiter, require_internal_network
from modules.intelligence import (
    check_typosquatting,
    extract_urls,
    defang_url,
    normaliser_observable,
    extraire_hote,
)

load_dotenv()

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
FRONTEND_DIR = os.path.join(PARENT_DIR, 'frontend')

app = Flask(__name__)
CORS(app)

init_db()
limiter.init_app(app)

def check_virustotal(observable):
    """Interroge l'API v3 de VirusTotal."""
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "titre": "⚪ INCONNU",
            "texte": "Clé VirusTotal non configurée. Analyse locale uniquement."
        }

    url = f"https://www.virustotal.com/api/v3/search?query={observable}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()

            if not data.get("data"):
                return {
                    "titre": "⚪ INCONNU",
                    "texte": "Lien inconnu. Vérifiez tout de même le nom de domaine et le sujet du mail."
                }

            stats = data["data"][0]["attributes"]["last_analysis_stats"]
            total = stats["malicious"] + stats["suspicious"]

            if total >= 3:
                return {
                    "titre": "🔴 ALERTE",
                    "texte": f"Menace confirmée ({total} flags). Ne cliquez pas sur le lien."
                }

            if total > 0:
                return {
                    "titre": "🟠 SUSPECT",
                    "texte": f"Lien potentiellement dangereux ({total} flag). Analysez bien le nom de domaine et le sujet du mail."
                }

            return {
                "titre": "🟢 CLEAN",
                "texte": "Aucun signalement détecté. Vérifiez tout de même l'expéditeur et le sujet du mail."
            }

        return {
            "titre": "ERREUR",
            "texte": f"Erreur API VirusTotal (code {response.status_code})."
        }

    except requests.RequestException as e:
        return {
            "titre": "CRASH",
            "texte": f"Erreur de connexion VirusTotal : {str(e)}"
        }

@app.route('/frontend/<path:filename>')
def serve_frontend(filename):
    """Sert les fichiers statiques pour l'add-in Outlook."""
    return send_from_directory(FRONTEND_DIR, filename)

@app.route('/api/analyze', methods=['POST'])
@require_internal_network                     
@limiter.limit("10 per minute")     
def analyze_single_url():
    payload = request.get_json(silent=True) or {}
    target_url = normaliser_observable(payload.get("url", ""))
    if not target_url:
        return jsonify({"titre": "ERREUR", "texte": "Aucune URL fournie."}), 400
    
    host = extraire_hote(target_url)

    if not host:
        return jsonify({"titre": "ERREUR", "texte": "URL ou domaine invalide."}), 400
    
    is_recent_ssl = False

    if is_ip_address(host):
        score, ip_texte = check_ip_reputation(host)
        verdict_final = "🔴 ALERTE IP" if score >= 50 else ("🟠 SUSPECT" if score > 0 else "🟢 CLEAN")
        log_analysis(target_url, host, verdict_final, is_recent_ssl)
        return jsonify({"titre": verdict_final, "texte": ip_texte})

    is_squatted, score_squat = check_typosquatting(target_url)
    is_recent_ssl, ssl_age, ssl_msg = check_ssl_age(target_url)
 

    verdict_final = get_cached_verdict(target_url)
    
    if not verdict_final:
        vt_res = check_virustotal(target_url)
        otx_pulses = check_otx_domain(target_url)

        verdict_final = vt_res["titre"]
        texte_final = vt_res["texte"]

        #OTX (corrélations)
        if otx_pulses > 0:
            if "CLEAN" in verdict_final or "INCONNU" in verdict_final:
                verdict_final = "🟠 SUSPECT"
                texte_final = f"Inconnu de VT, mais listé dans {otx_pulses} rapport(s) OTX."
            else:
                texte_final += f" Corroboré par {otx_pulses} rapport(s) OTX."
        
        log_analysis(target_url, host, verdict_final, is_recent_ssl)
    else:
        texte_final = "Résultat récupéré depuis le cache local."
    
    if is_recent_ssl and "ALERTE" not in verdict_final:
        verdict_final = "🟠 SUSPECT"
        texte_final += f" {ssl_msg}"

#Typosquatting
    if is_squatted:
        verdict_final = "🔴 ALERTE TYPOSQUATTING"
        texte_final = f"Imitation de domaine détectée ({int(score_squat*100)}% de ressemblance). Ne cliquez pas sur le lien."

    return jsonify({"titre": verdict_final, "texte": texte_final})

@app.route('/api/analyze-mail', methods=['POST'])
@require_internal_network
@limiter.limit("3 per minute")
def analyze_full_mail():
    payload = request.get_json(silent=True) or {}
    mail_body = payload.get("body", "")
    found_urls = extract_urls(mail_body)

    if not found_urls:
        return jsonify({"message": "Aucun lien détecté.", "count": 0, "results": []})

    results = []
    for url in found_urls:
    
        domain = extraire_hote(url) or "Format URL invalide"

        cached = get_cached_verdict(url)
        if cached:
            results.append({
                "original_defanged": defang_url(url),
                "verdict": cached,
                "details": "Analyse déjà effectuée."
            })
            continue

        verdict = "🟢 CLEAN"

        vt_res = check_virustotal(url)
        otx_pulses = check_otx_domain(url)
        is_squatted, _ = check_typosquatting(url)
        
        verdict = "🔴 ALERTE TYPOSQUATTING" if is_squatted else vt_res["titre"]
        if otx_pulses > 0 and "CLEAN" in verdict:
            verdict = "🟠 SUSPECT"

        log_analysis(url, domain, verdict)
        
        results.append({
            "original_defanged": defang_url(url),
            "verdict": verdict,
            "details": vt_res["texte"]
        })

    return jsonify({"count": len(found_urls), "results": results})

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "titre": "LIMITE ATTEINTE",
        "texte": "Trop de requêtes. Veuillez patienter avant la prochaine analyse."
    }), 429

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=debug_mode,
        ssl_context=("localhost.crt", "localhost.key"),
    )
