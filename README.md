# SecuBot - Analyseur d'URLs pour Outlook

SecuBot est une application de cybersécurité conçue comme un complément (Add-in) pour Microsoft Outlook. Développé durant une mission pour la protection civile, cet outil permet aux agents d'analyser, à la demande et en un clic, les URLs suspectes reçues par email. 

L'objectif est de réduire la surface d'attaque liée à l'erreur humaine (phishing) en offrant une analyse sandboxée et multi-sources, sans compromettre le poste de travail de l'utilisateur.

## Fonctionnalités Principales

* **Intégration Transparente :** S'intègre directement dans le volet des tâches (Taskpane) d'Outlook via un fichier manifest.xml.
* **Analyse Multi-Sources :** Interroge les bases de données de **VirusTotal**, **AlienVault OTX**, et **AbuseIPDB** pour établir la réputation d'un domaine ou d'une adresse IP.
* **Heuristique Locale :** * Vérification de l'âge des certificats SSL (les certificats récents sont souvent suspects).
    * Détection de Typosquatting (ex: `mircosoft.com` vs `microsoft.com`).
* **Analyse Globale de l'Email :** Capacité d'extraire et d'analyser simultanément tous les liens contenus dans le corps d'un email.
* **Mise en Cache :** Utilisation de SQLite (`secubot_history.db`) pour mettre en cache les verdicts récents et limiter la consommation des quotas d'API.
* **Sécurité et Confidentialité :**
    * Exécution isolée du navigateur local.
    * Neutralisation (Defanging) des URLs dans les logs (ex: `http://malware.com` devient `hXXp://malware[.]com`).
    * Restriction d'accès à l'API Flask par réseau autorisé et limitation de taux. Les clés API présentes dans le fichier `.env` servent aux appels sortants vers VirusTotal, OTX et AbuseIPDB. Elles ne constituent pas une authentification d'accès à l'API Flask.

## Fonctionnement simplifié

[Utilisateur Outlook]
        |
        v
[Add-in Outlook HTML/JS]
        |
        | POST /api/analyze ou /api/analyze-mail
        v
[API Flask SecuBot]
        |
        +--> Normalisation / extraction / defanging
        +--> Vérification typosquatting
        +--> Vérification SSL
        +--> VirusTotal
        +--> AlienVault OTX
        +--> AbuseIPDB
        |
        v
[Verdict + cache SQLite local]

##  Architecture du Projet

Le projet est divisé en trois parties distinctes : le backend Python/Flask, le frontend HTML/JS hébergé par Outlook et la configuration du complément Outlook

```text
SecuBot/
├── README.md
├── requirements.txt
├── .env.example
├── backend/
│   ├── secubot.py
│   ├── modules/
│   │   ├── abuseipdb.py
│   │   ├── database.py
│   │   ├── intelligence.py
│   │   ├── otx.py
│   │   ├── security.py
│   │   └── ssl_check.py
│   └── tests/
│       └── test_intelligence.py
├── frontend/
│   ├── taskpane.html
│   ├── taskpane.css
│   └── taskpane.js
└── manifest/
    └── manifest.example.xml
```
## Utilisation
1. Assurez-vous d'avoir Python installé (version minimale recommandée : 3.11).

2. Installez les dépendances requises : pip install -r requirements.txt

3. Configurez vos clés d'API (VirusTotal, OTX, AbuseIPDB) dans un fichier .env à la racine du projet.

4. Générez vos certificats locaux (localhost.crt, localhost.key) pour autoriser le HTTPS en développement.

5. Lancez le backend : python secubot.py (assurez-vous d'être dans le même dossier).

# Librairies utilisées
Flask : cette librairie permet de créer le serveur backend et l'API REST qui réceptionne les requêtes de l'add-in Outlook.

Flask-Limiter : couplé avec Flask, il sécurise l'API en implémentant un Rate Limiting (ex: 10 requêtes/min pour les URLs uniques, 3 requêtes/min pour les emails complets) afin de prévenir les abus et protéger les quotas d'API.

requests : utilisée massivement dans le dossier modules/ pour effectuer les appels HTTP vers les API externes de Threat Intelligence (VirusTotal, AlienVault OTX, AbuseIPDB).

python-dotenv : permet de charger les variables d'environnement depuis le fichier .env pour garder les clés d'API secrètes en dehors du code source.

pytest : utilisé pour exécuter le script test_intelligence.py afin de valider le comportement du moteur d'intelligence (expressions régulières, similarité de chaînes) avant déploiement.
