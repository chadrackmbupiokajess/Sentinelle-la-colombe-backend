"""
Sentinelle — point d'entrée WSGI, pour PythonAnywhere (ou tout hébergeur WSGI).

Sur un tel hébergeur, les WebSockets ne sont pas disponibles : le frontend doit
être construit avec NEXT_PUBLIC_WEBSOCKET=off pour passer directement en AJAX.
Sur un VPS, inutile : lancez uvicorn (voir Dockerfile) et gardez les WebSockets.

Dans le fichier WSGI de PythonAnywhere (onglet « Web »), remplacez tout par :

    import sys
    sys.path.insert(0, "/home/VOTRE_NOM/Sentinelle-la-colombe-backend")
    from wsgi import application

Les réglages (SENTINELLE_BD, clés VAPID, SENTINELLE_ORIGINES…) sont lus dans
le fichier .env placé à côté de ce fichier (jamais envoyé sur git).
"""

from __future__ import annotations

import os
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
if ICI not in sys.path:
    sys.path.insert(0, ICI)


def _charger_env(chemin: str) -> None:
    """Lit un fichier .env simple (CLE=valeur). Les variables déjà définies sont prioritaires."""
    if not os.path.isfile(chemin):
        return
    with open(chemin, encoding="utf-8") as fichier:
        for ligne in fichier:
            ligne = ligne.strip()
            if not ligne or ligne.startswith("#") or "=" not in ligne:
                continue
            cle, _, valeur = ligne.partition("=")
            cle, valeur = cle.strip(), valeur.strip()
            if len(valeur) >= 2 and valeur[0] == valeur[-1] and valeur[0] in "'\"":
                valeur = valeur[1:-1]
            os.environ.setdefault(cle, valeur)


# Avant d'importer main : SENTINELLE_BD doit être connu à l'ouverture de la base.
_charger_env(os.path.join(ICI, ".env"))

from a2wsgi import ASGIMiddleware  # noqa: E402

from main import app  # noqa: E402

_application_asgi = ASGIMiddleware(app)
_IP_DERRIERE_PROXY = os.environ.get("SENTINELLE_IP_PROXY", "1") != "0"


def application(environ, start_response):
    # Derrière le proxy de PythonAnywhere, REMOTE_ADDR est l'adresse du proxy : sans
    # correction, tous les visiteurs partageraient les mêmes limites anti-abus
    # (connexions, appels). La vraie adresse est transmise dans X-Real-IP.
    if _IP_DERRIERE_PROXY:
        reelle = environ.get("HTTP_X_REAL_IP") or environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0]
        if reelle.strip():
            environ["REMOTE_ADDR"] = reelle.strip()
    environ.setdefault("REMOTE_PORT", "0")  # requis pour que FastAPI connaisse l'adresse du client
    return _application_asgi(environ, start_response)
