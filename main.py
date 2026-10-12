"""
Sentinelle — API temps réel d'appel malade.

  • Bornes patient   : /c/{chambre}-{code}  →  WebSocket /ws/borne/{jeton}, routes /api/bornes/…
                        (le code imprimé sur la porte empêche d'appeler depuis n'importe quelle chambre ;
                        le code de séjour, donné à l'admission, cesse de fonctionner à la sortie)
  • Soignants        : comptes personnels (identifiant + mot de passe), session mémorisée jusqu'à déconnexion
                        WebSocket /ws/soignant?jeton=…, routes /api/… protégées
  • Administrateurs  : validation des comptes, chambres, codes QR  →  /api/admin/…

À chaque changement, l'état complet est rediffusé à tous les écrans concernés.

Lancement local :  python main.py      (ou  uvicorn main:app --host 0.0.0.0 --port 8000)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from py_vapid import Vapid
from pywebpush import WebPushException, webpush

from base import Base, ErreurMetier, maintenant
from securite import Limiteur

documentation = os.environ.get("SENTINELLE_DOCS", "1") != "0"
app = FastAPI(
    title="Sentinelle — API d'appel malade",
    version="2.0.0",
    docs_url="/api/docs" if documentation else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if documentation else None,
)

origines = os.environ.get("SENTINELLE_ORIGINES", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origines.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def entetes_securite(request: Request, suivant):
    reponse = await suivant(request)
    reponse.headers["X-Content-Type-Options"] = "nosniff"
    reponse.headers["Referrer-Policy"] = "no-referrer"
    reponse.headers["Cache-Control"] = "no-store"
    return reponse


base = Base()
logger = logging.getLogger("sentinelle.push")
VAPID_PUBLIC_KEY = os.environ.get("SENTINELLE_VAPID_PUBLIC_KEY", "").strip()
VAPID_PRIVATE_KEY = os.environ.get("SENTINELLE_VAPID_PRIVATE_KEY", "").strip()
try:
    if VAPID_PRIVATE_KEY:
        Vapid.from_string(VAPID_PRIVATE_KEY)
except (ValueError, TypeError):
    logger.error("La clé privée VAPID n'est pas valide.")
    VAPID_PRIVATE_KEY = ""
VAPID_SUBJECT = os.environ.get("SENTINELLE_VAPID_SUBJECT", "").strip()


async def envoyer_push_abonnement(abonnement: dict, donnees: dict) -> None:
    if not (VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY and VAPID_SUBJECT):
        logger.warning("Push indisponible : clés VAPID non configurées.")
        return
    try:
        await asyncio.to_thread(
            webpush,
            subscription_info={
                "endpoint": abonnement["endpoint"],
                "keys": {"p256dh": abonnement["p256dh"], "auth": abonnement["auth"]},
            },
            data=json.dumps(donnees, ensure_ascii=False),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": VAPID_SUBJECT},
            ttl=86400 if donnees.get("type") in ("urgence", "urgence_terminee") else 300,
        )
    except WebPushException as exc:
        status = exc.response.status_code if exc.response is not None else None
        logger.warning("Échec push vers un abonnement (HTTP %s): %s", status, exc)
        if status in (404, 410):
            base.supprimer_abonnement_push(abonnement["compte_id"], abonnement["endpoint"])


async def envoyer_push_compte(compte_id: int, donnees: dict) -> None:
    for abonnement in base.abonnements_push_compte(compte_id):
        await envoyer_push_abonnement({**abonnement, "compte_id": compte_id}, donnees)


@app.exception_handler(ErreurMetier)
async def gerer_erreur_metier(_, exc: ErreurMetier):
    return JSONResponse({"detail": exc.message}, status_code=exc.code)


# --------------------------------------------------------------------------
# Limites anti-abus (par adresse IP, par chambre)
# --------------------------------------------------------------------------
lim_connexion_ip = Limiteur(20, 600)  # 20 tentatives de connexion / 10 min / IP
lim_inscription_ip = Limiteur(5, 3600)  # 5 inscriptions / heure / IP
lim_appel_lit = Limiteur(6, 600)  # 6 appels / 10 min / lit
lim_appel_ip = Limiteur(30, 600)  # 30 appels / 10 min / IP (opérateurs mobiles : IP partagées)
lim_code_faux_ip = Limiteur(20, 600)  # 20 codes de chambre faux / 10 min / IP
lim_sejour_faux_ip = Limiteur(8, 900)  # 8 codes de séjour faux / 15 min / IP
TAILLE_MAX_VOCAL = 5 * 1024 * 1024
TYPES_AUDIO_AUTORISES = {"audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/wav"}

MESSAGES_STATUT = {
    "libre": "Cette chambre n'est pas active. Demandez à l'infirmière d'activer votre accès.",
    "code_requis": "Entrez le code de séjour donné par l'infirmière.",
    "termine": "Votre séjour est terminé : les appels ne sont plus possibles depuis ce téléphone.",
}


def ip(requete: Request | WebSocket) -> str:
    return requete.client.host if requete.client else "inconnue"


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------
def jeton_de(requete: Request) -> str | None:
    entete = requete.headers.get("authorization", "")
    return entete[7:].strip() if entete.lower().startswith("bearer ") else None


def soignant(requete: Request) -> dict:
    compte = base.compte_par_jeton(jeton_de(requete))
    if not compte:
        raise ErreurMetier("Session expirée. Reconnectez-vous.", 401)
    return compte


def administrateur(compte: dict = Depends(soignant)) -> dict:
    if compte["role"] != "admin":
        raise ErreurMetier("Réservé aux administrateurs.", 403)
    return compte


def jeton_sejour(requete: Request) -> str | None:
    """Jeton du téléphone du patient (obtenu avec le code de séjour)."""
    return requete.headers.get("x-sejour") or None


def exiger_sejour_actif(chambre: dict, requete: Request) -> dict:
    """Séjour (donc lit) du patient dont le téléphone fait la demande."""
    statut, sejour = base.appareil(chambre["id"], jeton_sejour(requete))
    if statut != "actif":
        raise ErreurMetier(MESSAGES_STATUT[statut], 403)
    return sejour


def borne(jeton: str, requete: Request) -> dict:
    """Chambre correspondant au lien imprimé sur la porte (ex. « 104-K7QM »)."""
    adresse = ip(requete)
    if lim_code_faux_ip.depasse(adresse):
        raise ErreurMetier("Trop de tentatives. Réessayez plus tard.", 429)
    chambre = base.chambre_par_jeton(jeton)
    if not chambre:
        lim_code_faux_ip.compter(adresse)
        raise ErreurMetier("Code de chambre invalide. Scannez de nouveau le code sur la porte.", 404)
    return chambre


# --------------------------------------------------------------------------
# Diffusion temps réel
# --------------------------------------------------------------------------
class Diffuseur:
    def __init__(self) -> None:
        self.soignants: dict[WebSocket, dict] = {}  # socket -> compte
        self.bornes: dict[WebSocket, tuple[str, str | None]] = {}  # socket -> (chambre, jeton de séjour)

    @staticmethod
    async def _envoyer(ws: WebSocket, donnees: dict) -> bool:
        try:
            await asyncio.wait_for(ws.send_json(donnees), timeout=5)
            return True
        except Exception:
            return False

    def equipe(self) -> list[str]:
        return sorted({c["nom"] for c in self.soignants.values()}, key=str.lower)

    def contacts_medicaux(self) -> list[dict]:
        comptes_connectes = {
            compte["id"]
            for compte in self.soignants.values()
            if compte["role"] in ("infirmier", "medecin", "admin")
        }
        return [
            {**contact, "en_ligne": contact["id"] in comptes_connectes}
            for contact in base.contacts_medicaux()
        ]

    def etat_soignants(self, compte_id: int) -> dict:
        return {
            "type": "etat",
            "alertes": base.alertes_visibles(),
            "chambres": base.lister_chambres(avec_sejours=True),
            "equipe": self.equipe(),
            "contacts_medicaux": self.contacts_medicaux(),
            "stats": base.statistiques(),
            "heure_serveur": maintenant().isoformat(timespec="milliseconds"),
            "urgences_privees": base.urgences_actives(compte_id),
        }

    @staticmethod
    def etat_borne(chambre_id: str, jeton_sejour: str | None) -> dict:
        statut, sejour = base.appareil(chambre_id, jeton_sejour)
        return {
            "type": "borne",
            "chambre": base.chambre(chambre_id),
            "statut": statut,
            "lit": sejour["lit"] if sejour else None,
            "alerte": base.alerte_active_sejour(sejour["id"]) if sejour else None,
            "heure_serveur": maintenant().isoformat(timespec="milliseconds"),
        }

    async def publier(self) -> None:
        for ws, compte in list(self.soignants.items()):
            etat = self.etat_soignants(compte["id"])
            if compte["role"] == "admin":
                etat["demandes_en_attente"] = base.demandes_en_attente()
            if not await self._envoyer(ws, etat):
                self.soignants.pop(ws, None)
        for ws, (chambre_id, sejour) in list(self.bornes.items()):
            if not await self._envoyer(ws, self.etat_borne(chambre_id, sejour)):
                self.bornes.pop(ws, None)

    async def aux_soignants(self, donnees: dict) -> None:
        for ws in list(self.soignants):
            if not await self._envoyer(ws, donnees):
                self.soignants.pop(ws, None)

    async def a_un_compte(self, compte_id: int, donnees: dict) -> None:
        for ws, compte in list(self.soignants.items()):
            if compte["id"] == compte_id and not await self._envoyer(ws, donnees):
                self.soignants.pop(ws, None)

    async def fermer_compte(self, compte_id: int) -> None:
        """Déconnecte immédiatement tous les écrans d'un compte (désactivé, mot de passe réinitialisé…)."""
        for ws, compte in list(self.soignants.items()):
            if compte["id"] == compte_id:
                self.soignants.pop(ws, None)
                try:
                    await ws.close(code=4401, reason="Session fermée")
                except Exception:
                    pass

    async def fermer_bornes(self, chambre_id: str) -> None:
        """Après un changement de code : les anciens liens de cette chambre cessent de fonctionner."""
        for ws, (cid, _) in list(self.bornes.items()):
            if cid == chambre_id:
                self.bornes.pop(ws, None)
                try:
                    await ws.close(code=4404, reason="Code de chambre changé")
                except Exception:
                    pass


diffuseur = Diffuseur()


# --------------------------------------------------------------------------
# Sorties automatiques (date de sortie prévue atteinte)
# --------------------------------------------------------------------------
async def verifier_sorties_automatiques() -> None:
    expires = base.cloturer_sejours_expires()
    if not expires:
        return
    await diffuseur.publier()  # les téléphones concernés passent à « Séjour terminé »
    for s in expires:
        await diffuseur.aux_soignants(
            {"type": "info", "texte": f"Sortie automatique : {s['chambre_libelle']} · Lit {s['lit']}."}
        )


async def _boucle_sorties_automatiques() -> None:
    while True:
        try:
            await verifier_sorties_automatiques()
        except Exception as e:  # ne jamais arrêter la surveillance
            print("Sorties automatiques :", e)
        await asyncio.sleep(30)


@app.on_event("startup")
async def demarrer_taches() -> None:
    asyncio.create_task(_boucle_sorties_automatiques())


# --------------------------------------------------------------------------
# Modèles d'entrée
# --------------------------------------------------------------------------
class Inscription(BaseModel):
    identifiant: str = Field(min_length=3, max_length=30)
    nom: str = Field(min_length=2, max_length=60)
    mot_de_passe: str = Field(min_length=1, max_length=200)


class Connexion(BaseModel):
    identifiant: str = Field(min_length=1, max_length=30)
    mot_de_passe: str = Field(min_length=1, max_length=200)


class ChangementMotDePasse(BaseModel):
    actuel: str = Field(min_length=1, max_length=200)
    nouveau: str = Field(min_length=1, max_length=200)


class NouveauStatut(BaseModel):
    statut: str


class NouveauRole(BaseModel):
    role: str


class NouvelleChambre(BaseModel):
    id: str = Field(min_length=1, max_length=12)
    libelle: str = Field("", max_length=60)
    service: str = Field("", max_length=60)
    lits: int = Field(5, ge=1, le=40)


class NombreLits(BaseModel):
    lits: int = Field(ge=1, le=40)


class Admission(BaseModel):
    initiales: str = Field("", max_length=10)
    sortie_prevue: str | None = Field(None, max_length=40)  # ISO 8601 ; vide = pas de date


class SortiePrevue(BaseModel):
    sortie_prevue: str | None = Field(None, max_length=40)


class CodeSejour(BaseModel):
    code: str = Field(min_length=1, max_length=10)


class NouveauMessage(BaseModel):
    texte: str = Field(min_length=1, max_length=500)


class ClesPush(BaseModel):
    p256dh: str = Field(min_length=20, max_length=256)
    auth: str = Field(min_length=8, max_length=128)


class AbonnementPush(BaseModel):
    endpoint: str = Field(min_length=1, max_length=2048)
    keys: ClesPush


class SuppressionAbonnementPush(BaseModel):
    endpoint: str = Field(min_length=1, max_length=2048)


# --------------------------------------------------------------------------
# Routes : généralités et authentification
# --------------------------------------------------------------------------
@app.get("/api/sante")
def sante():
    return {"ok": True, "soignants_connectes": len(diffuseur.soignants), "bornes": len(diffuseur.bornes)}


@app.get("/api/config")
def config():
    return {
        "premier_compte": base.nombre_comptes() == 0,
        "vapid_public_key": (
            VAPID_PUBLIC_KEY
            if VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY and VAPID_SUBJECT
            else None
        ),
    }


@app.post("/api/push/abonnement", status_code=201)
async def enregistrer_abonnement_push(donnees: AbonnementPush, compte: dict = Depends(soignant)):
    if not (VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY and VAPID_SUBJECT):
        raise ErreurMetier("Les notifications push ne sont pas configurées sur le serveur.", 503)
    if not donnees.endpoint.startswith("https://"):
        raise ErreurMetier("Adresse d'abonnement push invalide.", 400)
    base.enregistrer_abonnement_push(
        compte["id"], donnees.endpoint, donnees.keys.p256dh, donnees.keys.auth
    )
    abonnement = {
        "endpoint": donnees.endpoint,
        "p256dh": donnees.keys.p256dh,
        "auth": donnees.keys.auth,
        "compte_id": compte["id"],
    }
    for urgence in base.urgences_actives(compte["id"]):
        await envoyer_push_abonnement(
            abonnement,
            {
                "type": "urgence",
                "tag": f"urgence-privee-{urgence['message_id']}",
                "titre": f"🚨 Urgence — {urgence['expediteur_nom']} ({'Infirmier' if urgence['expediteur_role'] == 'infirmier' else 'Médecin'})",
                "corps": "Vous êtes demandé(e). Ouvrez Sentinelle puis appuyez sur « J'arrive ».",
                "url": "/infirmier",
                "message_id": urgence["message_id"],
            },
        )
    return {"ok": True}


@app.delete("/api/push/abonnement", status_code=204)
def supprimer_abonnement_push(donnees: SuppressionAbonnementPush, compte: dict = Depends(soignant)):
    base.supprimer_abonnement_push(compte["id"], donnees.endpoint)


@app.post("/api/auth/inscription", status_code=201)
async def inscription(donnees: Inscription, requete: Request):
    if not lim_inscription_ip.autoriser(ip(requete)):
        raise ErreurMetier("Trop d'inscriptions depuis cet appareil. Réessayez plus tard.", 429)
    compte, premier = base.inscrire(donnees.identifiant, donnees.nom, donnees.mot_de_passe)
    if premier:
        # Le tout premier compte est l'administrateur : il est connecté directement.
        jeton = base.creer_session(compte["id"], requete.headers.get("user-agent", ""))
        return {"compte": compte, "jeton": jeton, "en_attente": False}
    await diffuseur.publier()  # les administrateurs voient la nouvelle demande
    return {"compte": compte, "jeton": None, "en_attente": True}


@app.post("/api/auth/connexion")
def connexion(donnees: Connexion, requete: Request):
    if not lim_connexion_ip.autoriser(ip(requete)):
        raise ErreurMetier("Trop de tentatives depuis cet appareil. Réessayez dans quelques minutes.", 429)
    compte = base.authentifier(donnees.identifiant, donnees.mot_de_passe)
    jeton = base.creer_session(compte["id"], requete.headers.get("user-agent", ""))
    return {"jeton": jeton, "compte": compte}


@app.get("/api/auth/moi")
def moi(compte: dict = Depends(soignant)):
    return compte


@app.post("/api/auth/deconnexion", status_code=204)
def deconnexion(requete: Request):
    jeton = jeton_de(requete)
    if jeton:
        base.supprimer_session(jeton)


@app.post("/api/auth/mot-de-passe", status_code=204)
def changer_mot_de_passe(donnees: ChangementMotDePasse, compte: dict = Depends(soignant)):
    base.changer_mot_de_passe(compte["id"], donnees.actuel, donnees.nouveau)


# --------------------------------------------------------------------------
# Routes : soignants
# --------------------------------------------------------------------------
@app.get("/api/alertes")
def lister_alertes(_: dict = Depends(soignant)):
    return base.alertes_visibles()


@app.post("/api/alertes/{alerte_id}/accuser")
async def accuser_reception(alerte_id: str, compte: dict = Depends(soignant)):
    """Une infirmière accuse réception : l'alarme s'arrête partout."""
    alerte = base.accuser_reception(alerte_id, compte["nom"])
    await diffuseur.publier()
    return alerte


@app.post("/api/alertes/{alerte_id}/terminer")
async def terminer(alerte_id: str, compte: dict = Depends(soignant)):
    alerte = base.terminer(alerte_id, compte["nom"])
    await diffuseur.publier()
    return alerte


@app.get("/api/messages")
def lister_messages(_: dict = Depends(soignant)):
    return base.messages()


@app.post("/api/messages", status_code=201)
async def envoyer_message(donnees: NouveauMessage, compte: dict = Depends(soignant)):
    message = base.ajouter_message(compte["nom"], donnees.texte)
    await diffuseur.aux_soignants({"type": "message", "message": message})
    return message


def partenaire_medical(compte: dict, autre_id: int) -> dict:
    def role_medical(role: str) -> str | None:
        if role == "infirmier":
            return "infirmier"
        if role in ("medecin", "admin"):
            return "medecin"
        return None

    role_compte = role_medical(compte["role"])
    if role_compte is None:
        raise ErreurMetier("La messagerie privée est réservée aux médecins et infirmiers.", 403)
    autre = base.compte(autre_id)
    if not autre or autre["statut"] != "actif":
        raise ErreurMetier("Ce compte est introuvable ou indisponible.", 404)
    role_autre = role_medical(autre["role"])
    if role_autre is None:
        raise ErreurMetier("La messagerie privée est réservée aux médecins et infirmiers.", 403)
    return autre


@app.get("/api/messages-prives/{autre_id}")
def lister_messages_prives(autre_id: int, compte: dict = Depends(soignant)):
    partenaire_medical(compte, autre_id)
    return base.messages_prives(compte["id"], autre_id)


@app.post("/api/messages-prives/{autre_id}/lu")
async def marquer_messages_prives_lus(autre_id: int, compte: dict = Depends(soignant)):
    partenaire_medical(compte, autre_id)
    lecture = base.marquer_messages_prives_lus(compte["id"], autre_id)
    if lecture["ids"]:
        await diffuseur.a_un_compte(
            autre_id,
            {"type": "messages_prives_lus", **lecture},
        )
    return lecture


@app.post("/api/messages-prives/{destinataire_id}", status_code=201)
async def envoyer_message_prive(
    destinataire_id: int, donnees: NouveauMessage, compte: dict = Depends(soignant)
):
    partenaire_medical(compte, destinataire_id)
    message = base.ajouter_message_prive(compte["id"], destinataire_id, donnees.texte)
    await diffuseur.a_un_compte(destinataire_id, {"type": "message_prive", "message": message})
    return message


@app.post("/api/messages-prives/{destinataire_id}/urgence", status_code=201)
async def envoyer_urgence_privee(destinataire_id: int, compte: dict = Depends(soignant)):
    partenaire_medical(compte, destinataire_id)
    texte = "🚨 URGENCE — Vous êtes demandé(e)."
    message = base.ajouter_message_prive(compte["id"], destinataire_id, texte)
    # Persister l'état d'urgence pour permettre l'alerte continue et la reconnaissance ultérieure
    base.ajouter_urgence(message["id"], destinataire_id)
    await diffuseur.a_un_compte(
        destinataire_id,
        {"type": "message_prive", "message": message, "urgence": True},
    )
    urgence = next(
        urgence
        for urgence in base.urgences_actives(destinataire_id)
        if urgence["message_id"] == message["id"]
    )
    await diffuseur.a_un_compte(
        destinataire_id,
        {"type": "urgence_debut", "urgence": urgence},
    )
    await envoyer_push_compte(
        destinataire_id,
        {
            "type": "urgence",
            "tag": f"urgence-privee-{message['id']}",
            "titre": f"🚨 Urgence — {compte['nom']} ({'Infirmier' if compte['role'] == 'infirmier' else 'Médecin'})",
            "corps": "Vous êtes demandé(e). Ouvrez Sentinelle puis appuyez sur « J'arrive ».",
            "url": "/infirmier",
            "message_id": message["id"],
        },
    )
    return message


@app.post("/api/messages-prives/{destinataire_id}/vocaux", status_code=201)
async def envoyer_vocal_prive(
    destinataire_id: int, requete: Request, compte: dict = Depends(soignant)
):
    partenaire_medical(compte, destinataire_id)
    audio_type = requete.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if audio_type not in TYPES_AUDIO_AUTORISES:
        raise ErreurMetier("Format audio non pris en charge par ce navigateur.", 415)
    longueur = requete.headers.get("content-length")
    if longueur:
        try:
            taille_annoncee = int(longueur)
        except ValueError as exc:
            raise ErreurMetier("Taille de vocal invalide.", 400) from exc
        if taille_annoncee > TAILLE_MAX_VOCAL:
            raise ErreurMetier("Le vocal dépasse la taille maximale de 5 Mo.", 413)
    audio = bytearray()
    async for bloc in requete.stream():
        if len(audio) + len(bloc) > TAILLE_MAX_VOCAL:
            raise ErreurMetier("Le vocal dépasse la taille maximale de 5 Mo.", 413)
        audio.extend(bloc)
    message = base.ajouter_vocal_prive(compte["id"], destinataire_id, bytes(audio), audio_type)
    await diffuseur.a_un_compte(destinataire_id, {"type": "message_prive", "message": message})
    return message


@app.post("/api/messages-prives/{message_id}/jarrive", status_code=200)
async def jarrive_message_prive(message_id: int, compte: dict = Depends(soignant)):
    """Accusé 'J'arrive' pour clore une urgence liée à un message privé.
    Seul le destinataire de l'urgence peut l'accuser."""
    urgence = base.urgence_par_message(message_id)
    if not urgence or not urgence.get("actif"):
        raise ErreurMetier("Aucune urgence active pour ce message.", 400)
    if urgence["destinataire_id"] != compte["id"]:
        raise ErreurMetier("Vous n'êtes pas le destinataire de cette urgence.", 403)
    fermeture = base.clore_urgence(message_id, compte["nom"])
    # Notifier tous les soignants afin qu'ils arrêtent la sonnerie locale si nécessaire
    await diffuseur.a_un_compte(
        compte["id"],
        {"type": "urgence_terminee", "message_id": message_id, "par": compte["nom"]},
    )
    await envoyer_push_compte(
        compte["id"],
        {"type": "urgence_terminee", "tag": f"urgence-privee-{message_id}"},
    )
    await diffuseur.publier()
    return {"ok": True, "fermeture": fermeture}


@app.get("/api/messages-prives/{autre_id}/vocaux/{message_id}")
def lire_vocal_prive(autre_id: int, message_id: int, compte: dict = Depends(soignant)):
    partenaire_medical(compte, autre_id)
    vocal = base.vocal_prive(message_id, compte["id"], autre_id)
    if not vocal or not vocal["audio"]:
        raise ErreurMetier("Message vocal introuvable.", 404)
    return Response(
        content=vocal["audio"],
        media_type=vocal["audio_type"],
        headers={"Content-Disposition": "inline", "X-Content-Type-Options": "nosniff"},
    )


@app.post("/api/chambres/{chambre_id}/lits/{lit}/admission", status_code=201)
async def admission(chambre_id: str, lit: int, donnees: Admission, compte: dict = Depends(soignant)):
    """Admettre un patient sur un lit : renvoie le code de séjour à lui donner."""
    sejour = base.admettre(chambre_id, lit, donnees.initiales, compte["nom"], donnees.sortie_prevue)
    await diffuseur.publier()
    return sejour


@app.post("/api/chambres/{chambre_id}/lits/{lit}/code")
async def changer_code_sejour(chambre_id: str, lit: int, compte: dict = Depends(soignant)):
    sejour = base.changer_code_sejour(chambre_id, lit)
    await diffuseur.publier()
    return sejour


@app.post("/api/chambres/{chambre_id}/lits/{lit}/sortie-prevue")
async def modifier_sortie_prevue(chambre_id: str, lit: int, donnees: SortiePrevue, compte: dict = Depends(soignant)):
    """Prolonger ou avancer la sortie automatique (ou la retirer)."""
    sejour = base.modifier_sortie_prevue(chambre_id, lit, donnees.sortie_prevue)
    await diffuseur.publier()
    return sejour


@app.post("/api/chambres/{chambre_id}/lits/{lit}/sortie")
async def sortie(chambre_id: str, lit: int, compte: dict = Depends(soignant)):
    """Sortie du patient de ce lit : son téléphone ne peut plus appeler."""
    sejour = base.sortie(chambre_id, lit, compte["nom"])
    await diffuseur.publier()
    return sejour


# --------------------------------------------------------------------------
# Routes : administration
# --------------------------------------------------------------------------
@app.get("/api/admin/comptes")
def admin_comptes(_: dict = Depends(administrateur)):
    return base.lister_comptes()


@app.post("/api/admin/comptes/{compte_id}/statut")
async def admin_statut(compte_id: int, donnees: NouveauStatut, admin: dict = Depends(administrateur)):
    compte = base.changer_statut(compte_id, donnees.statut, admin)
    if compte["statut"] != "actif":
        await diffuseur.fermer_compte(compte_id)
    await diffuseur.publier()
    return compte


@app.post("/api/admin/comptes/{compte_id}/role")
async def admin_role(compte_id: int, donnees: NouveauRole, admin: dict = Depends(administrateur)):
    compte = base.changer_role(compte_id, donnees.role, admin)
    await diffuseur.fermer_compte(compte_id)  # se reconnecte avec ses nouveaux droits
    await diffuseur.publier()
    return compte


@app.post("/api/admin/comptes/{compte_id}/reinitialiser")
async def admin_reinitialiser(compte_id: int, _: dict = Depends(administrateur)):
    provisoire = base.reinitialiser_mot_de_passe(compte_id)
    await diffuseur.fermer_compte(compte_id)
    await diffuseur.publier()
    return {"mot_de_passe": provisoire}


@app.post("/api/admin/comptes/{compte_id}/deconnecter", status_code=204)
async def admin_deconnecter(compte_id: int, _: dict = Depends(administrateur)):
    base.supprimer_sessions_compte(compte_id)
    await diffuseur.fermer_compte(compte_id)
    await diffuseur.publier()


@app.get("/api/admin/chambres")
def admin_chambres(_: dict = Depends(administrateur)):
    return base.lister_chambres(avec_codes=True)


@app.post("/api/admin/chambres", status_code=201)
async def admin_ajouter_chambre(donnees: NouvelleChambre, _: dict = Depends(administrateur)):
    chambre = base.ajouter_chambre(donnees.id, donnees.libelle, donnees.service, donnees.lits)
    await diffuseur.publier()
    return chambre


@app.post("/api/admin/chambres/{chambre_id}/lits")
async def admin_changer_lits(chambre_id: str, donnees: NombreLits, _: dict = Depends(administrateur)):
    chambre = base.changer_lits(chambre_id, donnees.lits)
    await diffuseur.publier()
    return chambre


@app.delete("/api/admin/chambres/{chambre_id}", status_code=204)
async def admin_supprimer_chambre(chambre_id: str, _: dict = Depends(administrateur)):
    base.supprimer_chambre(chambre_id)
    await diffuseur.fermer_bornes(chambre_id)
    await diffuseur.publier()


@app.post("/api/admin/chambres/{chambre_id}/code")
async def admin_regenerer_code(chambre_id: str, _: dict = Depends(administrateur)):
    chambre = base.regenerer_code(chambre_id)
    await diffuseur.fermer_bornes(chambre_id)
    return chambre


# --------------------------------------------------------------------------
# Routes : bornes patient (publiques, protégées par le code de la chambre)
# --------------------------------------------------------------------------
@app.get("/api/bornes/{jeton}")
def lire_borne(jeton: str, requete: Request):
    chambre = borne(jeton, requete)
    statut, sejour = base.appareil(chambre["id"], jeton_sejour(requete))
    return {
        "chambre": chambre,
        "statut": statut,
        "lit": sejour["lit"] if sejour else None,
        "alerte": base.alerte_active_sejour(sejour["id"]) if sejour else None,
    }


@app.post("/api/bornes/{jeton}/activer")
async def activer_telephone(jeton: str, donnees: CodeSejour, requete: Request):
    """Le patient saisit le code de séjour une fois : son téléphone peut ensuite appeler."""
    chambre = borne(jeton, requete)
    adresse = ip(requete)
    if lim_sejour_faux_ip.depasse(adresse):
        raise ErreurMetier("Trop d'essais. Réessayez dans quelques minutes ou demandez l'aide d'une infirmière.", 429)
    try:
        jeton_tel = base.activer_appareil(chambre["id"], donnees.code)
    except ErreurMetier as e:
        if e.code == 401:
            lim_sejour_faux_ip.compter(adresse)
        raise
    return {"jeton_sejour": jeton_tel}


@app.post("/api/bornes/{jeton}/appel")
async def appeler(jeton: str, requete: Request):
    """Le patient appuie sur le bouton."""
    chambre = borne(jeton, requete)
    sejour = exiger_sejour_actif(chambre, requete)
    existante = base.alerte_active_sejour(sejour["id"])
    if existante:
        return existante
    if not lim_appel_lit.autoriser(sejour["id"]) or not lim_appel_ip.autoriser(ip(requete)):
        raise ErreurMetier(
            "Trop d'appels en peu de temps. En cas d'urgence, utilisez la sonnette murale.", 429
        )
    alerte, _ = base.creer_alerte(sejour)
    await diffuseur.publier()
    return alerte


@app.post("/api/bornes/{jeton}/annuler")
async def annuler(jeton: str, requete: Request):
    """Le patient annule son appel."""
    chambre = borne(jeton, requete)
    sejour = exiger_sejour_actif(chambre, requete)
    alerte = base.annuler_sejour(sejour["id"])
    if alerte:
        await diffuseur.publier()
        await diffuseur.aux_soignants(
            {"type": "info", "texte": f"{alerte['chambre_libelle']}, lit {alerte['lit']} : appel annulé par le patient."}
        )
    return {"ok": True}


# --------------------------------------------------------------------------
# WebSockets
# --------------------------------------------------------------------------
async def _garder_ouvert(ws: WebSocket, jeton: str) -> None:
    """Lit (et ignore) les « ping » du client jusqu'à la déconnexion."""
    while True:
        await ws.receive_text()
        if not base.compte_par_jeton(jeton):
            await ws.close(code=4401, reason="Session expirée")
            return


@app.websocket("/ws/soignant")
async def ws_soignant(ws: WebSocket):
    await ws.accept()
    compte = base.compte_par_jeton(ws.query_params.get("jeton"))
    if not compte:
        await ws.close(code=4401, reason="Session expirée")
        return
    diffuseur.soignants[ws] = compte
    try:
        await ws.send_json({"type": "moi", "compte": compte})
        await ws.send_json({"type": "messages", "messages": base.messages()})
        await diffuseur.publier()  # met aussi à jour la liste « équipe » des collègues
        await _garder_ouvert(ws, ws.query_params.get("jeton", ""))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        if diffuseur.soignants.pop(ws, None) is not None:
            await diffuseur.publier()


@app.websocket("/ws/borne/{jeton}")
async def ws_borne(ws: WebSocket, jeton: str):
    await ws.accept()
    adresse = ip(ws)
    chambre = None if lim_code_faux_ip.depasse(adresse) else base.chambre_par_jeton(jeton)
    if not chambre:
        lim_code_faux_ip.compter(adresse)
        await ws.close(code=4404, reason="Code de chambre invalide")
        return
    sejour = ws.query_params.get("sejour") or None
    diffuseur.bornes[ws] = (chambre["id"], sejour)
    try:
        await ws.send_json(diffuseur.etat_borne(chambre["id"], sejour))
        await _garder_ouvert(ws)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        diffuseur.bornes.pop(ws, None)


# --------------------------------------------------------------------------
# Lancement direct :  python main.py
# --------------------------------------------------------------------------
def _adresses_reseau() -> list[str]:
    """Adresses IPv4 de cette machine sur le réseau local (ex. 192.168.0.67)."""
    import socket

    adresses = set()
    try:  # adresse de la carte réseau principale
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            adresses.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            adresses.add(info[4][0])
    except OSError:
        pass
    return sorted(a for a in adresses if not a.startswith("127."))


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    print("\n  Sentinelle — backend démarré")
    print(f"  • Sur ce PC        : http://localhost:{port}/api/sante")
    for adresse_ip in _adresses_reseau():
        print(f"  • Sur le réseau    : http://{adresse_ip}:{port}/api/sante")
        print(f"    Poste soignant   : http://{adresse_ip}:3000/infirmier")
    print()
    # host 0.0.0.0 : indispensable pour être joignable depuis les tablettes et téléphones.
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, proxy_headers=True, forwarded_allow_ips="*")
