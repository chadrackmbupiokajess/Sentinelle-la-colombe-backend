"""
Sentinelle — couche de données et règles métier.

Stockage SQLite (un simple fichier, aucun serveur de base de données à installer).
Toute la logique se trouve ici ; l'API (main.py) ne fait qu'exposer ces fonctions
et diffuser les changements en temps réel.

Cycle de vie d'un appel :
    en_attente  ──(une infirmière accuse réception)──►  prise_en_charge  ──►  terminee
         │                                                   │
         └──────────────(le patient annule)──────────────────┴──►  annulee

Salles à plusieurs lits, séjour par lit (empêche d'appeler une fois rentré chez soi) :
    l'infirmière « admet » un patient sur un lit → code à 4 chiffres propre à ce lit →
    le patient le saisit une fois sur son téléphone (lié à SON séjour) → ses appels
    indiquent « Salle 104 · Lit 3 » → « sortie » : son téléphone ne peut plus appeler.

Cycle de vie d'un compte soignant :
    en_attente ──(validé par un administrateur)──► actif ◄──► desactive
         └──(refusé)──► refuse
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

from securite import (
    empreinte_jeton,
    hacher_mot_de_passe,
    mot_de_passe_temporaire,
    mot_de_passe_valide,
    nouveau_code_chambre,
    nouveau_jeton,
    verifier_mot_de_passe,
)

CHEMIN_BD = os.environ.get(
    "SENTINELLE_BD", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinelle.db")
)
DUREE_SESSION = timedelta(days=int(os.environ.get("SENTINELLE_SESSION_JOURS", "30")))
# Un séjour oublié (sortie non enregistrée) expire seul au bout de ce délai.
DUREE_SEJOUR = timedelta(days=int(os.environ.get("SENTINELLE_SEJOUR_JOURS", "30")))
ESSAIS_CODE_SALLE_MAX = 25  # codes de séjour faux tolérés par salle avant blocage
LITS_PAR_DEFAUT = int(os.environ.get("SENTINELLE_LITS", "5"))
LITS_MAX = 40
ECHECS_AVANT_BLOCAGE = 5
DUREE_BLOCAGE = timedelta(minutes=5)

STATUTS_ACTIFS = ("en_attente", "prise_en_charge")
RE_IDENTIFIANT = re.compile(r"^[a-z0-9][a-z0-9._-]{2,29}$")

# Chambres créées au premier démarrage (modifiables ensuite dans l'espace administrateur).
CHAMBRES_INITIALES = [
    *[(str(n), f"Chambre {n}", "Aile Nord") for n in range(101, 107)],
    *[(str(n), f"Chambre {n}", "Aile Sud") for n in range(107, 113)],
]


class ErreurMetier(Exception):
    """Erreur prévue, renvoyée telle quelle à l'interface (message en français)."""

    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code


def maintenant() -> datetime:
    return datetime.now(timezone.utc)


def horodatage(dt: datetime | None = None) -> str:
    return (dt or maintenant()).isoformat(timespec="seconds")


def lire_date(valeur: str) -> datetime:
    return datetime.fromisoformat(valeur)


def _compte_public(ligne: dict | None) -> dict | None:
    if not ligne:
        return None
    return {
        "id": ligne["id"],
        "identifiant": ligne["identifiant"],
        "nom": ligne["nom"],
        "role": ligne["role"],
        "statut": ligne["statut"],
        "cree_le": ligne["cree_le"],
        "doit_changer": bool(ligne["doit_changer"]),
    }


class Base:
    def __init__(self, chemin: str = CHEMIN_BD):
        self.cx = sqlite3.connect(chemin, check_same_thread=False)
        self.cx.row_factory = sqlite3.Row
        self.verrou = threading.RLock()
        self._creer_schema()

    # ------------------------------------------------------------------ schéma
    def _creer_schema(self) -> None:
        with self.verrou, self.cx:
            self.cx.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS chambres (
                    id       TEXT PRIMARY KEY,
                    libelle  TEXT NOT NULL,
                    service  TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS alertes (
                    id           TEXT PRIMARY KEY,
                    chambre_id   TEXT NOT NULL REFERENCES chambres(id),
                    statut       TEXT NOT NULL,
                    cree_le      TEXT NOT NULL,
                    accuse_le    TEXT,
                    accuse_par   TEXT,
                    termine_le   TEXT,
                    termine_par  TEXT,
                    annule_le    TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_alertes_statut  ON alertes(statut);
                CREATE INDEX IF NOT EXISTS idx_alertes_chambre ON alertes(chambre_id);
                CREATE TABLE IF NOT EXISTS messages (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    auteur   TEXT NOT NULL,
                    texte    TEXT NOT NULL,
                    cree_le  TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS comptes (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifiant    TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    nom            TEXT NOT NULL,
                    mot_de_passe   TEXT NOT NULL,
                    role           TEXT NOT NULL DEFAULT 'infirmier',
                    statut         TEXT NOT NULL DEFAULT 'en_attente',
                    cree_le        TEXT NOT NULL,
                    valide_par     TEXT,
                    echecs         INTEGER NOT NULL DEFAULT 0,
                    bloque_jusqua  TEXT,
                    doit_changer   INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    empreinte  TEXT PRIMARY KEY,
                    compte_id  INTEGER NOT NULL REFERENCES comptes(id) ON DELETE CASCADE,
                    cree_le    TEXT NOT NULL,
                    vu_le      TEXT NOT NULL,
                    expire_le  TEXT NOT NULL,
                    appareil   TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_compte ON sessions(compte_id);
                CREATE TABLE IF NOT EXISTS sejours (
                    id          TEXT PRIMARY KEY,
                    chambre_id  TEXT NOT NULL,
                    code        TEXT NOT NULL,
                    initiales   TEXT NOT NULL DEFAULT '',
                    admis_le    TEXT NOT NULL,
                    admis_par   TEXT NOT NULL,
                    expire_le   TEXT NOT NULL,
                    sortie_le   TEXT,
                    sortie_par  TEXT,
                    essais      INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_sejours_chambre ON sejours(chambre_id);
                CREATE TABLE IF NOT EXISTS appareils_patient (
                    empreinte   TEXT PRIMARY KEY,
                    sejour_id   TEXT NOT NULL,
                    cree_le     TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_appareils_sejour ON appareils_patient(sejour_id);
                """
            )
            # Migrations : bases créées par les versions précédentes.
            def ajouter_colonne(table: str, colonne: str, definition: str) -> None:
                colonnes = {l["name"] for l in self.cx.execute(f"PRAGMA table_info({table})")}
                if colonne not in colonnes:
                    self.cx.execute(f"ALTER TABLE {table} ADD COLUMN {colonne} {definition}")

            ajouter_colonne("chambres", "code", "TEXT")
            ajouter_colonne("chambres", "lits", f"INTEGER NOT NULL DEFAULT {LITS_PAR_DEFAUT}")
            ajouter_colonne("chambres", "essais_sejour", "INTEGER NOT NULL DEFAULT 0")
            ajouter_colonne("sejours", "lit", "INTEGER NOT NULL DEFAULT 1")
            ajouter_colonne("alertes", "lit", "INTEGER")
            ajouter_colonne("alertes", "sejour_id", "TEXT")
            ajouter_colonne("sejours", "sortie_prevue", "TEXT")
            if self.cx.execute("SELECT COUNT(*) FROM chambres").fetchone()[0] == 0:
                self.cx.executemany(
                    "INSERT INTO chambres (id, libelle, service) VALUES (?, ?, ?)",
                    CHAMBRES_INITIALES,
                )
            for (chambre_id,) in self.cx.execute("SELECT id FROM chambres WHERE code IS NULL").fetchall():
                self.cx.execute(
                    "UPDATE chambres SET code = ? WHERE id = ?", (nouveau_code_chambre(), chambre_id)
                )

    def _un(self, sql: str, params: tuple = ()) -> dict | None:
        ligne = self.cx.execute(sql, params).fetchone()
        return dict(ligne) if ligne else None

    def _plusieurs(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(l) for l in self.cx.execute(sql, params).fetchall()]

    # ================================================================ COMPTES
    def nombre_comptes(self) -> int:
        with self.verrou:
            return self.cx.execute("SELECT COUNT(*) FROM comptes").fetchone()[0]

    def _admins_actifs(self) -> int:
        return self.cx.execute(
            "SELECT COUNT(*) FROM comptes WHERE role = 'admin' AND statut = 'actif'"
        ).fetchone()[0]

    def compte(self, compte_id: int) -> dict | None:
        with self.verrou:
            return _compte_public(self._un("SELECT * FROM comptes WHERE id = ?", (compte_id,)))

    def inscrire(self, identifiant: str, nom: str, mot_de_passe: str) -> tuple[dict, bool]:
        """Crée une demande de compte. Le tout premier compte devient administrateur, actif."""
        identifiant = identifiant.strip().lower()
        nom = " ".join(nom.split())
        if not RE_IDENTIFIANT.match(identifiant):
            raise ErreurMetier(
                "Identifiant : 3 à 30 caractères, lettres minuscules, chiffres, point, tiret ou souligné."
            )
        if len(nom) < 2:
            raise ErreurMetier("Indiquez votre nom complet.")
        erreur = mot_de_passe_valide(mot_de_passe)
        if erreur:
            raise ErreurMetier(erreur)
        empreinte = hacher_mot_de_passe(mot_de_passe)
        with self.verrou, self.cx:
            premier = self.cx.execute("SELECT COUNT(*) FROM comptes").fetchone()[0] == 0
            if self._un("SELECT id FROM comptes WHERE identifiant = ?", (identifiant,)):
                raise ErreurMetier("Cet identifiant est déjà utilisé.", 409)
            cur = self.cx.execute(
                "INSERT INTO comptes (identifiant, nom, mot_de_passe, role, statut, cree_le) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    identifiant,
                    nom[:60],
                    empreinte,
                    "admin" if premier else "infirmier",
                    "actif" if premier else "en_attente",
                    horodatage(),
                ),
            )
            return _compte_public(self._un("SELECT * FROM comptes WHERE id = ?", (cur.lastrowid,))), premier

    def authentifier(self, identifiant: str, mot_de_passe: str) -> dict:
        identifiant = identifiant.strip().lower()
        with self.verrou:
            ligne = self._un("SELECT * FROM comptes WHERE identifiant = ?", (identifiant,))
        if ligne and ligne["bloque_jusqua"] and lire_date(ligne["bloque_jusqua"]) > maintenant():
            raise ErreurMetier("Trop d'essais. Réessayez dans quelques minutes.", 429)
        if not verifier_mot_de_passe(mot_de_passe, ligne["mot_de_passe"] if ligne else None):
            if ligne:
                with self.verrou, self.cx:
                    echecs = ligne["echecs"] + 1
                    if echecs >= ECHECS_AVANT_BLOCAGE:
                        self.cx.execute(
                            "UPDATE comptes SET echecs = 0, bloque_jusqua = ? WHERE id = ?",
                            (horodatage(maintenant() + DUREE_BLOCAGE), ligne["id"]),
                        )
                    else:
                        self.cx.execute("UPDATE comptes SET echecs = ? WHERE id = ?", (echecs, ligne["id"]))
            raise ErreurMetier("Identifiant ou mot de passe incorrect.", 401)
        if ligne["statut"] == "en_attente":
            raise ErreurMetier("Votre compte attend la validation d'un administrateur.", 403)
        if ligne["statut"] != "actif":
            raise ErreurMetier("Ce compte est désactivé. Contactez un administrateur.", 403)
        with self.verrou, self.cx:
            self.cx.execute("UPDATE comptes SET echecs = 0, bloque_jusqua = NULL WHERE id = ?", (ligne["id"],))
        return _compte_public(ligne)

    # --------------------------------------------------------------- sessions
    def creer_session(self, compte_id: int, appareil: str = "") -> str:
        jeton = nouveau_jeton()
        t = maintenant()
        with self.verrou, self.cx:
            self.cx.execute(
                "INSERT INTO sessions (empreinte, compte_id, cree_le, vu_le, expire_le, appareil) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (empreinte_jeton(jeton), compte_id, horodatage(t), horodatage(t),
                 horodatage(t + DUREE_SESSION), appareil[:120]),
            )
            # Ménage : sessions expirées.
            self.cx.execute("DELETE FROM sessions WHERE expire_le < ?", (horodatage(t),))
        return jeton

    def compte_par_jeton(self, jeton: str | None) -> dict | None:
        """Compte actif lié au jeton, ou None. Prolonge la session (30 jours glissants)."""
        if not jeton:
            return None
        empreinte = empreinte_jeton(jeton)
        t = maintenant()
        with self.verrou:
            ligne = self._un(
                "SELECT s.vu_le, s.expire_le, c.* FROM sessions s JOIN comptes c ON c.id = s.compte_id "
                "WHERE s.empreinte = ?",
                (empreinte,),
            )
            if not ligne or lire_date(ligne["expire_le"]) < t or ligne["statut"] != "actif":
                return None
            if t - lire_date(ligne["vu_le"]) > timedelta(hours=1):
                with self.cx:
                    self.cx.execute(
                        "UPDATE sessions SET vu_le = ?, expire_le = ? WHERE empreinte = ?",
                        (horodatage(t), horodatage(t + DUREE_SESSION), empreinte),
                    )
        return _compte_public(ligne)

    def supprimer_session(self, jeton: str) -> None:
        with self.verrou, self.cx:
            self.cx.execute("DELETE FROM sessions WHERE empreinte = ?", (empreinte_jeton(jeton),))

    def supprimer_sessions_compte(self, compte_id: int) -> None:
        with self.verrou, self.cx:
            self.cx.execute("DELETE FROM sessions WHERE compte_id = ?", (compte_id,))

    # ---------------------------------------------------------- administration
    def lister_comptes(self) -> list[dict]:
        with self.verrou:
            lignes = self._plusieurs(
                "SELECT c.*, (SELECT COUNT(*) FROM sessions s WHERE s.compte_id = c.id AND s.expire_le > ?) "
                "AS sessions FROM comptes c ORDER BY "
                "CASE c.statut WHEN 'en_attente' THEN 0 WHEN 'actif' THEN 1 ELSE 2 END, c.nom COLLATE NOCASE",
                (horodatage(),),
            )
        return [{**_compte_public(l), "sessions": l["sessions"], "valide_par": l["valide_par"]} for l in lignes]

    def demandes_en_attente(self) -> int:
        with self.verrou:
            return self.cx.execute("SELECT COUNT(*) FROM comptes WHERE statut = 'en_attente'").fetchone()[0]

    def _exiger_compte(self, compte_id: int) -> dict:
        ligne = self._un("SELECT * FROM comptes WHERE id = ?", (compte_id,))
        if not ligne:
            raise ErreurMetier("Compte introuvable.", 404)
        return ligne

    def changer_statut(self, compte_id: int, statut: str, par: dict) -> dict:
        if statut not in ("actif", "refuse", "desactive"):
            raise ErreurMetier("Statut inconnu.")
        with self.verrou, self.cx:
            ligne = self._exiger_compte(compte_id)
            if ligne["id"] == par["id"] and statut != "actif":
                raise ErreurMetier("Vous ne pouvez pas désactiver votre propre compte.", 409)
            if ligne["role"] == "admin" and ligne["statut"] == "actif" and statut != "actif" and self._admins_actifs() <= 1:
                raise ErreurMetier("Il doit rester au moins un administrateur actif.", 409)
            valide_par = par["nom"] if ligne["statut"] == "en_attente" and statut == "actif" else ligne["valide_par"]
            self.cx.execute(
                "UPDATE comptes SET statut = ?, valide_par = ? WHERE id = ?", (statut, valide_par, compte_id)
            )
            if statut != "actif":
                self.cx.execute("DELETE FROM sessions WHERE compte_id = ?", (compte_id,))
            return _compte_public(self._un("SELECT * FROM comptes WHERE id = ?", (compte_id,)))

    def changer_role(self, compte_id: int, role: str, par: dict) -> dict:
        if role not in ("infirmier", "admin"):
            raise ErreurMetier("Rôle inconnu.")
        with self.verrou, self.cx:
            ligne = self._exiger_compte(compte_id)
            if ligne["role"] == "admin" and role != "admin" and ligne["statut"] == "actif" and self._admins_actifs() <= 1:
                raise ErreurMetier("Il doit rester au moins un administrateur actif.", 409)
            if ligne["id"] == par["id"] and role != "admin":
                raise ErreurMetier("Demandez à un autre administrateur de modifier votre rôle.", 409)
            self.cx.execute("UPDATE comptes SET role = ? WHERE id = ?", (role, compte_id))
            return _compte_public(self._un("SELECT * FROM comptes WHERE id = ?", (compte_id,)))

    def reinitialiser_mot_de_passe(self, compte_id: int) -> str:
        """Génère un mot de passe provisoire (à changer à la prochaine connexion)."""
        provisoire = mot_de_passe_temporaire()
        with self.verrou, self.cx:
            self._exiger_compte(compte_id)
            self.cx.execute(
                "UPDATE comptes SET mot_de_passe = ?, doit_changer = 1, echecs = 0, bloque_jusqua = NULL "
                "WHERE id = ?",
                (hacher_mot_de_passe(provisoire), compte_id),
            )
            self.cx.execute("DELETE FROM sessions WHERE compte_id = ?", (compte_id,))
        return provisoire

    def changer_mot_de_passe(self, compte_id: int, actuel: str, nouveau: str) -> None:
        with self.verrou:
            ligne = self._exiger_compte(compte_id)
        if not verifier_mot_de_passe(actuel, ligne["mot_de_passe"]):
            raise ErreurMetier("Mot de passe actuel incorrect.", 401)
        erreur = mot_de_passe_valide(nouveau)
        if erreur:
            raise ErreurMetier(erreur)
        if actuel == nouveau:
            raise ErreurMetier("Choisissez un mot de passe différent de l'actuel.")
        with self.verrou, self.cx:
            self.cx.execute(
                "UPDATE comptes SET mot_de_passe = ?, doit_changer = 0 WHERE id = ?",
                (hacher_mot_de_passe(nouveau), compte_id),
            )

    # =============================================================== CHAMBRES
    def lister_chambres(self, avec_codes: bool = False, avec_sejours: bool = False) -> list[dict]:
        with self.verrou:
            lignes = self._plusieurs("SELECT * FROM chambres ORDER BY service, CAST(id AS INTEGER), id")
        sejours = self.sejours_actifs() if avec_sejours else {}
        for l in lignes:
            l.pop("essais_sejour", None)
            if not avec_codes:
                l.pop("code", None)
            if avec_sejours:
                l["sejours"] = sejours.get(l["id"], [])
        return lignes

    def chambre(self, chambre_id: str) -> dict | None:
        with self.verrou:
            ligne = self._un("SELECT id, libelle, service, lits FROM chambres WHERE id = ?", (chambre_id,))
        return ligne

    def chambre_par_jeton(self, jeton: str) -> dict | None:
        """« 104-K7QM » → chambre 104, si le code correspond (casse indifférente)."""
        if "-" not in jeton:
            return None
        chambre_id, code = jeton.rsplit("-", 1)
        with self.verrou:
            ligne = self._un("SELECT * FROM chambres WHERE id = ?", (chambre_id,))
        if not ligne or not ligne["code"] or ligne["code"] != code.strip().upper():
            return None
        return {"id": ligne["id"], "libelle": ligne["libelle"], "service": ligne["service"], "lits": ligne["lits"]}

    def ajouter_chambre(self, chambre_id: str, libelle: str, service: str, lits: int = LITS_PAR_DEFAUT) -> dict:
        chambre_id = chambre_id.strip()
        if not 1 <= lits <= LITS_MAX:
            raise ErreurMetier(f"Nombre de lits : entre 1 et {LITS_MAX}.")
        if not chambre_id or not re.match(r"^[A-Za-z0-9]{1,12}$", chambre_id):
            raise ErreurMetier("Numéro de chambre : lettres et chiffres uniquement (12 au maximum).")
        with self.verrou, self.cx:
            if self._un("SELECT id FROM chambres WHERE id = ?", (chambre_id,)):
                raise ErreurMetier(f"La chambre {chambre_id} existe déjà.", 409)
            self.cx.execute(
                "INSERT INTO chambres (id, libelle, service, code, lits) VALUES (?, ?, ?, ?, ?)",
                (chambre_id, libelle.strip() or f"Salle {chambre_id}", service.strip(), nouveau_code_chambre(), lits),
            )
            return self._un("SELECT * FROM chambres WHERE id = ?", (chambre_id,))

    def changer_lits(self, chambre_id: str, lits: int) -> dict:
        if not 1 <= lits <= LITS_MAX:
            raise ErreurMetier(f"Nombre de lits : entre 1 et {LITS_MAX}.")
        with self.verrou, self.cx:
            if not self._un("SELECT id FROM chambres WHERE id = ?", (chambre_id,)):
                raise ErreurMetier("Chambre introuvable.", 404)
            occupe = [s["lit"] for s in self._sejours_actifs_chambre(chambre_id) if s["lit"] > lits]
            if occupe:
                raise ErreurMetier(
                    f"Impossible : le lit {max(occupe)} est occupé. Faites d'abord sortir ce patient.", 409
                )
            self.cx.execute("UPDATE chambres SET lits = ? WHERE id = ?", (lits, chambre_id))
            return self._un("SELECT * FROM chambres WHERE id = ?", (chambre_id,))

    def regenerer_code(self, chambre_id: str) -> dict:
        with self.verrou, self.cx:
            if self.cx.execute(
                "UPDATE chambres SET code = ? WHERE id = ?", (nouveau_code_chambre(), chambre_id)
            ).rowcount == 0:
                raise ErreurMetier("Chambre introuvable.", 404)
            return self._un("SELECT * FROM chambres WHERE id = ?", (chambre_id,))

    def supprimer_chambre(self, chambre_id: str) -> None:
        if self.alerte_active(chambre_id):
            raise ErreurMetier("Impossible : un appel est en cours dans cette chambre.", 409)
        with self.verrou, self.cx:
            self.cx.execute("DELETE FROM alertes WHERE chambre_id = ?", (chambre_id,))
            self.cx.execute(
                "DELETE FROM appareils_patient WHERE sejour_id IN (SELECT id FROM sejours WHERE chambre_id = ?)",
                (chambre_id,),
            )
            self.cx.execute("DELETE FROM sejours WHERE chambre_id = ?", (chambre_id,))
            if self.cx.execute("DELETE FROM chambres WHERE id = ?", (chambre_id,)).rowcount == 0:
                raise ErreurMetier("Chambre introuvable.", 404)

    # ================================================================ SÉJOURS
    _CHAMPS_SEJOUR = (
        "id", "chambre_id", "lit", "code", "initiales", "admis_le", "admis_par", "expire_le", "sortie_prevue",
    )
    SORTIE_PREVUE_MAX = timedelta(days=365)

    @classmethod
    def _valider_sortie_prevue(cls, valeur: str | None) -> datetime | None:
        """Date de sortie prévue (ISO 8601) : dans le futur, et dans moins d'un an."""
        if not valeur:
            return None
        try:
            date = datetime.fromisoformat(valeur.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ErreurMetier("Date de sortie invalide.")
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        t = maintenant()
        if date <= t + timedelta(minutes=1):
            raise ErreurMetier("La date de sortie doit être dans le futur.")
        if date > t + cls.SORTIE_PREVUE_MAX:
            raise ErreurMetier("La date de sortie doit être dans moins d'un an.")
        return date.astimezone(timezone.utc)

    def _sejour_public(self, ligne: dict | None) -> dict | None:
        return {k: ligne[k] for k in self._CHAMPS_SEJOUR} if ligne else None

    def _sejours_actifs_chambre(self, chambre_id: str) -> list[dict]:
        return self._plusieurs(
            "SELECT * FROM sejours WHERE chambre_id = ? AND sortie_le IS NULL AND expire_le > ? ORDER BY lit",
            (chambre_id, horodatage()),
        )

    def _sejour_actif_lit(self, chambre_id: str, lit: int) -> dict | None:
        return self._un(
            "SELECT * FROM sejours WHERE chambre_id = ? AND lit = ? AND sortie_le IS NULL AND expire_le > ? "
            "ORDER BY admis_le DESC LIMIT 1",
            (chambre_id, lit, horodatage()),
        )

    def sejours_actifs(self) -> dict[str, list[dict]]:
        """Patients admis, regroupés par salle et triés par lit."""
        with self.verrou:
            lignes = self._plusieurs(
                "SELECT * FROM sejours WHERE sortie_le IS NULL AND expire_le > ? ORDER BY chambre_id, lit",
                (horodatage(),),
            )
        resultat: dict[str, list[dict]] = {}
        for l in lignes:
            resultat.setdefault(l["chambre_id"], []).append(self._sejour_public(l))
        return resultat

    def _code_libre(self, chambre_id: str) -> str:
        """Code à 4 chiffres différent de ceux des autres lits de la salle."""
        pris = {s["code"] for s in self._sejours_actifs_chambre(chambre_id)}
        while True:
            code = f"{secrets.randbelow(10_000):04d}"
            if code not in pris:
                return code

    def _exiger_lit(self, chambre_id: str, lit: int) -> dict:
        chambre = self._un("SELECT * FROM chambres WHERE id = ?", (chambre_id,))
        if not chambre:
            raise ErreurMetier("Chambre introuvable.", 404)
        if not 1 <= lit <= chambre["lits"]:
            raise ErreurMetier(f"Cette salle compte {chambre['lits']} lit(s).", 400)
        return chambre

    def admettre(
        self, chambre_id: str, lit: int, initiales: str, par: str, sortie_prevue: str | None = None
    ) -> dict:
        """Ouvre un séjour sur un lit et renvoie le code à donner au patient.
        Avec une date de sortie prévue, le code est désactivé automatiquement à cette date ;
        sans date, il expire par sécurité au bout de DUREE_SEJOUR (30 jours)."""
        initiales = re.sub(r"[^A-Za-zÀ-ÿ. -]", "", initiales).strip().upper()[:6]
        prevue = self._valider_sortie_prevue(sortie_prevue)
        t = maintenant()
        with self.verrou, self.cx:
            self._exiger_lit(chambre_id, lit)
            if self._sejour_actif_lit(chambre_id, lit):
                raise ErreurMetier(f"Le lit {lit} est déjà occupé.", 409)
            sejour_id = uuid.uuid4().hex
            self.cx.execute(
                "INSERT INTO sejours (id, chambre_id, lit, code, initiales, admis_le, admis_par, expire_le, "
                "sortie_prevue) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (sejour_id, chambre_id, lit, self._code_libre(chambre_id), initiales, horodatage(t), par,
                 horodatage(prevue or t + DUREE_SEJOUR), horodatage(prevue) if prevue else None),
            )
            self.cx.execute("UPDATE chambres SET essais_sejour = 0 WHERE id = ?", (chambre_id,))
            return self._sejour_public(self._un("SELECT * FROM sejours WHERE id = ?", (sejour_id,)))

    def changer_code_sejour(self, chambre_id: str, lit: int) -> dict:
        """Nouveau code (si l'ancien a circulé) : le téléphone du patient devra le saisir."""
        with self.verrou, self.cx:
            sejour = self._sejour_actif_lit(chambre_id, lit)
            if not sejour:
                raise ErreurMetier(f"Aucun patient sur le lit {lit}.", 409)
            self.cx.execute("UPDATE sejours SET code = ? WHERE id = ?", (self._code_libre(chambre_id), sejour["id"]))
            self.cx.execute("DELETE FROM appareils_patient WHERE sejour_id = ?", (sejour["id"],))
            self.cx.execute("UPDATE chambres SET essais_sejour = 0 WHERE id = ?", (chambre_id,))
            return self._sejour_public(self._un("SELECT * FROM sejours WHERE id = ?", (sejour["id"],)))

    def modifier_sortie_prevue(self, chambre_id: str, lit: int, sortie_prevue: str | None) -> dict:
        """Change (ou retire) la date de sortie prévue d'un patient en cours de séjour."""
        prevue = self._valider_sortie_prevue(sortie_prevue)
        with self.verrou, self.cx:
            sejour = self._sejour_actif_lit(chambre_id, lit)
            if not sejour:
                raise ErreurMetier(f"Aucun patient sur le lit {lit}.", 409)
            expire = prevue or maintenant() + DUREE_SEJOUR
            self.cx.execute(
                "UPDATE sejours SET sortie_prevue = ?, expire_le = ? WHERE id = ?",
                (horodatage(prevue) if prevue else None, horodatage(expire), sejour["id"]),
            )
            return self._sejour_public(self._un("SELECT * FROM sejours WHERE id = ?", (sejour["id"],)))

    def cloturer_sejours_expires(self) -> list[dict]:
        """Sorties automatiques : séjours dont la date de sortie (ou l'expiration) est passée.
        Clôture aussi leurs appels restés ouverts. Renvoie les séjours clôturés."""
        t = horodatage()
        with self.verrou, self.cx:
            expires = self._plusieurs(
                "SELECT s.*, c.libelle AS chambre_libelle FROM sejours s JOIN chambres c ON c.id = s.chambre_id "
                "WHERE s.sortie_le IS NULL AND s.expire_le <= ?",
                (t,),
            )
            for s in expires:
                self.cx.execute(
                    "UPDATE sejours SET sortie_le = expire_le, sortie_par = 'Sortie automatique' WHERE id = ?",
                    (s["id"],),
                )
                self.cx.execute(
                    "UPDATE alertes SET statut = 'terminee', termine_le = ?, termine_par = 'Sortie automatique' "
                    "WHERE sejour_id = ? AND statut IN (?, ?)",
                    (t, s["id"], *STATUTS_ACTIFS),
                )
        return expires

    def sortie(self, chambre_id: str, lit: int, par: str) -> dict:
        """Clôture le séjour du lit : le téléphone de ce patient ne peut plus appeler."""
        with self.verrou, self.cx:
            sejour = self._sejour_actif_lit(chambre_id, lit)
            if not sejour:
                raise ErreurMetier(f"Aucun patient sur le lit {lit}.", 409)
            t = horodatage()
            self.cx.execute("UPDATE sejours SET sortie_le = ?, sortie_par = ? WHERE id = ?", (t, par, sejour["id"]))
            # Un appel resté ouvert pour ce patient est clôturé avec le séjour.
            self.cx.execute(
                "UPDATE alertes SET statut = 'terminee', termine_le = ?, termine_par = ? "
                "WHERE sejour_id = ? AND statut IN (?, ?)",
                (t, par, sejour["id"], *STATUTS_ACTIFS),
            )
            return self._sejour_public(self._un("SELECT * FROM sejours WHERE id = ?", (sejour["id"],)))

    def activer_appareil(self, chambre_id: str, code: str) -> str:
        """Le patient saisit son code : son téléphone est lié à SON séjour (donc à son lit)."""
        code = re.sub(r"\D", "", code)
        with self.verrou, self.cx:
            sejours = self._sejours_actifs_chambre(chambre_id)
            if not sejours:
                raise ErreurMetier("Cette salle n'est pas active. Demandez à l'infirmière d'activer votre accès.", 409)
            essais = self.cx.execute("SELECT essais_sejour FROM chambres WHERE id = ?", (chambre_id,)).fetchone()[0]
            if essais >= ESSAIS_CODE_SALLE_MAX:
                raise ErreurMetier("Trop d'essais. Demandez un nouveau code à l'infirmière.", 429)
            sejour = next((s for s in sejours if hmac.compare_digest(code, s["code"])), None)
            if sejour:
                jeton = nouveau_jeton()
                self.cx.execute(
                    "INSERT INTO appareils_patient (empreinte, sejour_id, cree_le) VALUES (?, ?, ?)",
                    (empreinte_jeton(jeton), sejour["id"], horodatage()),
                )
            else:
                # Enregistré AVANT de lever l'erreur (sinon la transaction l'annulerait).
                self.cx.execute("UPDATE chambres SET essais_sejour = essais_sejour + 1 WHERE id = ?", (chambre_id,))
        if not sejour:
            raise ErreurMetier("Code incorrect. Vérifiez le code donné par l'infirmière.", 401)
        return jeton

    def appareil(self, chambre_id: str, jeton: str | None) -> tuple[str, dict | None]:
        """
        Statut du téléphone du patient dans cette salle, et son séjour s'il est actif :
          actif        : lié à un séjour en cours → peut appeler (pour son lit)
          code_requis  : des patients sont admis, ce téléphone n'a pas (ou plus) de code valide
          termine      : ce téléphone appartenait à un séjour clôturé (patient sorti)
          libre        : aucun patient admis dans la salle
        """
        with self.verrou:
            lie = (
                self._un(
                    "SELECT s.* FROM appareils_patient a JOIN sejours s ON s.id = a.sejour_id WHERE a.empreinte = ?",
                    (empreinte_jeton(jeton),),
                )
                if jeton
                else None
            )
            if lie and lie["chambre_id"] == chambre_id:
                if lie["sortie_le"] is None and lire_date(lie["expire_le"]) > maintenant():
                    return "actif", self._sejour_public(lie)
                return "termine", None
            return ("code_requis" if self._sejours_actifs_chambre(chambre_id) else "libre"), None

    # ================================================================ ALERTES
    _SELECT_ALERTE = """
        SELECT a.*, c.libelle AS chambre_libelle, c.service AS chambre_service,
               COALESCE(s.initiales, '') AS patient_initiales
        FROM alertes a JOIN chambres c ON c.id = a.chambre_id
        LEFT JOIN sejours s ON s.id = a.sejour_id
    """

    def alerte(self, alerte_id: str) -> dict | None:
        with self.verrou:
            return self._un(self._SELECT_ALERTE + " WHERE a.id = ?", (alerte_id,))

    def alerte_active(self, chambre_id: str) -> dict | None:
        with self.verrou:
            return self._un(
                self._SELECT_ALERTE
                + " WHERE a.chambre_id = ? AND a.statut IN (?, ?) ORDER BY a.cree_le DESC LIMIT 1",
                (chambre_id, *STATUTS_ACTIFS),
            )

    def alerte_active_sejour(self, sejour_id: str) -> dict | None:
        with self.verrou:
            return self._un(
                self._SELECT_ALERTE
                + " WHERE a.sejour_id = ? AND a.statut IN (?, ?) ORDER BY a.cree_le DESC LIMIT 1",
                (sejour_id, *STATUTS_ACTIFS),
            )

    def creer_alerte(self, sejour: dict) -> tuple[dict, bool]:
        """Crée l'appel d'un patient (son lit). S'il a déjà un appel en cours, on le renvoie
        (un patient qui appuie plusieurs fois ne crée pas de doublons)."""
        existante = self.alerte_active_sejour(sejour["id"])
        if existante:
            return existante, False
        alerte_id = uuid.uuid4().hex
        with self.verrou, self.cx:
            self.cx.execute(
                "INSERT INTO alertes (id, chambre_id, lit, sejour_id, statut, cree_le) "
                "VALUES (?, ?, ?, ?, 'en_attente', ?)",
                (alerte_id, sejour["chambre_id"], sejour["lit"], sejour["id"], horodatage()),
            )
        return self.alerte(alerte_id), True

    def _exiger(self, alerte_id: str) -> dict:
        alerte = self.alerte(alerte_id)
        if not alerte:
            raise ErreurMetier("Appel introuvable.", 404)
        return alerte

    def accuser_reception(self, alerte_id: str, infirmier: str) -> dict:
        self._exiger(alerte_id)
        with self.verrou, self.cx:
            # La condition sur le statut garantit qu'une seule infirmière
            # « gagne » si deux appuient en même temps.
            modifie = self.cx.execute(
                "UPDATE alertes SET statut = 'prise_en_charge', accuse_le = ?, accuse_par = ? "
                "WHERE id = ? AND statut = 'en_attente'",
                (horodatage(), infirmier, alerte_id),
            ).rowcount
        alerte = self.alerte(alerte_id)
        if not modifie:
            if alerte["statut"] == "prise_en_charge":
                raise ErreurMetier(f"Déjà pris en charge par {alerte['accuse_par']}.", 409)
            raise ErreurMetier("Cet appel n'est plus actif.", 409)
        return alerte

    def terminer(self, alerte_id: str, infirmier: str) -> dict:
        self._exiger(alerte_id)
        with self.verrou, self.cx:
            modifie = self.cx.execute(
                "UPDATE alertes SET statut = 'terminee', termine_le = ?, termine_par = ? "
                "WHERE id = ? AND statut = 'prise_en_charge'",
                (horodatage(), infirmier, alerte_id),
            ).rowcount
        alerte = self.alerte(alerte_id)
        if not modifie:
            if alerte["statut"] == "en_attente":
                raise ErreurMetier("Accusez d'abord réception de l'appel.", 409)
            raise ErreurMetier("Cet appel n'est plus actif.", 409)
        return alerte

    def annuler_sejour(self, sejour_id: str) -> dict | None:
        """Le patient annule son appel en cours (s'il y en a un)."""
        alerte = self.alerte_active_sejour(sejour_id)
        if not alerte:
            return None
        with self.verrou, self.cx:
            self.cx.execute(
                "UPDATE alertes SET statut = 'annulee', annule_le = ? WHERE id = ? AND statut IN (?, ?)",
                (horodatage(), alerte["id"], *STATUTS_ACTIFS),
            )
        return self.alerte(alerte["id"])

    def alertes_visibles(self, heures: int = 12, limite_historique: int = 25) -> list[dict]:
        """Appels en cours + historique récent, pour le tableau des soignants."""
        depuis = horodatage(maintenant() - timedelta(hours=heures))
        with self.verrou:
            actives = self._plusieurs(
                self._SELECT_ALERTE + " WHERE a.statut IN (?, ?) ORDER BY a.cree_le ASC",
                STATUTS_ACTIFS,
            )
            historique = self._plusieurs(
                self._SELECT_ALERTE
                + " WHERE a.statut IN ('terminee', 'annulee') AND a.cree_le >= ?"
                " ORDER BY a.cree_le DESC LIMIT ?",
                (depuis, limite_historique),
            )
        return actives + historique

    def statistiques(self) -> dict:
        """Indicateurs des dernières 24 h."""
        depuis = horodatage(maintenant() - timedelta(hours=24))
        with self.verrou:
            lignes = self._plusieurs(
                "SELECT cree_le, accuse_le FROM alertes WHERE cree_le >= ? AND statut != 'annulee'",
                (depuis,),
            )
        delais = [
            (lire_date(l["accuse_le"]) - lire_date(l["cree_le"])).total_seconds()
            for l in lignes
            if l["accuse_le"]
        ]
        return {
            "appels_24h": len(lignes),
            "delai_moyen_s": round(sum(delais) / len(delais)) if delais else None,
            "delai_max_s": round(max(delais)) if delais else None,
        }

    # =============================================================== MESSAGES
    def messages(self, limite: int = 80) -> list[dict]:
        with self.verrou:
            lignes = self._plusieurs("SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limite,))
        return list(reversed(lignes))

    def ajouter_message(self, auteur: str, texte: str) -> dict:
        texte = texte.strip()
        if not texte:
            raise ErreurMetier("Message vide.")
        if len(texte) > 500:
            raise ErreurMetier("Message trop long (500 caractères maximum).")
        with self.verrou, self.cx:
            cur = self.cx.execute(
                "INSERT INTO messages (auteur, texte, cree_le) VALUES (?, ?, ?)",
                (auteur[:60], texte, horodatage()),
            )
            return self._un("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,))
