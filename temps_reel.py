"""
Sentinelle — temps réel par AJAX (« sondage »), en secours des WebSockets.

Quand un écran ne peut pas garder de WebSocket ouvert (hébergeur qui ne les
accepte pas, comme PythonAnywhere, ou réseau qui les coupe), il interroge
le serveur toutes les quelques secondes :

  • GET /api/temps-reel/soignant?curseur=N   → événements depuis N + état complet
  • GET /api/temps-reel/borne/{jeton}        → état de la borne

Tout est stocké dans SQLite (et non en mémoire) pour fonctionner aussi quand
l'hébergeur lance plusieurs processus web en parallèle :

  • un journal des événements adressés aux soignants (messages, urgences,
    infos…), conservé quelques minutes ;
  • la présence des soignants connectés en AJAX (dernier passage).
"""

from __future__ import annotations

import json
import os
import time

from base import Base

# Un soignant reste « en ligne » tant qu'il a interrogé le serveur dans ce délai.
# Assez long pour couvrir les onglets en arrière-plan, que les navigateurs
# ralentissent à une requête par minute environ.
PRESENCE_S = int(os.environ.get("SENTINELLE_PRESENCE_S", "90"))
CONSERVATION_S = 600  # durée de conservation du journal (secondes)
LIMITE_EVENEMENTS = 200  # événements renvoyés au maximum par requête


class TempsReel:
    def __init__(self, base: Base) -> None:
        self.base = base
        with base.verrou, base.cx:
            base.cx.execute(
                """
                CREATE TABLE IF NOT EXISTS evenements_temps_reel (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    compte_id INTEGER,              -- NULL = tous les soignants
                    donnees   TEXT NOT NULL,
                    cree_le   REAL NOT NULL
                )
                """
            )
            base.cx.execute(
                "CREATE INDEX IF NOT EXISTS idx_evenements_temps_reel_cree "
                "ON evenements_temps_reel (cree_le)"
            )
            base.cx.execute(
                """
                CREATE TABLE IF NOT EXISTS presence_sondage (
                    compte_id INTEGER PRIMARY KEY,
                    vu_le     REAL NOT NULL
                )
                """
            )

    # ------------------------------------------------------------ journal
    def publier(self, donnees: dict, compte_id: int | None = None) -> None:
        """Ajoute un événement au journal (compte_id None = pour tous les soignants)."""
        t = time.time()
        with self.base.verrou, self.base.cx:
            self.base.cx.execute(
                "INSERT INTO evenements_temps_reel (compte_id, donnees, cree_le) VALUES (?, ?, ?)",
                (compte_id, json.dumps(donnees, ensure_ascii=False), t),
            )
            self.base.cx.execute(
                "DELETE FROM evenements_temps_reel WHERE cree_le < ?", (t - CONSERVATION_S,)
            )

    def dernier_id(self) -> int:
        with self.base.verrou:
            ligne = self.base.cx.execute("SELECT MAX(id) FROM evenements_temps_reel").fetchone()
        return ligne[0] or 0

    def depuis(self, curseur: int, compte_id: int) -> tuple[list[dict], int]:
        """Événements destinés à ce compte, postérieurs au curseur. Renvoie (événements, nouveau curseur)."""
        dernier = self.dernier_id()
        if curseur > dernier:  # base réinitialisée : on repart du présent
            return [], dernier
        with self.base.verrou:
            lignes = self.base.cx.execute(
                "SELECT id, donnees FROM evenements_temps_reel "
                "WHERE id > ? AND id <= ? AND (compte_id IS NULL OR compte_id = ?) "
                "ORDER BY id LIMIT ?",
                (curseur, dernier, compte_id, LIMITE_EVENEMENTS),
            ).fetchall()
        if len(lignes) == LIMITE_EVENEMENTS:
            dernier = lignes[-1][0]
        return [json.loads(l[1]) for l in lignes], dernier

    # ------------------------------------------------------------ présence
    def marquer_present(self, compte_id: int) -> bool:
        """Enregistre le passage du soignant. Renvoie True s'il n'était pas déjà en ligne."""
        t = time.time()
        with self.base.verrou, self.base.cx:
            ligne = self.base.cx.execute(
                "SELECT vu_le FROM presence_sondage WHERE compte_id = ?", (compte_id,)
            ).fetchone()
            self.base.cx.execute(
                "INSERT INTO presence_sondage (compte_id, vu_le) VALUES (?, ?) "
                "ON CONFLICT(compte_id) DO UPDATE SET vu_le = excluded.vu_le",
                (compte_id, t),
            )
        return ligne is None or t - ligne[0] > PRESENCE_S

    def retirer(self, compte_id: int) -> None:
        with self.base.verrou, self.base.cx:
            self.base.cx.execute("DELETE FROM presence_sondage WHERE compte_id = ?", (compte_id,))

    def presents(self) -> list[dict]:
        """Comptes actifs ayant interrogé le serveur récemment (id, nom, rôle)."""
        with self.base.verrou:
            lignes = self.base.cx.execute(
                "SELECT c.id, c.nom, c.role FROM presence_sondage p JOIN comptes c ON c.id = p.compte_id "
                "WHERE p.vu_le >= ? AND c.statut = 'actif'",
                (time.time() - PRESENCE_S,),
            ).fetchall()
        return [{"id": l[0], "nom": l[1], "role": l[2]} for l in lignes]
