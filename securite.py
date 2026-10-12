"""
Sentinelle — outils de sécurité (bibliothèque standard Python uniquement).

  • Mots de passe : scrypt avec sel aléatoire, jamais stockés en clair.
  • Jetons de session : 256 bits aléatoires ; seule leur empreinte SHA-256
    est stockée, un vol de la base ne permet donc pas d'usurper une session.
  • Codes de chambre : courts (lisibles sur une affiche) mais imprévisibles.
  • Limiteur de débit : protège la connexion, l'inscription et les appels.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

# ----------------------------------------------------------------- mots de passe
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}
LONGUEUR_MIN_MOT_DE_PASSE = 8


def hacher_mot_de_passe(mot_de_passe: str) -> str:
    sel = secrets.token_bytes(16)
    empreinte = hashlib.scrypt(mot_de_passe.encode("utf-8"), salt=sel, **_SCRYPT)
    return f"scrypt${sel.hex()}${empreinte.hex()}"


def verifier_mot_de_passe(mot_de_passe: str, stocke: str | None) -> bool:
    if not stocke:
        # Calcul factice : même durée que l'identifiant existe ou non.
        hashlib.scrypt(b"x", salt=b"0" * 16, **_SCRYPT)
        return False
    try:
        algo, sel_hex, empreinte_hex = stocke.split("$")
        if algo != "scrypt":
            return False
        calcul = hashlib.scrypt(mot_de_passe.encode("utf-8"), salt=bytes.fromhex(sel_hex), **_SCRYPT)
        return hmac.compare_digest(calcul.hex(), empreinte_hex)
    except (ValueError, TypeError):
        return False


def mot_de_passe_valide(mot_de_passe: str) -> str | None:
    """Renvoie un message d'erreur, ou None si le mot de passe convient."""
    if len(mot_de_passe) < LONGUEUR_MIN_MOT_DE_PASSE:
        return f"Le mot de passe doit contenir au moins {LONGUEUR_MIN_MOT_DE_PASSE} caractères."
    if mot_de_passe.isdigit() or mot_de_passe.isalpha():
        return "Le mot de passe doit mélanger des lettres et des chiffres."
    return None


def mot_de_passe_temporaire() -> str:
    """Mot de passe provisoire lisible, donné par l'administrateur (ex. « Kq7m-Xp3t »)."""
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    while True:
        brut = "".join(secrets.choice(alphabet) for _ in range(8))
        if mot_de_passe_valide(brut) is None:
            return f"{brut[:4]}-{brut[4:]}"


# ------------------------------------------------------------------- sessions
def nouveau_jeton() -> str:
    return secrets.token_urlsafe(32)


def empreinte_jeton(jeton: str) -> str:
    return hashlib.sha256(jeton.encode("utf-8")).hexdigest()


# ---------------------------------------------------------- codes de chambre
# Sans caractères ambigus (0/O, 1/I/L) : facile à recopier depuis une affiche.
ALPHABET_CODE = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def nouveau_code_chambre(longueur: int = 4) -> str:
    return "".join(secrets.choice(ALPHABET_CODE) for _ in range(longueur))


# ------------------------------------------------------------ limiteur de débit
class Limiteur:
    """Au plus `maximum` événements par `fenetre` secondes et par clé (en mémoire)."""

    def __init__(self, maximum: int, fenetre: float):
        self.maximum = maximum
        self.fenetre = fenetre
        self._evenements: dict[str, deque[float]] = defaultdict(deque)
        self._verrou = threading.Lock()

    def _purger(self, file: deque[float], maintenant: float) -> None:
        while file and maintenant - file[0] > self.fenetre:
            file.popleft()

    def depasse(self, cle: str) -> bool:
        """Vrai si la clé a déjà atteint sa limite (sans compter de nouvel événement)."""
        with self._verrou:
            file = self._evenements[cle]
            self._purger(file, time.monotonic())
            return len(file) >= self.maximum

    def compter(self, cle: str) -> None:
        with self._verrou:
            maintenant = time.monotonic()
            file = self._evenements[cle]
            self._purger(file, maintenant)
            file.append(maintenant)

    def autoriser(self, cle: str) -> bool:
        """Compte l'événement s'il est permis ; renvoie False si la limite est atteinte."""
        with self._verrou:
            maintenant = time.monotonic()
            file = self._evenements[cle]
            self._purger(file, maintenant)
            if len(file) >= self.maximum:
                return False
            file.append(maintenant)
            return True
