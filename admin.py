"""
Sentinelle — dépannage des comptes en ligne de commande (sur le serveur).

    python admin.py lister
    python admin.py creer-admin <identifiant> "<Nom complet>"
    python admin.py reinitialiser <identifiant>

Utile si l'unique administrateur a oublié son mot de passe.
"""

from __future__ import annotations

import getpass
import sys

from base import Base, ErreurMetier


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("lister", "creer-admin", "reinitialiser"):
        print(__doc__)
        return 1
    base = Base()
    commande = sys.argv[1]

    if commande == "lister":
        for c in base.lister_comptes():
            print(f"  {c['identifiant']:<20} {c['nom']:<28} {c['role']:<10} {c['statut']}")
        return 0

    if commande == "creer-admin":
        if len(sys.argv) < 4:
            print('Usage : python admin.py creer-admin <identifiant> "<Nom complet>"')
            return 1
        mot_de_passe = getpass.getpass("Mot de passe : ")
        if mot_de_passe != getpass.getpass("Confirmez : "):
            print("Les mots de passe ne correspondent pas.")
            return 1
        try:
            compte, _ = base.inscrire(sys.argv[2], sys.argv[3], mot_de_passe)
        except ErreurMetier as e:
            print(e.message)
            return 1
        with base.verrou, base.cx:
            base.cx.execute("UPDATE comptes SET role = 'admin', statut = 'actif' WHERE id = ?", (compte["id"],))
        print(f"Administrateur « {compte['identifiant']} » créé et actif.")
        return 0

    if len(sys.argv) < 3:
        print("Usage : python admin.py reinitialiser <identifiant>")
        return 1
    ligne = base.cx.execute("SELECT id FROM comptes WHERE identifiant = ?", (sys.argv[2].lower(),)).fetchone()
    if not ligne:
        print("Identifiant introuvable.")
        return 1
    provisoire = base.reinitialiser_mot_de_passe(ligne["id"])
    with base.verrou, base.cx:
        base.cx.execute("UPDATE comptes SET statut = 'actif' WHERE id = ?", (ligne["id"],))
    print(f"Mot de passe provisoire : {provisoire}  (à changer à la prochaine connexion)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
