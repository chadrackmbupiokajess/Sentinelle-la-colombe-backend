"""Génère une paire de clés VAPID à copier dans le fichier .env du déploiement."""

import base64

from cryptography.hazmat.primitives.asymmetric import ec


def base64url(donnees: bytes) -> str:
    return base64.urlsafe_b64encode(donnees).decode("ascii").rstrip("=")


def main() -> None:
    cle = ec.generate_private_key(ec.SECP256R1())
    privee = cle.private_numbers().private_value.to_bytes(32, "big")
    publique = cle.public_key().public_numbers()
    cle_publique = b"\x04" + publique.x.to_bytes(32, "big") + publique.y.to_bytes(32, "big")
    print("SENTINELLE_VAPID_PUBLIC_KEY=" + base64url(cle_publique))
    print("SENTINELLE_VAPID_PRIVATE_KEY=" + base64url(privee))


if __name__ == "__main__":
    main()
