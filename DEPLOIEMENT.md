# Déploiement de Sentinelle

Le backend fonctionne de deux façons, sans changer le code :

| Hébergement | Lancement | Temps réel | Frontend |
|---|---|---|---|
| **PythonAnywhere** (maintenant) | `wsgi.py` | AJAX (requêtes toutes les 3 s) | `NEXT_PUBLIC_WEBSOCKET=off` |
| **VPS Hostinger** (plus tard) | `uvicorn` (voir `Dockerfile`) | WebSocket, AJAX en secours | variable retirée |

---

## 1. Backend sur PythonAnywhere

### Première installation

1. Ouvrez une console **Bash** (onglet *Consoles*).
2. Récupérez le code et préparez l'environnement :

   ```bash
   git clone https://github.com/VOTRE_COMPTE/Sentinelle-la-colombe-backend.git
   mkdir -p ~/donnees
   mkvirtualenv sentinelle --python=python3.12
   cd ~/Sentinelle-la-colombe-backend
   pip install -r requirements.txt
   cp .env.example .env
   python generer_cles_push.py     # copiez les 2 lignes affichées dans .env
   nano .env                       # remplacez VOTRE_NOM, l'adresse Vercel, l'e-mail
   ```

   Dépôt privé : GitHub demande un *personal access token* à la place du mot de passe
   (ou ajoutez une clé SSH à votre compte GitHub).

3. Onglet **Web** → *Add a new web app* → **Manual configuration** → la même version de Python (3.12).
4. Dans cette page :
   - **Virtualenv** : `/home/VOTRE_NOM/.virtualenvs/sentinelle`
   - **Source code** : `/home/VOTRE_NOM/Sentinelle-la-colombe-backend`
   - **Force HTTPS** : activé
   - Cliquez sur le lien du **WSGI configuration file**, effacez tout et mettez :

     ```python
     import sys
     sys.path.insert(0, "/home/VOTRE_NOM/Sentinelle-la-colombe-backend")
     from wsgi import application
     ```

5. Bouton vert **Reload**, puis vérifiez `https://VOTRE_NOM.pythonanywhere.com/api/sante`
   → `{"ok": true, ...}`. En cas d'erreur, consultez l'*Error log* de l'onglet Web.

### À chaque mise à jour

```bash
cd ~/Sentinelle-la-colombe-backend
git pull
workon sentinelle && pip install -r requirements.txt   # seulement si requirements.txt a changé
```

Puis onglet **Web** → **Reload** (sans cela, l'ancien code continue de tourner).

### À savoir

- La base (`SENTINELLE_BD`) est dans `~/donnees`, **hors du dépôt** : `git pull` ne la touche jamais.
  Pensez à la télécharger de temps en temps (onglet *Files*) comme sauvegarde.
- Les sorties automatiques sont vérifiées à chaque requête des écrans (au plus toutes les 30 s) :
  il n'y a pas de tâche de fond à configurer.
- **Compte gratuit** : les connexions sortantes sont limitées à une liste de sites autorisés.
  Si les notifications push n'arrivent pas (voir *Error log* : « Échec push »), il faut un compte payant.
- Le compte gratuit n'a qu'un processus web : il convient pour un essai. Pour un vrai service,
  prenez un compte payant ou passez au VPS.

---

## 2. Frontend sur Vercel

1. *Add New Project* → importez le dépôt du frontend.
2. **Environment Variables** :
   - `NEXT_PUBLIC_API_URL` = `https://VOTRE_NOM.pythonanywhere.com`
   - `NEXT_PUBLIC_WEBSOCKET` = `off`
3. *Deploy*. Ensuite, chaque `git push` redéploie automatiquement.
4. Dans le `.env` du backend, mettez l'adresse obtenue dans `SENTINELLE_ORIGINES`
   (ex. `https://sentinelle.vercel.app`), puis **Reload**.

Une variable `NEXT_PUBLIC_…` est intégrée au moment de la construction : après l'avoir modifiée
sur Vercel, relancez un déploiement (*Deployments* → *Redeploy*).

---

## 3. Plus tard : passage au VPS Hostinger

1. Sur le VPS, lancez le backend avec uvicorn (le `Dockerfile` fait déjà tout), derrière Caddy pour le HTTPS.
2. Copiez la base de PythonAnywhere (`~/donnees/sentinelle.db`) sur le VPS, à l'emplacement de `SENTINELLE_BD`.
3. Sur Vercel : changez `NEXT_PUBLIC_API_URL` vers le VPS et **supprimez** `NEXT_PUBLIC_WEBSOCKET`, puis redéployez.

Les écrans reviennent alors aux WebSockets. Si un réseau bloque les WebSockets
(certains Wi-Fi d'hôpital), l'AJAX prend le relais tout seul au bout de 8 secondes.
