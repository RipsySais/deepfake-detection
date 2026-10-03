# DeepDetect

Application web Flask qui estime si une image ou une vidéo est un deepfake,
à l'aide d'un modèle de vision pré-entraîné (Vision Transformer).

> Le score est une **estimation**, pas une preuve. Aucun détecteur n'est
> infaillible, surtout face à des manipulations absentes de ses données
> d'entraînement. Croisez toujours avec d'autres sources.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Git Bash Windows : source .venv/Scripts/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
cp .env.example .env               # puis renseigner SECRET_KEY
```

Générer une clé secrète :

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Lancer

```bash
flask --app app load-model         # optionnel : télécharge le modèle à l'avance
python app.py                      # http://127.0.0.1:5000
```

Sans `MAIL_USERNAME`, aucun email n'est envoyé : le lien de vérification
s'affiche dans la console du serveur (pratique en développement).

## Tests et style

```bash
pip install -r requirements-dev.txt
pytest
pycodestyle .
```

## Structure

| Fichier | Rôle |
|---|---|
| `app.py` | Routes, authentification, `create_app` |
| `detector.py` | Chargement du modèle, extraction d'images vidéo, scores |
| `models.py` | Tables `User` et `AnalysisResult` |
| `forms.py` | Formulaires de connexion et d'inscription |
| `config.py` | Réglages lus dans `.env` |
| `extensions.py` | Objets Flask partagés (db, bcrypt, mail, csrf) |
| `tests/` | Tests des routes et du détecteur |

## Changer de modèle

Le modèle se règle avec `DEEPFAKE_MODEL` dans `.env`. Il doit être un
classifieur d'images Hugging Face dont l'un des labels contient « fake »
(Fake, Deepfake...). Un modèle entraîné par vos soins s'utilise de la même
façon, avec son chemin local ou son identifiant Hugging Face.

## Limites connues

- Les modèles d'images ne détectent pas les incohérences temporelles d'une
  vidéo : chaque image est jugée séparément.
- La précision dépend fortement du type de deepfake et de la qualité du
  fichier (compression, recadrage).
- Pas encore de limitation du nombre de requêtes par utilisateur.
