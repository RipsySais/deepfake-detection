"""Modèles de base de données (utilisateurs et résultats d'analyse)."""
from datetime import datetime, timezone

from extensions import db


def _now():
    """Retourne l'heure UTC courante."""
    return datetime.now(timezone.utc)


class User(db.Model):
    """Utilisateur inscrit, éventuellement avec son email vérifié."""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    verified = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        """Retourne une représentation lisible de l'utilisateur."""
        return f"<User {self.username}>"


class AnalysisResult(db.Model):
    """Résultat de l'analyse d'un fichier image ou vidéo.

    `fake_score` est la probabilité (0 à 1) que le contenu soit manipulé,
    telle qu'estimée par le modèle. C'est une indication, pas une preuve.
    """
    __tablename__ = 'analysis_result'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    fake_score = db.Column(db.Float, nullable=False)
    is_deepfake = db.Column(db.Boolean, nullable=False)
    frames_analyzed = db.Column(db.Integer, nullable=False, default=1)
    faces_found = db.Column(db.Integer)
    details = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=_now, nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)

    def __repr__(self):
        """Retourne une représentation lisible du résultat d'analyse."""
        return f"<AnalysisResult {self.filename}>"
