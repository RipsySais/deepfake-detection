from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """Modèle représentant un utilisateur."""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        """Retourne une représentation lisible de l'utilisateur."""
        return f"<User {self.username}>"


class AnalysisResult(db.Model):
    """Modèle représentant le résultat d'une analyse de fichier."""
    __tablename__ = 'analysis_result'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    is_deepfake = db.Column(db.Boolean, nullable=False)
    details = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        """Retourne une représentation lisible du résultat d'analyse."""
        return f"<AnalysisResult {self.filename}>"
