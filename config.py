"""Configuration de l'application, lue depuis les variables d'environnement.

Les valeurs sensibles (clé secrète, identifiants mail) ne doivent jamais
être écrites dans le code : elles vont dans un fichier `.env` non versionné.
"""
import os

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name, default):
    """Lit une variable d'environnement booléenne (1, true, yes, on)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


class Config:
    """Paramètres par défaut, surchargeables par l'environnement."""

    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 'sqlite:///database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER')
    MAX_CONTENT_LENGTH = (
        int(os.environ.get('MAX_UPLOAD_MB', '100')) * 1024 * 1024)
    MAX_FILES_PER_REQUEST = 5

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', False)
    WTF_CSRF_ENABLED = True

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = _env_bool('MAIL_USE_TLS', True)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    VERIFY_TOKEN_MAX_AGE = 3600

    MODEL_ID = os.environ.get(
        'DEEPFAKE_MODEL', 'prithivMLmods/Deep-Fake-Detector-Model')
    FAKE_THRESHOLD = float(os.environ.get('FAKE_THRESHOLD', '0.5'))
    MAX_VIDEO_FRAMES = int(os.environ.get('MAX_VIDEO_FRAMES', '16'))
    USE_FACE_CROP = _env_bool('USE_FACE_CROP', True)
