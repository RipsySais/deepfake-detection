"""Fixtures partagées : application de test avec un faux classifieur."""
import io

import pytest
from PIL import Image

from app import create_app
from detector import DeepfakeDetector
from extensions import bcrypt, db
from models import User

PASSWORD = 'motdepasse1'


def fixed_classifier(value):
    """Retourne un classifieur qui donne toujours la même probabilité."""
    return lambda images: [value] * len(images)


@pytest.fixture
def app(tmp_path):
    """Application isolée : base SQLite et dossier d'upload temporaires."""
    detector = DeepfakeDetector(
        model_id='test', classifier=fixed_classifier(0.9),
        use_face_crop=False)
    application = create_app({
        'TESTING': True,
        'SECRET_KEY': 'test-secret',
        'SQLALCHEMY_DATABASE_URI': f"sqlite:///{tmp_path / 'test.db'}",
        'UPLOAD_FOLDER': str(tmp_path / 'uploads'),
        'WTF_CSRF_ENABLED': False,
        'MAIL_USERNAME': '',
    }, detector=detector)
    yield application
    with application.app_context():
        db.session.remove()


@pytest.fixture
def client(app):
    """Client HTTP de test."""
    return app.test_client()


@pytest.fixture
def make_user(app):
    """Fabrique un utilisateur et retourne son id."""
    def factory(username='alice', verified=True):
        with app.app_context():
            user = User(
                username=username,
                email=f'{username}@example.com',
                password=bcrypt.generate_password_hash(PASSWORD).decode(),
                verified=verified)
            db.session.add(user)
            db.session.commit()
            return user.id
    return factory


@pytest.fixture
def logged_client(client, make_user):
    """Client déjà connecté en tant qu'utilisateur vérifié."""
    make_user()
    client.post('/login', data={'username': 'alice', 'password': PASSWORD})
    return client


def png_bytes():
    """Génère une petite image PNG en mémoire."""
    buffer = io.BytesIO()
    Image.new('RGB', (64, 64), (120, 80, 200)).save(buffer, format='PNG')
    buffer.seek(0)
    return buffer
