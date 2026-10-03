"""Tests des routes : comptes, sécurité et analyse."""
import io
import os

from app import make_token
from detector import DetectorError
from extensions import db
from models import AnalysisResult, User
from tests.conftest import PASSWORD, png_bytes


def test_index_is_public(client):
    """La page d'accueil s'affiche sans connexion."""
    response = client.get('/')
    assert response.status_code == 200
    assert 'Connectez-vous pour analyser'.encode() in response.data


def test_register_then_verify(app, client):
    """Inscription puis validation avec un token signé."""
    client.post('/register', data={
        'username': 'bob1', 'email': 'bob@example.com',
        'password': PASSWORD, 'confirm_password': PASSWORD})
    with app.app_context():
        user = User.query.filter_by(username='bob1').first()
        assert user is not None and user.verified is False
        token = make_token(user)
    client.get(f'/verify/{token}')
    with app.app_context():
        assert User.query.filter_by(username='bob1').first().verified


def test_forged_token_is_rejected(app, client, make_user):
    """L'ancien format de token falsifiable ne valide plus aucun compte."""
    user_id = make_user('carl', verified=False)
    client.get('/verify/verify-1-123')
    with app.app_context():
        assert db.session.get(User, user_id).verified is False


def test_expired_token_is_rejected(app, client, make_user):
    """Un token expiré est refusé."""
    user_id = make_user('dana', verified=False)
    with app.app_context():
        token = make_token(db.session.get(User, user_id))
    app.config['VERIFY_TOKEN_MAX_AGE'] = -1
    client.get(f'/verify/{token}')
    with app.app_context():
        assert db.session.get(User, user_id).verified is False


def test_unverified_user_cannot_login(client, make_user):
    """Un compte non vérifié ne peut pas ouvrir de session."""
    make_user('erin', verified=False)
    client.post('/login', data={'username': 'erin', 'password': PASSWORD})
    with client.session_transaction() as session:
        assert 'user_id' not in session


def test_wrong_password(client, make_user):
    """Un mauvais mot de passe est refusé."""
    make_user()
    client.post('/login', data={'username': 'alice', 'password': 'faux'})
    with client.session_transaction() as session:
        assert 'user_id' not in session


def test_analyze_requires_login(client):
    """Sans connexion, /analyze redirige vers la page de connexion."""
    response = client.post('/analyze')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


def test_analyze_image_stores_result_and_deletes_upload(
        app, logged_client):
    """Une image est analysée, enregistrée, puis le fichier est supprimé."""
    response = logged_client.post(
        '/analyze',
        data={'files': (png_bytes(), 'photo.png')},
        content_type='multipart/form-data',
        follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        result = AnalysisResult.query.one()
        assert result.filename == 'photo.png'
        assert result.file_type == 'image'
        assert result.is_deepfake is True
        assert abs(result.fake_score - 0.9) < 1e-9
    assert os.listdir(app.config['UPLOAD_FOLDER']) == []
    assert '90 %'.encode() in response.data


def test_analyze_rejects_unsupported_format(app, logged_client):
    """Un format inconnu n'est ni analysé ni enregistré."""
    response = logged_client.post(
        '/analyze',
        data={'files': (io.BytesIO(b'MZ'), 'virus.exe')},
        content_type='multipart/form-data',
        follow_redirects=True)
    assert 'format non pris en charge'.encode() in response.data
    with app.app_context():
        assert AnalysisResult.query.count() == 0


def test_analyze_limits_number_of_files(app, logged_client):
    """Plus de 5 fichiers dans un envoi sont refusés."""
    files = [(png_bytes(), f'img{i}.png') for i in range(6)]
    logged_client.post(
        '/analyze', data={'files': files},
        content_type='multipart/form-data')
    with app.app_context():
        assert AnalysisResult.query.count() == 0


def test_detector_error_is_reported_not_stored(app, logged_client):
    """Une erreur du détecteur est affichée et rien n'est enregistré."""
    def broken(images):
        raise DetectorError('modèle indisponible')

    app.extensions['detector']._classifier = broken
    response = logged_client.post(
        '/analyze',
        data={'files': (png_bytes(), 'photo.png')},
        content_type='multipart/form-data',
        follow_redirects=True)
    assert 'modèle indisponible'.encode() in response.data
    with app.app_context():
        assert AnalysisResult.query.count() == 0
    assert os.listdir(app.config['UPLOAD_FOLDER']) == []
