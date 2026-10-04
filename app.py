"""Application Flask DeepDetect : comptes utilisateurs et analyse de médias."""
import logging
import os
import secrets
import smtplib
import uuid
from functools import wraps

from flask import (Flask, current_app, flash, g, redirect, render_template,
                   request, session, url_for)
from flask_mail import Message
from itsdangerous import (BadSignature, SignatureExpired,
                          URLSafeTimedSerializer)
from sqlalchemy import inspect, text
from werkzeug.utils import secure_filename

from config import Config
from detector import DeepfakeDetector, DetectorError, file_kind
from extensions import bcrypt, csrf, db, mail
from forms import LoginForm, RegisterForm
from models import AnalysisResult, User

VERIFY_SALT = 'email-verify'


def create_app(config=None, detector=None):
    """Crée et configure l'application (utile aussi pour les tests)."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)

    if not app.config.get('SECRET_KEY'):
        app.logger.warning(
            'SECRET_KEY absente : une clé temporaire est utilisée, les '
            'sessions seront perdues au redémarrage.')
        app.config['SECRET_KEY'] = secrets.token_hex(32)
    if not app.config.get('UPLOAD_FOLDER'):
        app.config['UPLOAD_FOLDER'] = os.path.join(
            app.instance_path, 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    if detector is None:
        detector = DeepfakeDetector(
            model_id=app.config['MODEL_ID'],
            threshold=app.config['FAKE_THRESHOLD'],
            max_frames=app.config['MAX_VIDEO_FRAMES'],
            use_face_crop=app.config['USE_FACE_CROP'])
    app.extensions['detector'] = detector

    with app.app_context():
        db.create_all()
        upgrade_schema()

    register_hooks(app)
    register_routes(app)
    register_commands(app)
    return app


def upgrade_schema():
    """Ajoute les colonnes apparues après la création de la base.

    `db.create_all()` crée les tables manquantes mais ne modifie jamais une
    table existante : cette mini-migration ajoute `faces_found` aux bases
    créées par la version précédente. (À terme, Flask-Migrate fait ce travail
    proprement.)
    """
    inspector = inspect(db.engine)
    columns = {c['name'] for c in inspector.get_columns('analysis_result')}
    if 'faces_found' not in columns:
        with db.engine.begin() as connection:
            connection.execute(text(
                'ALTER TABLE analysis_result ADD COLUMN faces_found INTEGER'))


def login_required(view):
    """Réserve une route aux utilisateurs connectés et vérifiés."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash('Veuillez vous connecter pour continuer.', 'error')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def make_token(user):
    """Crée un token signé et daté pour vérifier l'email d'un utilisateur."""
    serializer = URLSafeTimedSerializer(
        current_app.config['SECRET_KEY'], salt=VERIFY_SALT)
    return serializer.dumps({'uid': user.id})


def read_token(token):
    """Retourne l'id utilisateur d'un token valide, sinon None."""
    serializer = URLSafeTimedSerializer(
        current_app.config['SECRET_KEY'], salt=VERIFY_SALT)
    try:
        data = serializer.loads(
            token, max_age=current_app.config['VERIFY_TOKEN_MAX_AGE'])
    except (BadSignature, SignatureExpired):
        return None
    return data.get('uid') if isinstance(data, dict) else None


def send_verification(user):
    """Envoie le lien de vérification ; retourne False en mode développement.

    Sans MAIL_USERNAME, aucun email n'est envoyé : le lien est écrit dans les
    logs du serveur pour pouvoir tester l'inscription en local.
    """
    link = url_for('verify_email', token=make_token(user), _external=True)
    if not current_app.config['MAIL_USERNAME']:
        current_app.logger.warning('Lien de vérification : %s', link)
        return False
    message = Message(
        'Vérification de votre email',
        sender=current_app.config['MAIL_USERNAME'],
        recipients=[user.email])
    message.body = (
        f'Bonjour {user.username},\n\nCliquez sur ce lien pour vérifier '
        f'votre email (valable 1 heure) :\n{link}\n')
    mail.send(message)
    return True


def register_hooks(app):
    """Déclare les fonctions exécutées avant chaque requête."""
    @app.before_request
    def load_user():
        """Charge l'utilisateur connecté (ou None) dans `g.user`."""
        g.user = None
        user_id = session.get('user_id')
        if user_id is not None:
            user = db.session.get(User, user_id)
            if user is not None and user.verified:
                g.user = user
            else:
                session.clear()

    @app.errorhandler(413)
    def too_large(error):
        """Réponse quand l'envoi dépasse la taille maximale."""
        limit = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
        flash(f'Fichiers trop volumineux (maximum {limit} Mo).', 'error')
        return redirect(url_for('index', _anchor='analyse'))

    @app.template_filter('percent')
    def percent(value):
        """Formate une probabilité (0 à 1) en pourcentage."""
        return f'{value * 100:.0f} %'


def register_routes(app):
    """Déclare les routes de l'application."""

    @app.route('/')
    def index():
        """Page d'accueil, avec l'historique si l'utilisateur est connecté."""
        results = []
        if g.user is not None:
            results = (AnalysisResult.query
                       .filter_by(user_id=g.user.id)
                       .order_by(AnalysisResult.timestamp.desc())
                       .limit(20).all())
        return render_template('index.html', results=results)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Connexion d'un utilisateur dont l'email est vérifié."""
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            valid = user and bcrypt.check_password_hash(
                user.password, form.password.data)
            if valid and not user.verified:
                flash('Email non vérifié : consultez le lien reçu.', 'error')
            elif valid:
                session.clear()
                session['user_id'] = user.id
                flash('Connexion réussie !', 'success')
                return redirect(url_for('index'))
            else:
                flash("Nom d'utilisateur ou mot de passe incorrect.", 'error')
        return render_template('login.html', form=form)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """Inscription puis envoi du lien de vérification."""
        form = RegisterForm()
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data.lower()
            taken = (User.query.filter_by(username=username).first()
                     or User.query.filter_by(email=email).first())
            if taken:
                flash('Utilisateur ou email déjà existant.', 'error')
                return redirect(url_for('register'))

            hashed = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')
            user = User(username=username, email=email, password=hashed)
            db.session.add(user)
            db.session.commit()
            try:
                sent = send_verification(user)
            except (smtplib.SMTPException, OSError):
                app.logger.exception('Échec de l\'envoi de l\'email')
                db.session.delete(user)
                db.session.commit()
                flash("L'email n'a pas pu être envoyé. Réessayez plus "
                      "tard.", 'error')
                return redirect(url_for('register'))
            if sent:
                flash('Un email de vérification a été envoyé.', 'success')
            else:
                flash('Mode développement : le lien de vérification est '
                      'affiché dans la console du serveur.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/verify/<token>')
    def verify_email(token):
        """Active le compte si le token signé est valide et non expiré."""
        user_id = read_token(token)
        user = db.session.get(User, user_id) if user_id else None
        if user is None:
            flash('Lien de vérification invalide ou expiré.', 'error')
        else:
            user.verified = True
            db.session.commit()
            flash('Email vérifié ! Vous pouvez vous connecter.', 'success')
        return redirect(url_for('login'))

    @app.route('/logout')
    def logout():
        """Déconnexion."""
        session.clear()
        flash('Déconnexion réussie !', 'success')
        return redirect(url_for('login'))

    @app.post('/analyze')
    @login_required
    def analyze():
        """Analyse les fichiers envoyés puis enregistre les résultats."""
        files = [f for f in request.files.getlist('files') if f.filename]
        back = redirect(url_for('index', _anchor='analyse'))
        if not files:
            flash('Aucun fichier sélectionné.', 'error')
            return back
        limit = app.config['MAX_FILES_PER_REQUEST']
        if len(files) > limit:
            flash(f'Maximum {limit} fichiers par analyse.', 'error')
            return back

        detector = app.extensions['detector']
        done = 0
        for upload in files:
            name = secure_filename(upload.filename) or 'fichier'
            kind = file_kind(name)
            if kind is None:
                flash(f'« {name} » : format non pris en charge.', 'error')
                continue
            path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                f"{uuid.uuid4().hex}.{name.rsplit('.', 1)[1].lower()}")
            upload.save(path)
            try:
                verdict = detector.analyze(path, kind)
            except DetectorError as error:
                flash(f'« {name} » : {error}', 'error')
                continue
            except Exception:
                app.logger.exception('Erreur pendant l\'analyse de %s', name)
                flash(f'« {name} » : erreur inattendue pendant l\'analyse.',
                      'error')
                continue
            finally:
                if os.path.exists(path):
                    os.remove(path)
            db.session.add(AnalysisResult(
                filename=name,
                file_type=kind,
                fake_score=verdict.fake_probability,
                is_deepfake=verdict.is_deepfake,
                frames_analyzed=verdict.frames_analyzed,
                faces_found=verdict.faces_found,
                details=verdict.details,
                user_id=g.user.id))
            done += 1
        db.session.commit()
        if done:
            flash(f'{done} fichier(s) analysé(s).', 'success')
        return back


def register_commands(app):
    """Déclare les commandes `flask --app app <commande>`."""
    @app.cli.command('load-model')
    def load_model():
        """Télécharge et charge le modèle à l'avance."""
        app.extensions['detector'].load()
        print('Modèle chargé.')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    create_app().run(debug=os.environ.get('FLASK_DEBUG') == '1')
