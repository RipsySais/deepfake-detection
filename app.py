from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.utils import secure_filename
import os
import time
from datetime import datetime
from deepface import DeepFace

app = Flask(__name__)
app.secret_key = 'your_secret_key_2025'  # Remplacez par une clé sécurisée
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Remplacez par votre email
app.config['MAIL_PASSWORD'] = 'your_app_password'     # Mot de passe d'application Gmail
app.config['WTF_CSRF_ENABLED'] = True

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
csrf = CSRFProtect(app)


# Modèles
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    verified = db.Column(db.Boolean, default=False)


class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    is_deepfake = db.Column(db.Boolean, nullable=False)
    details = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()


# Formulaires
class LoginForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Connexion')


class RegisterForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired(), Length(min=4, max=80)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6),
                             EqualTo('confirm_password', message='Les mots de passe doivent correspondre')])
    confirm_password = PasswordField('Confirmer le mot de passe', validators=[DataRequired()])
    submit = SubmitField("S'inscrire")


# Routes
@app.route('/')
def index():
    if 'user_id' not in session or not User.query.get(session['user_id']).verified:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    results = AnalysisResult.query.filter_by(user_id=session['user_id']) \
                                  .order_by(AnalysisResult.timestamp.desc()) \
                                  .all()
    return render_template('index.html', username=user.username, results=results)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password) and user.verified:
            session['user_id'] = user.id
            flash('Connexion réussie !', 'success')
            return redirect(url_for('index'))
        flash("Nom d'utilisateur, mot de passe ou email non vérifié incorrect.", 'error')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Utilisateur ou email déjà existant.', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Envoyer email de vérification
        token = f"verify-{new_user.id}-{time.time()}"  # Token simple (à améliorer)
        msg = Message('Vérification de votre email',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f" Cliquez ici pour vérifier votre email : {url_for('verify_email', token=token, _external=True)}"
        mail.send(msg)

        flash('Un email de vérification a été envoyé. Vérifiez votre boîte.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/verify/<token>')
def verify_email(token):
    try:
        user_id = int(token.split('-')[1])
        user = User.query.get(user_id)
        is_valid = time.time() - float(token.split('-')[2]) < 3600  # 1 heure de validité
        if user and not user.verified and is_valid:
            user.verified = True
            db.session.commit()
            flash('Email vérifié avec succès ! Connectez-vous.', 'success')
        else:
            flash('Lien de vérification invalide ou expiré.', 'error')
    except (IndexError, ValueError):
        flash('Lien de vérification invalide.', 'error')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Déconnexion réussie !', 'success')
    return redirect(url_for('login'))


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session or not User.query.get(session['user_id']).verified:
        flash('Veuillez vous connecter et vérifier votre email.', 'error')
        return redirect(url_for('login'))

    files = request.files.getlist('files')
    new_results = []

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            try:
                result = DeepFace.verify(
                    img1_path=file_path,
                    model_name='DeepFace',
                    detector_backend='opencv'
                )
                confidence = result['distance'] * 100  # À calibrer
                is_deepfake = confidence > 70  # Seuil ajustable
                details = "Deepfake détecté" if is_deepfake else "Authentique"
            except Exception as e:
                confidence = 0
                is_deepfake = False
                details = f"Erreur d'analyse : {str(e)}"

            record = AnalysisResult(
                filename=filename,
                file_type='image' if filename.lower().endswith(('.jpg', '.png')) else 'video',
                confidence=confidence,
                is_deepfake=is_deepfake,
                details=details,
                user_id=session['user_id']
            )
            db.session.add(record)
            db.session.commit()
            new_results.append(record)

    flash('Analyse terminée !', 'success')
    return redirect(url_for('index'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'png', 'mp4', 'mov'}


if __name__ == '__main__':
    app.run(debug=True)
