"""Formulaires WTForms de connexion et d'inscription."""
from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class LoginForm(FlaskForm):
    """Formulaire de connexion."""
    username = StringField("Nom d'utilisateur", validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Connexion')


class RegisterForm(FlaskForm):
    """Formulaire d'inscription."""
    username = StringField(
        "Nom d'utilisateur",
        validators=[DataRequired(), Length(min=4, max=80)])
    email = EmailField(
        'Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        'Mot de passe',
        validators=[
            DataRequired(),
            Length(min=8, max=72),
            EqualTo('confirm_password',
                    message='Les mots de passe doivent correspondre'),
        ])
    confirm_password = PasswordField(
        'Confirmer le mot de passe', validators=[DataRequired()])
    submit = SubmitField("S'inscrire")
