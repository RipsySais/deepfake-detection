"""Extensions Flask partagées, créées ici pour éviter les imports circulaires.

Chaque extension est instanciée sans application, puis liée à l'application
dans `create_app` avec `init_app`.
"""
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()
csrf = CSRFProtect()
