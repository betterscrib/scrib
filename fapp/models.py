from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager

import logging as lg

# Create database connection object
db = SQLAlchemy()
login_manager = LoginManager()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256))


class Recording(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(256))
    user_id = db.Column(db.Integer)
    file_size = db.Column(db.Integer)
    file_format = db.Column(db.String(50))
    duration = db.Column(db.Float)

class Integration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    token = db.Column(db.String(256))


