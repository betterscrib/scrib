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

class Call(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aircall_id = db.Column(db.String(256))
    direction = db.Column(db.String(50))
    answered_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer)
    user_name = b.Column(db.String(256))
    number_name = b.Column(db.String(256))
    number_digits = b.Column(db.String(256))
    number_country = b.Column(db.String(256))
    contact_number_digits = b.Column(db.String(256))
    contact_first_name = b.Column(db.String(256))
    contact_last_name = b.Column(db.String(256))
    contact_company = b.Column(db.String(256))
    tags = b.Column(db.String(256))
    comments =b.Column(db.String(256))

