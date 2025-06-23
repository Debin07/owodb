from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class License(db.Model):
    key = db.Column(db.String, primary_key=True)
    device_id = db.Column(db.String, default="ANY")
    status = db.Column(db.String, default="valid")
    expires = db.Column(db.String)  # "YYYY-MM-DD HH:MM:SS"

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)  # hashed

