from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


# User model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


# Model to store face encodings for each user
class Face(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    encoding = db.Column(db.PickleType, nullable=False)  # Use PickleType to store face encodings
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
