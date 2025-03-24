from flask_jwt_extended import create_access_token, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, username: str, password: str, admin: bool = False):
        self.username = username
        self.password = generate_password_hash(password)
        self.admin = admin

    @classmethod
    def authenticate(cls, username: str, password: str):
        user = cls.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            return user

        raise Exception('User not found')

    def get_access_token(self, device_fp: str):
        access_token = create_access_token(identity=str(self.id), additional_claims={'admin': self.admin, 'device_fp': device_fp})
        return access_token

    def get_refresh_token(self, device_fp: str):
        refresh_token = create_refresh_token(identity=str(self.id), additional_claims={'admin': self.admin, 'device_fp': device_fp})
        return refresh_token
