from flask import Flask
from dotenv import load_dotenv

from config import Config
from extensions import db, jwt
from auth.auth import auth
from content.content import content

load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)

    app.register_blueprint(auth)
    app.register_blueprint(content)

    return app 