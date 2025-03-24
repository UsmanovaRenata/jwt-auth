from flask import Blueprint, render_template, redirect, url_for
from flask_jwt_extended import jwt_required, get_jwt

from auth.auth import device_verified_required
content = Blueprint('content', __name__, template_folder='templates/content')


@content.route('/', methods=['GET'])
def hello_world():
    return redirect(url_for('auth.login'))


@content.route('/hello', methods=['GET'])
@jwt_required()
@device_verified_required
def hello():
    claims = get_jwt()
    is_admin = claims.get('admin', False)
    return render_template('content.html', is_admin=is_admin)
