import hashlib
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, make_response, jsonify
from flask_jwt_extended import (
    jwt_required, set_access_cookies, set_refresh_cookies,
    get_jwt, get_jwt_identity, unset_jwt_cookies, get_jti, verify_jwt_in_request
)

from config import Config
from extensions import jwt
from models import db, User
from redis_client import redis_client

auth = Blueprint('auth', __name__, template_folder='templates/auth')


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return redis_client.is_in_blacklist(jti)


@jwt.expired_token_loader
def custom_401_handler(jwt_header, jwt_payload):
    return render_template('401.html')


def device_verified_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()

        claims = get_jwt()
        expected_fp = claims.get("device_fp")
        current_fp = generate_device_fingerprint()

        if expected_fp != current_fp:
            return jsonify({
                "error": "Device verification failed",
            }), 403

        return fn(*args, **kwargs)

    return wrapper


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    if request.method == 'POST':
        try:
            if request.form.get('username') and request.form.get('password'):
                new_user = User(request.form.get('username'), request.form.get('password'),
                                bool(request.form.get('is_admin')))
                db.session.add(new_user)
                db.session.commit()

                return make_response(redirect(url_for('.login')))
            else:
                raise Exception("Empty fields")
        except Exception as e:
            return jsonify({'error': str(e)}), 400


@auth.route('/auth', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('auth.html')
    if request.method == 'POST':
        try:
            if request.form.get('username') and request.form.get('password'):
                user = User.authenticate(request.form.get('username'), request.form.get('password'))
                response = make_response(redirect(url_for('content.hello')))
                access_token = user.get_access_token(generate_device_fingerprint())
                refresh_token = user.get_refresh_token(generate_device_fingerprint())

                redis_client.add_to_whitelist(user.id, get_jti(refresh_token), exp=Config.JWT_REFRESH_TOKEN_EXPIRES)
                set_access_cookies(response, access_token)
                set_refresh_cookies(response, refresh_token)
                return response
            else:
                raise Exception
        except:
            return jsonify({"error": "Invalid username or password"}), 401


@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@device_verified_required
def refresh():
    user_id = get_jwt_identity()
    refresh_token = get_jwt()['jti']

    user = User.query.filter_by(id=user_id).first()

    if redis_client.is_in_whitelist(user_id, refresh_token):
        new_access_token = user.get_access_token(generate_device_fingerprint())
        response = make_response({"msg": "Token refreshed"}, 200)
        set_access_cookies(response, new_access_token)
        return response
    else:
        return jsonify({"error": "Invalid refresh token"}), 401


@auth.route('/logout', methods=['POST'])
@jwt_required()
@device_verified_required
def logout():
    user_id = get_jwt_identity()
    jti = get_jwt()['jti']

    redis_client.add_to_blacklist(jti, exp=Config.JWT_ACCESS_TOKEN_EXPIRES)
    redis_client.remove_from_whitelist(user_id)

    response = make_response({"msg": "Successfully logged out"}, 200)
    unset_jwt_cookies(response)
    return response


def generate_device_fingerprint() -> str:
    device_string = f"""
    {request.user_agent.string}
    {request.remote_addr}
    {request.headers.get('Accept-Language')}
    """.encode('utf-8')

    return hashlib.sha256(device_string).hexdigest()