import json, os, hashlib, time, base64, hmac
from functools import wraps
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app

auth_bp = Blueprint('auth', __name__)
USERS_DB = os.path.join(os.path.dirname(__file__), 'users_db.json')

def load_users():
    if not os.path.exists(USERS_DB):
        return {}
    with open(USERS_DB) as f:
        return json.load(f)

def save_users(users):
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=2)

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def make_token(payload, secret):
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip('=')
    body   = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    sig    = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    ).decode().rstrip('=')
    return f"{header}.{body}.{sig}"

def check_token(token, secret):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("bad token")
    h, b, s = parts
    expected = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest()
    ).decode().rstrip('=')
    if not hmac.compare_digest(s, expected):
        raise ValueError("bad signature")
    padded  = b + '=' * (-len(b) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    if payload.get('exp', 0) < time.time():
        raise ValueError("expired")
    return payload

def token_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        if not header.startswith('Bearer '):
            return jsonify({'error': 'No token'}), 401
        try:
            payload = check_token(header.split()[1], current_app.config['SECRET_KEY'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        return f(payload['username'], *args, **kwargs)
    return inner

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    u = data.get('username', '').strip().lower()
    p = data.get('password', '')
    if not u or not p:
        return jsonify({'error': 'Username and password required'}), 400
    if len(u) < 3 or len(p) < 6:
        return jsonify({'error': 'Username min 3 chars, password min 6 chars'}), 400
    users = load_users()
    if u in users:
        return jsonify({'error': 'Username taken'}), 409
    users[u] = {'password_hash': hash_pw(p), 'email': data.get('email',''), 'created': datetime.utcnow().isoformat()}
    save_users(users)
    return jsonify({'message': 'Registered'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    u = data.get('username', '').strip().lower()
    p = data.get('password', '')
    users = load_users()
    user  = users.get(u)
    if not user or user['password_hash'] != hash_pw(p):
        return jsonify({'error': 'Wrong username or password'}), 401
    token = make_token({'username': u, 'exp': time.time() + 86400}, current_app.config['SECRET_KEY'])
    return jsonify({'token': token, 'username': u}), 200

@auth_bp.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    users = load_users()
    u = users.get(current_user, {})
    return jsonify({'username': current_user, 'email': u.get('email',''), 'created': u.get('created','')}), 200
