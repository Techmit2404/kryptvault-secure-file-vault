import json, os
from flask import Blueprint, jsonify
from auth_module import token_required
from auth_module import load_users
from flask import request

storage_bp = Blueprint('storage', __name__)

FILES_DB   = os.path.join(os.path.dirname(__file__), 'files_db.json')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'secure_storage')


# ================= DB HELPERS =================

def load_files():
    if not os.path.exists(FILES_DB):
        return {}
    with open(FILES_DB) as f:
        return json.load(f)

def save_files(db):
    with open(FILES_DB, 'w') as f:
        json.dump(db, f, indent=2)

def save_file_metadata(fid, meta):
    db = load_files()
    db[fid] = meta
    save_files(db)

def get_file_metadata(fid):
    return load_files().get(fid)


# ================= FILE LIST =================

@storage_bp.route('/files', methods=['GET'])
@token_required
def list_files(current_user):

    db = load_files()
    result = []

    for m in db.values():
        if (
            m['owner'] == current_user
            or current_user in m.get('shared_with', [])
            or m['access_level'] == 'public'
        ):
            result.append({
                'file_id': m['file_id'],
                'original_name': m['original_name'],
                'owner': m['owner'],
                'access_level': m['access_level'],
                'upload_time': m['upload_time'],
                'file_size': m['file_size'],
                'is_mine': m['owner'] == current_user
            })

    return jsonify({'files': result}), 200


# ================= DROPBOX =================

@storage_bp.route('/dropbox', methods=['GET'])
@token_required
def dropbox(current_user):

    db = load_files()

    result = [
        {
            'file_id': m['file_id'],
            'original_name': m['original_name'],
            'owner': m['owner'],
            'access_level': m['access_level'],
            'message': m.get('share_message', '')
        }
        for m in db.values()
        if current_user in m.get('shared_with', [])
    ]

    return jsonify({'dropbox': result}), 200

@storage_bp.route('/share/<fid>', methods=['POST'])
@token_required
def share_file(current_user, fid):

    data = request.get_json()
    target_user = data.get("username")
    message = data.get("message", "")

    db = load_files()
    meta = db.get(fid)

    if not meta:
        return jsonify({'error': 'Not found'}), 404

    if meta['owner'] != current_user:
        return jsonify({'error': 'Not your file'}), 403

    if target_user == current_user:
        return jsonify({'error': 'Cannot share with yourself'}), 400

    if target_user not in load_users():
        return jsonify({'error': 'User not found'}), 404

    if meta['access_level'] == 'private':
        return jsonify({'error': 'Private files cannot be shared'}), 403

    meta.setdefault('shared_with', [])

    if target_user not in meta['shared_with']:
        meta['shared_with'].append(target_user)

    meta['share_message'] = message

    save_files(db)

    return jsonify({'message': 'File shared'}), 200

# ================= DELETE =================

@storage_bp.route('/delete/<fid>', methods=['DELETE'])
@token_required
def delete_file(current_user, fid):

    db = load_files()
    meta = db.get(fid)

    if not meta:
        return jsonify({'error': 'Not found'}), 404

    if meta['owner'] != current_user:
        return jsonify({'error': 'Not your file'}), 403

    path = os.path.join(UPLOAD_DIR, meta['stored_filename'])

    if os.path.exists(path):
        os.remove(path)

    del db[fid]
    save_files(db)

    return jsonify({'message': 'Deleted successfully'}), 200