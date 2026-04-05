from flask import Blueprint, request, jsonify
import os, base64, hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from key_manager import generate_dek, encrypt_dek_with_kek, decrypt_dek_with_kek
from auth_module import token_required
from audit_module import log_action
from file_input_validnsanit import sanitize_file, validate_file
from storage_module import save_file_metadata, get_file_metadata
from flask import send_file
import io
from flask import request

encryption_bp = Blueprint('encryption', __name__)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'secure_storage')
os.makedirs(UPLOAD_DIR, exist_ok=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encrypt_bytes(data, dek):
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, data, None)
    return ct, nonce


def decrypt_bytes(ct, nonce, dek):
    return AESGCM(dek).decrypt(nonce, ct, None)


# ================== UPLOAD ==================

@encryption_bp.route('/upload', methods=['POST'])
@token_required
def upload(current_user):

    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    file = request.files['file']

    # ✅ Step 1: Sanitize
    original_name = file.filename
    safe_name, error = sanitize_file(file)
    if error:
        return jsonify({'error': error}), 400

    # ✅ Step 2: Validate
    temp_path, error = validate_file(file, safe_name)
    if error:
        return jsonify({'error': error}), 400

    # ✅ Step 3: Read validated file
    with open(temp_path, 'rb') as f:
        data = f.read()

    os.remove(temp_path)  # cleanup temp

    # ✅ Step 4: Hash
    file_hash = sha256(data)

    # ✅ Step 5: Encryption
    dek = generate_dek()
    ct, nonce = encrypt_bytes(data, dek)
    enc_dek = encrypt_dek_with_kek(dek)

    # ✅ Step 6: Store file
    fid = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')
    diskname = f"{fid}.enc"

    with open(os.path.join(UPLOAD_DIR, diskname), 'wb') as f:
        f.write(nonce + ct)

    # ✅ Step 7: Save metadata
    meta = {
        'file_id': fid,
        'original_name': original_name,
        'owner': current_user,
        'stored_filename': diskname,
        'encrypted_dek': enc_dek,
        'sha256_hash': file_hash,
        'access_level': request.form.get('access_level', 'private'),
        'upload_time': datetime.utcnow().isoformat(),
        'file_size': len(data),
        'shared_with': []
    }

    save_file_metadata(fid, meta)
    log_action(current_user, 'UPLOAD', fid, safe_name)

    return jsonify({'message': 'File securely uploaded', 'file_id': fid}), 201


# ================== DOWNLOAD ==================

@encryption_bp.route('/download/<fid>', methods=['GET'])
@token_required
def download(current_user, fid):

    meta = get_file_metadata(fid)
    if not meta:
        return jsonify({'error': 'Not found'}), 404

    if meta['owner'] != current_user and current_user not in meta.get('shared_with', []) and meta['access_level'] != 'public':
        return jsonify({'error': 'Access denied'}), 403
    
    mode = request.args.get("mode", "download")  # view or download
    
    if meta['access_level'] == 'protected' and meta['owner'] != current_user:
        if mode == "download":
         return jsonify({'error': 'Download not allowed for protected file'}), 403

    raw = open(os.path.join(UPLOAD_DIR, meta['stored_filename']), 'rb').read()

    nonce = raw[:12]
    ct = raw[12:]

    dek = decrypt_dek_with_kek(meta['encrypted_dek'])
    plaintext = decrypt_bytes(ct, nonce, dek)

    if sha256(plaintext) != meta['sha256_hash']:
        return jsonify({'error': 'Integrity failed'}), 500

    if mode == "view":
        return send_file(
        io.BytesIO(plaintext),
        as_attachment=False,
        download_name=meta['original_name']
        )
    else:
        return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=meta['original_name']
     )