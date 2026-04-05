import json, os
from datetime import datetime
from flask import Blueprint, request, jsonify
from auth_module import token_required

audit_bp  = Blueprint('audit', __name__)
AUDIT_LOG = os.path.join(os.path.dirname(__file__), 'audit_log.json')

def log_action(username, action, file_id='', filename='', extra=''):
    logs = []
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            logs = json.load(f)
    try:
        ip = request.remote_addr or 'unknown'
    except RuntimeError:
        ip = 'system'
    logs.append({
        'timestamp':  datetime.utcnow().isoformat(),
        'username':   username,
        'action':     action,
        'file_id':    file_id,
        'filename':   filename,
        'ip_address': ip,
        'extra':      extra
    })
    if len(logs) > 1000:
        logs = logs[-1000:]
    with open(AUDIT_LOG, 'w') as f:
        json.dump(logs, f, indent=2)

@audit_bp.route('/logs', methods=['GET'])
@token_required
def my_logs(current_user):
    if not os.path.exists(AUDIT_LOG):
        return jsonify({'logs': []}), 200
    with open(AUDIT_LOG) as f:
        all_logs = json.load(f)
    mine = sorted(
        [l for l in all_logs if l['username'] == current_user],
        key=lambda x: x['timestamp'], reverse=True
    )[:50]
    return jsonify({'logs': mine}), 200

@audit_bp.route('/file/<fid>', methods=['GET'])
@token_required
def file_logs(current_user, fid):
    from storage_module import get_file_metadata
    meta = get_file_metadata(fid)
    if not meta: return jsonify({'error': 'Not found'}), 404
    if meta['owner'] != current_user: return jsonify({'error': 'Not your file'}), 403
    if not os.path.exists(AUDIT_LOG):
        return jsonify({'logs': []}), 200
    with open(AUDIT_LOG) as f:
        all_logs = json.load(f)
    return jsonify({'logs': sorted(
        [l for l in all_logs if l['file_id'] == fid],
        key=lambda x: x['timestamp'], reverse=True
    )}), 200
