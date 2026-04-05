import os
import uuid
import magic
from werkzeug.utils import secure_filename
from deep_file_validator import deep_validate    

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'txt','mp3','mp4'}

ALLOWED_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'application/pdf',
    'text/plain',
    'audio/mpeg',
    'video/mp4'
}

EXTENSION_TO_MIME = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'pdf': 'application/pdf',
    'txt': 'text/plain',
    'mp3': 'audio/mpeg',
    'mp4': 'video/mp4'
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

UPLOAD_FOLDER = "temp_uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def sanitize_file(file):

    if not file or file.filename == '':
        return None, "Invalid file"

    old_name = file.filename.strip().lower()
    clean_name = secure_filename(old_name)

    if clean_name == '':
        return None, "Unsafe filename"

    new_name = str(uuid.uuid4())

    return new_name, None

def check_extension(filename):
    
    if '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS

def check_file_size(file):
    
    file.seek(0,2)
    size = file.tell()
    file.seek(0)
    return size <= MAX_FILE_SIZE

def check_mime_type(filepath):
    mime = magic.from_file(filepath, mime=True)
    return mime in ALLOWED_MIME_TYPES

def validate_magic_bytes(filepath, extension):

    with open(filepath, 'rb') as f:
        header = f.read(16)

    if extension in ['jpg', 'jpeg']:
        return header.startswith(b'\xFF\xD8\xFF')

    elif extension == 'png':
        return header.startswith(b'\x89PNG')

    elif extension == 'pdf':
        return header.startswith(b'%PDF')

    elif extension == 'mp3':
        return header.startswith(b'ID3') or header[:2] == b'\xFF\xFB'

    elif extension == 'mp4':
        return b'ftyp' in header

    elif extension == 'txt':
        # Basic check: no binary junk
        return all(32 <= b <= 126 or b in (9, 10, 13) for b in header)

    return False

def validate_file(file, safe_name):

    if not check_extension(file.filename):
        return None, "Invalid extension"

    if not check_file_size(file):
        return None, "File too large"

    temp_path = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(temp_path)

    if not check_mime_type(temp_path):
        os.remove(temp_path)
        return None, "Invalid MIME type"

    extension = file.filename.rsplit('.', 1)[1].lower()
    mime_type = magic.from_file(temp_path, mime=True)

    expected_mime = EXTENSION_TO_MIME.get(extension)

    if expected_mime != mime_type:
        os.remove(temp_path)
        return None, "Extension and MIME mismatch"

    if not validate_magic_bytes(temp_path, extension):
        os.remove(temp_path)
        return None, "Invalid file signature"

    # ✅ FIXED: Deep validation properly placed
    if not deep_validate(temp_path, extension):
        os.remove(temp_path)
        return None, "Deep validation failed"

    return temp_path, None