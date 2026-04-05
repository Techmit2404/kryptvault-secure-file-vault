from PIL import Image
from PyPDF2 import PdfReader

def validate_image(filepath):
    try:
        with Image.open(filepath) as img:
            img.verify()  # checks integrity
        return True
    except:
        return False

def validate_pdf(filepath):
    try:
        reader = PdfReader(filepath)
        _ = len(reader.pages)
        return True
    except:
        return False

def validate_text(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            f.read()
        return True
    except:
        return False

def validate_media(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(1024)
        return len(data) > 0
    except:
        return False
    
def deep_validate(filepath, extension):

    if extension in ['jpg', 'jpeg', 'png']:
        return validate_image(filepath)

    elif extension == 'pdf':
        return validate_pdf(filepath)

    elif extension == 'txt':
        return validate_text(filepath)

    elif extension in ['mp3', 'mp4']:
        return validate_media(filepath)

    return False