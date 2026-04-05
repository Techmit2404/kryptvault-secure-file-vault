from flask import Flask
from flask_cors import CORS

from auth_module import auth_bp
from encryption_module import encryption_bp
from storage_module import storage_bp
from audit_module import audit_bp

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'krypt_vault_secret_2024'

# 🔗 Register all modules
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(encryption_bp, url_prefix='/file')
app.register_blueprint(storage_bp, url_prefix='/storage')
app.register_blueprint(audit_bp, url_prefix='/audit')


@app.route('/')
def home():
    return {"message": "Krypt Vault Backend Running 🚀"}


if __name__ == '__main__':
    print("Server running at http://localhost:5000")
    app.run(debug=True)