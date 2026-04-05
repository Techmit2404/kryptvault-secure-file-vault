# 🔐 KryptVault — Secure File Vault System

A **secure file storage and sharing system** designed with strong cryptographic principles, deep file validation, and controlled access mechanisms.

KryptVault ensures that every file is **validated, encrypted, and access-controlled** before being stored or shared.

---

## 🚀 Features

* 🔑 **AES-256 Encryption (DEK + KEK Model)**
* 🛡️ **Secure Key Management (Environment-based KEK)**
* 📁 **Deep File Validation & Inspection**
* 🔍 **Magic Byte & MIME Type Verification**
* 📊 **Audit Logging System**
* 👤 **Authentication & Authorization (JWT-based)**
* 📦 **Secure File Storage**
* 📤 **Controlled File Sharing (Dropbox Model)**
* 🔒 **Access Levels: Public / Protected / Private**

---

## 🧠 System Design Overview

KryptVault follows a **layered security architecture**:

### 🔑 Key Management

* Single **Master KEK** stored in environment variable
* Each file gets a unique **DEK (Data Encryption Key)**
* DEK is encrypted using KEK

---

### 📂 File Upload Workflow

1. File is **sanitized**
2. File is **validated**

   * Extension check
   * File size check
   * MIME type verification
   * Magic byte validation
3. File undergoes **deep inspection**
4. File is **encrypted using AES-GCM**
5. Metadata is stored
6. Audit log is generated

---

### 🔐 Encryption Model

* File encrypted using **AES-256 (via AES-GCM)**
* Each file → unique DEK
* DEK encrypted using KEK
* Stored file = **Encrypted only (ciphertext)**

---

### 🔓 Decryption Flow

1. Fetch encrypted file
2. Decrypt DEK using KEK
3. Decrypt file using DEK
4. Verify integrity (SHA-256)
5. Return file

---

### 📤 File Sharing Mechanism

* Files can be shared via **Dropbox-like system**
* Access types:

| Access Level | Description                          |
| ------------ | ------------------------------------ |
| Public       | Anyone with access can view/download |
| Protected    | Can only view (no download)          |
| Private      | Not shareable                        |

* Users can:

  * Share files with other users
  * Add custom message while sharing
  * Access shared files via Dropbox

---

### 📊 Audit Logging

Every action is logged:

* Upload
* Download
* Access
* Sharing

Includes:

* Timestamp
* Username
* IP Address
* File ID

---

## 🧱 Project Structure

```
backend/
├── app.py
├── auth_module.py
├── encryption_module.py
├── storage_module.py
├── audit_module.py
├── key_manager.py
├── deep_file_validator.py
├── file_input_validnsanit.py

frontend/
└── index.html

requirements.txt
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository

```
git clone https://github.com/your-username/kryptvault-secure-file-vault.git
cd kryptvault-secure-file-vault
```

---

### 2️⃣ Install Dependencies

```
pip install -r requirements.txt
```

---

### 3️⃣ Set Environment Variable (IMPORTANT)

#### Windows (PowerShell):

```
$env:KRYPT_VAULT_KEK="your_64_hex_key_here"
```

#### Linux / Mac:

```
export KRYPT_VAULT_KEK="your_64_hex_key_here"
```

Example:

```
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

---

### 4️⃣ Run Backend Server

```
cd backend
python app.py
```

Server runs at:

```
http://localhost:5000
```

---

### 5️⃣ Run Frontend

Open:

```
frontend/index.html
```

---

## 🔐 Security Highlights

* ✔ AES-GCM encryption (confidentiality + integrity)
* ✔ Per-file encryption keys (DEK model)
* ✔ KEK-based key wrapping
* ✔ File integrity verification (SHA-256)
* ✔ Multi-layer file validation
* ✔ Secure authentication (token-based)
* ✔ Controlled access enforcement

---

## 📌 Future Enhancements

* 🔄 Key Rotation System
* 👤 User-based KEK
* 🌐 Secure external sharing links
* ⏱️ Time-limited access control
* 📊 Advanced monitoring dashboard

---

## 💡 Why This Project Stands Out

This is not just a file upload system.

It demonstrates:

* Applied **cryptography concepts**
* Secure **file handling pipelines**
* Real-world **access control design**
* Structured **backend architecture**

---

## 👨‍💻 Author

**Swayam Shah**

---

## ⭐ Final Note

KryptVault is built with a focus on **security-first design**, ensuring that files are never stored or shared without proper validation and encryption.

---
