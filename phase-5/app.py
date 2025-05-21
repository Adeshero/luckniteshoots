from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
import os
import uuid
import json
import datetime
import hashlib
import hmac
from werkzeug.utils import secure_filename
import numpy as np
import tensorflow as tf
import joblib
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import sys
import traceback

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import encryption modules
try:
    from phase-3.aes import aes_encrypt, aes_decrypt
    from phase-3.rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt
    from phase-3.ecc import generate_ecc_keys, derive_shared_key, ecc_encrypt, ecc_decrypt
    from phase-3.ai_optimizer import get_best_encryption_method
    from phase-4.data_integrity import DataIntegrityChecker
    from phase-1.cryptanalysis import AICryptanalysis
except ImportError:
    print("Warning: Some modules could not be imported. Some features may not work.")
    # Create dummy functions for testing
    def aes_encrypt(data, key=None):
        return data, key or b"dummy_key"
    def aes_decrypt(data, key):
        return data
    def generate_rsa_keys():
        return None, None
    def rsa_encrypt(data, pub_key):
        return data
    def rsa_decrypt(data, priv_key):
        return data
    def generate_ecc_keys():
        return None, None
    def derive_shared_key(priv_key, peer_pub_key):
        return b"dummy_key"
    def ecc_encrypt(data, shared_key):
        return data
    def ecc_decrypt(data, shared_key):
        return data
    def get_best_encryption_method(data_size_kb, is_sensitive):
        return "AES"

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize AI models
try:
    integrity_checker = DataIntegrityChecker()
    integrity_checker.load_model()
    cryptanalysis = AICryptanalysis()
    cryptanalysis.load_model()
except Exception as e:
    print(f"Warning: Could not load AI models: {e}")
    integrity_checker = None
    cryptanalysis = None

# Helper functions
def generate_report(file_data, encryption_method, key, encrypted_data):
    """Generate an AI-powered encryption report"""
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "file_name": secure_filename(request.files['file'].filename),
        "file_size": len(file_data),
        "encryption_method": encryption_method,
        "key_hash": hashlib.sha256(key).hexdigest() if key else None,
        "encrypted_size": len(encrypted_data),
        "ai_analysis": {}
    }
    
    # Add AI analysis if models are available
    if integrity_checker:
        integrity_result = integrity_checker.check_integrity(encrypted_data)
        report["ai_analysis"]["integrity"] = integrity_result
    
    if cryptanalysis:
        cryptanalysis_result = cryptanalysis.analyze_encrypted_data(encrypted_data)
        report["ai_analysis"]["cryptanalysis"] = cryptanalysis_result
    
    # Generate entropy visualization
    plt.figure(figsize=(10, 4))
    
    # Byte distribution
    plt.subplot(1, 2, 1)
    data = np.frombuffer(encrypted_data, dtype=np.uint8)
    plt.hist(data, bins=256, range=(0, 256), density=True, alpha=0.7)
    plt.title('Byte Distribution')
    plt.xlabel('Byte Value')
    plt.ylabel('Frequency')
    
    # Entropy
    plt.subplot(1, 2, 2)
    hist, _ = np.histogram(data, bins=256, range=(0, 256), density=True)
    entropy = -np.sum(hist * np.log2(hist + 1e-10))
    plt.bar(['Entropy'], [entropy], color='green')
    plt.axhline(y=8.0, color='r', linestyle='-', label='Maximum Entropy (8.0)')
    plt.title('Entropy Analysis')
    plt.ylabel('Entropy (bits)')
    plt.ylim(0, 8.5)
    plt.legend()
    
    plt.tight_layout()
    
    # Save plot to base64 string
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    plt.close()
    
    report["visualization"] = base64.b64encode(image_png).decode('utf-8')
    
    return report

def save_report(report, user_id):
    """Save the report to a file"""
    reports_dir = os.path.join(app.config['UPLOAD_FOLDER'], user_id, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    report_id = str(uuid.uuid4())
    report_path = os.path.join(reports_dir, f"{report_id}.json")
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_id

def get_report(report_id, user_id):
    """Get a report by ID"""
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], user_id, 'reports', f"{report_id}.json")
    
    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            return json.load(f)
    
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        # Get encryption method
        encryption_method = request.form.get('encryption_method', 'auto')
        is_sensitive = request.form.get('is_sensitive', 'false') == 'true'
        
        # Read file data
        file_data = file.read()
        file_size_kb = len(file_data) / 1024
        
        # Determine encryption method
        if encryption_method == 'auto':
            encryption_method = get_best_encryption_method(file_size_kb, is_sensitive)
        
        # Encrypt data
        try:
            if encryption_method == 'AES':
                encrypted_data, key = aes_encrypt(file_data)
            elif encryption_method == 'RSA':
                priv_key, pub_key = generate_rsa_keys()
                # RSA can only encrypt small amounts of data
                chunk_size = 190  # RSA max is ~190 bytes
                encrypted_chunks = []
                for i in range(0, len(file_data), chunk_size):
                    chunk = file_data[i:i+chunk_size]
                    encrypted_chunk = rsa_encrypt(chunk, pub_key)
                    encrypted_chunks.append(encrypted_chunk)
                encrypted_data = b''.join(encrypted_chunks)
                key = priv_key
            elif encryption_method == 'ECC':
                priv_key, pub_key = generate_ecc_keys()
                peer_priv, peer_pub = generate_ecc_keys()
                shared_key = derive_shared_key(priv_key, peer_pub)
                encrypted_data = ecc_encrypt(file_data, shared_key)
                key = priv_key
            else:
                flash(f'Unknown encryption method: {encryption_method}')
                return redirect(request.url)
            
            # Generate report
            report = generate_report(file_data, encryption_method, key, encrypted_data)
            
            # Save encrypted file
            user_id = session.get('user_id', str(uuid.uuid4()))
            session['user_id'] = user_id
            
            user_dir = os.path.join(app.config['UPLOAD_FOLDER'], user_id)
            os.makedirs(user_dir, exist_ok=True)
            
            file_id = str(uuid.uuid4())
            encrypted_path = os.path.join(user_dir, f"{file_id}.enc")
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save key
            key_path = os.path.join(user_dir, f"{file_id}.key")
            with open(key_path, 'wb') as f:
                f.write(key)
            
            # Save report
            report_id = save_report(report, user_id)
            
            # Store file info in session
            session['encrypted_file'] = {
                'id': file_id,
                'name': secure_filename(file.filename),
                'method': encryption_method,
                'report_id': report_id
            }
            
            return redirect(url_for('report', report_id=report_id))
            
        except Exception as e:
            flash(f'Error during encryption: {str(e)}')
            traceback.print_exc()
            return redirect(request.url)
    
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        key_file = request.files['key']
        
        if file.filename == '' or key_file.filename == '':
            flash('Both encrypted file and key file are required')
            return redirect(request.url)
        
        # Get encryption method
        encryption_method = request.form.get('encryption_method')
        
        # Read files
        encrypted_data = file.read()
        key_data = key_file.read()
        
        try:
            # Decrypt data
            if encryption_method == 'AES':
                decrypted_data = aes_decrypt(encrypted_data, key_data)
            elif encryption_method == 'RSA':
                # RSA decryption
                decrypted_data = rsa_decrypt(encrypted_data, key_data)
            elif encryption_method == 'ECC':
                # ECC decryption
                decrypted_data = ecc_decrypt(encrypted_data, key_data)
            else:
                flash(f'Unknown encryption method: {encryption_method}')
                return redirect(request.url)
            
            # Save decrypted file
            user_id = session.get('user_id', str(uuid.uuid4()))
            session['user_id'] = user_id
            
            user_dir = os.path.join(app.config['UPLOAD_FOLDER'], user_id)
            os.makedirs(user_dir, exist_ok=True)
            
            file_id = str(uuid.uuid4())
            decrypted_path = os.path.join(user_dir, f"{file_id}.dec")
            
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Store file info in session
            session['decrypted_file'] = {
                'id': file_id,
                'path': decrypted_path,
                'name': secure_filename(file.filename).replace('.enc', '')
            }
            
            return redirect(url_for('download'))
            
        except Exception as e:
            flash(f'Error during decryption: {str(e)}')
            traceback.print_exc()
            return redirect(request.url)
    
    return render_template('decrypt.html')

@app.route('/report/<report_id>')
def report(report_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('No user session found')
        return redirect(url_for('index'))
    
    report_data = get_report(report_id, user_id)
    if not report_data:
        flash('Report not found')
        return redirect(url_for('index'))
    
    return render_template('report.html', report=report_data)

@app.route('/download')
def download():
    decrypted_file = session.get('decrypted_file')
    if not decrypted_file:
        flash('No decrypted file found')
        return redirect(url_for('index'))
    
    return send_file(
        decrypted_file['path'],
        as_attachment=True,
        download_name=decrypted_file['name']
    )

@app.route('/about')
def about():
    return render_template('about.html')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 