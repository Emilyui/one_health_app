import os
import base64
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json

# --- APP CONFIGURATION ---
app = Flask(__name__)
# IMPORTANT: Change this secret key in a real application!
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'
# Configure the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'onehealth.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# AES Encryption Key (must be 16, 24, or 32 bytes long)
# IMPORTANT: Store this securely, e.g., in environment variables, not hardcoded.
AES_KEY = b'MySuperSecretKey123456' # 24 bytes for AES-192

db = SQLAlchemy(app)

# --- ENCRYPTION SERVICE ---
class EncryptionService:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)
        
        cipher = AES.new(self.key, AES.MODE_CBC)
        # Pad the data to be a multiple of 16 bytes
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        # Prepend the IV to the ciphertext for use in decryption
        return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

    def decrypt(self, b64_encoded_data):
        try:
            decoded_data = base64.b64decode(b64_encoded_data)
            iv = decoded_data[:AES.block_size]
            ciphertext = decoded_data[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_padded_data = cipher.decrypt(ciphertext)
            # Unpad the data
            return unpad(decrypted_padded_data, AES.block_size).decode('utf-8')
        except (ValueError, KeyError):
            return "Decryption Error" # Or handle more gracefully

encryption_service = EncryptionService(AES_KEY)

# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # Roles: 'Citizen', 'Doctor', 'Researcher'
    role = db.Column(db.String(50), nullable=False, default='Citizen')
    records = db.relationship('HealthRecord', backref='reporter', lazy=True)

class HealthRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Categories: 'Human', 'Animal', 'Plant'
    category = db.Column(db.String(50), nullable=False)
    description_encrypted = db.Column(db.String(1024), nullable=False) # Store encrypted data
    location_lat = db.Column(db.Float, nullable=False)
    location_lon = db.Column(db.Float, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    @property
    def description(self):
        return encryption_service.decrypt(self.description_encrypted)
    
    @description.setter
    def description(self, plaintext):
        self.description_encrypted = encryption_service.encrypt(plaintext)

# --- USER & AUTHENTICATION ROUTES ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # For simplicity, role is based on email domain. In reality, this would be an admin process.
        role = 'Doctor' if '@health.gov' in email else 'Researcher' if '@research.edu' in email else 'Citizen'
        
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    return redirect(url_for('login'))

# --- CORE APPLICATION ROUTES ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_role=session.get('user_role'))

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_id = session['user_id']
        category = request.form['category']
        description = request.form['description']
        lat = float(request.form['lat'])
        lon = float(request.form['lon'])
        is_public = 'is_public' in request.form

        new_record = HealthRecord(user_id=user_id, category=category, location_lat=lat, location_lon=lon, is_public=is_public)
        new_record.description = description # Use the setter to encrypt
        db.session.add(new_record)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('report.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # For QR Code generation, we'll create a simple JSON string with user info
    user_id = session['user_id']
    user = User.query.get(user_id)
    qr_data = json.dumps({'user_id': user.id, 'email': user.email, 'role': user.role})
    
    return render_template('profile.html', qr_data=qr_data)

# --- API ENDPOINT FOR DASHBOARD DATA ---
@app.route('/api/data')
def api_data():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_role = session.get('user_role')
    records = []

    if user_role == 'Doctor':
        # Doctors see all records
        all_records = HealthRecord.query.all()
        for record in all_records:
            records.append({
                'lat': record.location_lat, 'lon': record.location_lon,
                'category': record.category, 'desc': record.description, # Doctors can see decrypted data
                'reporter': record.reporter.email
            })
    elif user_role == 'Researcher':
        # Researchers see only public records, and they are anonymized
        public_records = HealthRecord.query.filter_by(is_public=True).all()
        for record in public_records:
            records.append({
                'lat': record.location_lat, 'lon': record.location_lon,
                'category': record.category, 'desc': 'Anonymized Data', # No sensitive description
                'reporter': 'Anonymous'
            })
    else: # Citizen
        # Citizens see only their own records
        citizen_records = HealthRecord.query.filter_by(user_id=session['user_id']).all()
        for record in citizen_records:
            records.append({
                'lat': record.location_lat, 'lon': record.location_lon,
                'category': record.category, 'desc': record.description,
                'reporter': record.reporter.email
            })

    return jsonify(records)


if __name__ == '__main__':
    with app.app_context():
        # This will create the database file if it doesn't exist
        db.create_all()
    app.run(debug=True)
