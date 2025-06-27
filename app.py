from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from models import db
import os

# ======= Flask Setup =======
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv("SECRET_KEY", "supersecret")

db.init_app(app)

# ======= Models =======
class License(db.Model):
    key = db.Column(db.String, primary_key=True)
    device_id = db.Column(db.String, default="ANY")
    status = db.Column(db.String, default="valid")
    expires = db.Column(db.String)  # Format: "YYYY-MM-DD HH:MM:SS"

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

# ======= Login Manager =======
login_mgr = LoginManager(app)
login_mgr.login_view = 'login'

@login_mgr.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

# ======= Routes =======
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'], request.form['password']
        user = Admin.query.filter_by(username=u).first()
        if user and check_password_hash(user.password, p):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    licenses = License.query.all()
    return render_template('index.html', licenses=licenses)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        key = request.form['key'].strip()
        device_id = request.form.get('device_id', 'ANY').strip()
        status = request.form['status']
        expires = request.form['expires'].strip()

        license_obj = License.query.get(key) or License(key=key)
        license_obj.device_id = device_id
        license_obj.status = status
        license_obj.expires = expires

        db.session.add(license_obj)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('add.html')

@app.route('/delete/<key>')
@login_required
def delete(key):
    license_obj = License.query.get(key)
    if license_obj:
        db.session.delete(license_obj)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.json
    key = data.get('key', '').strip()
    device = data.get('device_id', '').strip()

    license_obj = License.query.get(key)
    if not license_obj or license_obj.status != 'valid':
        return jsonify({'status': license_obj.status if license_obj else 'invalid'}), 200

    if license_obj.device_id != "ANY" and license_obj.device_id != device:
        return jsonify({'status': 'invalid'}), 200

    expires = license_obj.expires
    if expires:
        dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() > dt:
            return jsonify({'status': 'expired', 'expires': expires}), 200

    return jsonify({'status': 'valid', 'expires': expires}), 200

# ======= DB Initialization with ENV-based Admin =======
with app.app_context():
    db.create_all()
    if not Admin.query.first():
        admin_user = os.getenv('ADMIN_USERNAME')
        admin_pass = os.getenv('ADMIN_PASSWORD')
        if admin_user and admin_pass:
            hashed = generate_password_hash(admin_pass)
            default_admin = Admin(username=admin_user, password=hashed)
            db.session.add(default_admin)
            db.session.commit()
            print(f"✅ Admin default dibuat: {admin_user}")
        else:
            print("ℹ️ Admin default tidak dibuat — variabel ENV tidak lengkap.")

# ======= Run (for local testing) =======
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(debug=True, host="0.0.0.0", port=port)
