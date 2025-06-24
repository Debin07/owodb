from app import db, Admin
from werkzeug.security import generate_password_hash
from flask import Flask

with db.app.app_context():
    db.create_all()
    if not Admin.query.first():
        admin = Admin(username='Debin07', password=generate_password_hash('Pantat21'))
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin berhasil dibuat.")
