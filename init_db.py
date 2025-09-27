from app import create_app
from models.models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    # Drop and recreate tables
    db.drop_all()
    db.create_all()

    # Create default admin
    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

    print("✅ Database initialized.")
    print("   Admin login: admin@example.com / admin123")

