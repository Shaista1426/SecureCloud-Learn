from app import create_app
from app.extensions import db
from app.models import User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():

    db.drop_all()
    db.create_all()

    pw = generate_password_hash(
        "password123",
        method="pbkdf2:sha256"
    )

    instructor = User(
        username="Alice",
        email="alice@inst.com",
        password=pw,
        role="instructor"
    )

    student = User(
        username="Bob",
        email="bob@student.com",
        password=pw,
        role="student"
    )

    db.session.add(instructor)
    db.session.add(student)
    db.session.commit()

    print("Database Seeded Successfully")