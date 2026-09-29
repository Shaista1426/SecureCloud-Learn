from app import db, create_app
from app.models import User, Course, Quiz, Question

app = create_app()
app.app_context().push()

# Create all tables
db.create_all()
print("All tables created successfully!")
