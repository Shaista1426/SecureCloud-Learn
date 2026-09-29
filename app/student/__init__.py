from flask import Blueprint

# Define the blueprint
student_bp = Blueprint(
    'student_bp',            # blueprint name
    __name__,                # current module
    template_folder='templates'  # look for templates in app/student/templates/
)

# Import routes AFTER defining blueprint
