from flask import Blueprint

# Define the blueprint
instructor_bp = Blueprint(
    'instructor_bp',          # Blueprint name
    __name__,                 # Current module
    template_folder='templates'  # Look for templates in app/instructor/templates/
)

# Import routes AFTER defining blueprint
