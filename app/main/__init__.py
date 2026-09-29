from flask import Blueprint

# Define blueprint
main_bp = Blueprint(
    'main_bp',               # blueprint name
    __name__,                # current module
    template_folder='templates'  # look for templates in app/main/templates/
)

# Import routes AFTER defining blueprint
from . import routes
