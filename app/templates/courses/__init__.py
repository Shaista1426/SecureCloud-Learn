from flask import Blueprint

courses_bp = Blueprint(
    'courses_bp',
    __name__,
    template_folder='templates'
)

from . import routes
