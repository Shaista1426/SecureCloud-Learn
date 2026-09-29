from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from dotenv import load_dotenv
import os
import time

load_dotenv()


# -------------------------------------------------
# Upload Configuration
# -------------------------------------------------

UPLOAD_FOLDER = os.path.join("app", "static", "course_images")

ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg"
}


# -------------------------------------------------
# Initialize Extensions
# -------------------------------------------------

db = SQLAlchemy()

login_manager = LoginManager()

migrate = Migrate()

mail = Mail()


# -------------------------------------------------
# Login Manager Configuration
# -------------------------------------------------

login_manager.login_view = "auth_bp.login"


# -------------------------------------------------
# Create Flask Application
# -------------------------------------------------

def create_app():

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )


    # -------------------------------------------------
    # Basic Application Configuration
    # -------------------------------------------------

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

    # -------------------------------------------------
    # Session / Automatic Inactivity Logout
    # -------------------------------------------------

    app.config["PERMANENT_SESSION_LIFETIME"] = 900

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


    # -------------------------------------------------
    # Flask-Mail Configuration
    # -------------------------------------------------

    app.config["MAIL_SERVER"] = os.getenv(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    app.config["MAIL_PORT"] = int(
        os.getenv(
            "MAIL_PORT",
            587
        )
    )

    app.config["MAIL_USE_TLS"] = (
        os.getenv(
            "MAIL_USE_TLS",
            "True"
        ).lower() == "true"
    )

    app.config["MAIL_USE_SSL"] = (
        os.getenv(
            "MAIL_USE_SSL",
            "False"
        ).lower() == "true"
    )

    app.config["MAIL_USERNAME"] = os.getenv(
        "MAIL_USERNAME"
    )

    app.config["MAIL_PASSWORD"] = os.getenv(
        "MAIL_PASSWORD"
    )

    app.config["MAIL_DEFAULT_SENDER"] = os.getenv(
        "MAIL_DEFAULT_SENDER"
    )


    # -------------------------------------------------
    # Initialize Extensions with Flask App
    # -------------------------------------------------

    db.init_app(app)

    login_manager.init_app(app)

    migrate.init_app(app, db)

    mail.init_app(app)

    # -------------------------------------------------
    # Automatic Logout After Inactivity
    # -------------------------------------------------

    @app.before_request
    def check_inactivity():

        # ---------------------------------------------
        # Only check logged-in users
        # ---------------------------------------------

        from flask_login import current_user, logout_user
        from flask import session, request

        if not current_user.is_authenticated:
            return

        # ---------------------------------------------
        # Ignore static files
        # ---------------------------------------------

        if request.endpoint == "static":
            return

        # ---------------------------------------------
        # Get current time
        # ---------------------------------------------

        current_time = time.time()

        # ---------------------------------------------
        # Get last activity time
        # ---------------------------------------------

        last_activity = session.get(
            "last_activity"
        )

        # ---------------------------------------------
        # Check inactivity
        # ---------------------------------------------

        if last_activity:

            inactive_time = (
                current_time - last_activity
            )

            if inactive_time > 900:

                logout_user()

                session.pop(
                    "last_activity",
                    None
                )

                session["inactivity_logout"] = True

                return

        # ---------------------------------------------
        # Update last activity
        # ---------------------------------------------

        session["last_activity"] = current_time

        # ---------------------------------------------
        # Make session permanent
        # ---------------------------------------------

        session.permanent = True


    # -------------------------------------------------
    # Import Models
    # -------------------------------------------------

    from app import models  # noqa


    # -------------------------------------------------
    # Import Blueprints
    # -------------------------------------------------

    from app.auth.routes import auth_bp

    from app.main.routes import main_bp

    from app.routes.course_routes import course_bp

    from app.dashboard.routes import dashboard_bp

    from app.routes.quizzes import quiz_bp


    # -------------------------------------------------
    # Register Blueprints
    # -------------------------------------------------

    app.register_blueprint(auth_bp)

    app.register_blueprint(main_bp)

    app.register_blueprint(
        course_bp,
        url_prefix="/courses"
    )

    app.register_blueprint(
        quiz_bp,
        url_prefix="/quizzes"
    )

    app.register_blueprint(
        dashboard_bp,
        url_prefix="/dashboard"
    )


    # -------------------------------------------------
    # Return Application
    # -------------------------------------------------

    return app


# -------------------------------------------------
# Flask-Login User Loader
# -------------------------------------------------

from app.models import User


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


# -------------------------------------------------
# File Validation Helper
# -------------------------------------------------

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )