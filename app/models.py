# app/models.py

from app import db
from flask_login import UserMixin
from datetime import datetime
import json


# =========================================================
# USER MODEL
# =========================================================

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(120),
        nullable=False,
        unique=True
    )

    email = db.Column(
        db.String(120),
        nullable=False,
        unique=True
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    # -----------------------------------------------------
    # Password & PIN Expiry Fields
    # -----------------------------------------------------

    password_changed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    pin = db.Column(
        db.String(255),
        nullable=True
    )

    pin_changed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    # -----------------------------------------------------
    # Mobile Number & MPIN Authentication Fields
    # -----------------------------------------------------

    mobile_number = db.Column(
        db.String(20),
        nullable=True,
        unique=True
    )

    mobile_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )

    mobile_otp_hash = db.Column(
        db.String(255),
        nullable=True
    )

    mobile_otp_expiry = db.Column(
        db.DateTime,
        nullable=True
    )

    mpin = db.Column(
        db.String(255),
        nullable=True
    )

    mpin_changed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    # -----------------------------------------------------
    # Security Question Fields
    # -----------------------------------------------------

    security_question = db.Column(
        db.String(255),
        nullable=True
    )

    security_answer = db.Column(
        db.String(255),
        nullable=True
    )

    role = db.Column(
        db.String(50),
        nullable=False,
        default='student'
    ) # 'student' or 'instructor'


    # -----------------------------------------------------
    # Email Verification Fields
    # -----------------------------------------------------

    email_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )

    verification_token = db.Column(
        db.String(255),
        nullable=True
    )

    verification_token_expiry = db.Column(
        db.DateTime,
        nullable=True
    )

    # -----------------------------------------------------
    # Two-Factor Authentication / MFA Fields
    # -----------------------------------------------------

    mfa_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )

    mfa_otp_hash = db.Column(
        db.String(255),
        nullable=True
    )

    mfa_otp_expiry = db.Column(
        db.DateTime,
        nullable=True
    )

    # -----------------------------------------------------
    # Failed Login / Account Lock Fields
    # -----------------------------------------------------

    failed_login_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        server_default='0'
    )

    account_locked = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )


    # -----------------------------------------------------
    # Biometric Authentication Fields
    # -----------------------------------------------------

    face_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )

    face_encoding = db.Column(
        db.Text,
        nullable=True
    )

    # -----------------------------------------------------
    # Password Reset Fields
    # -----------------------------------------------------

    reset_token = db.Column(
        db.String(255),
        nullable=True
    )

    reset_token_expiry = db.Column(
        db.DateTime,
        nullable=True
    )



    # -----------------------------------------------------
    # Relationships
    # -----------------------------------------------------

    courses = db.relationship(
        'Course',
        back_populates='instructor'
    )

    enrollments = db.relationship(
        'Enrollment',
        backref='student',
        cascade='all, delete-orphan'
    )

# =========================================================
# COURSE MODEL
# =========================================================

class Course(db.Model):
    __tablename__ = 'course'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(120),
        nullable=False
    )

    description = db.Column(
        db.Text
    )

    content = db.Column(
        db.Text
    )

    image_filename = db.Column(
        db.String(255)
    )

    instructor_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    instructor = db.relationship(
        'User',
        back_populates='courses'
    )

    is_published = db.Column(
        db.Boolean,
        default=False
    )

    quizzes = db.relationship(
        'Quiz',
        backref='course',
        cascade='all, delete-orphan'
    )


# =========================================================
# QUIZ MODEL
# =========================================================

class Quiz(db.Model):
    __tablename__ = 'quiz'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(120),
        nullable=False
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey('course.id'),
        nullable=False
    )

    questions = db.relationship(
        'QuizQuestion',
        backref='quiz',
        cascade='all, delete-orphan'
    )

    total_marks = db.Column(
        db.Integer
    )

    pass_percentage = db.Column(
        db.Integer,
        default=40
    )


# =========================================================
# QUIZ QUESTION MODEL
# =========================================================

class QuizQuestion(db.Model):
    __tablename__ = 'question'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    question_text = db.Column(
        db.Text,
        nullable=False
    )

    option1 = db.Column(
        db.String(255),
        nullable=False
    )

    option2 = db.Column(
        db.String(255),
        nullable=False
    )

    option3 = db.Column(
        db.String(255),
        nullable=False
    )

    option4 = db.Column(
        db.String(255),
        nullable=False
    )

    # Store integer 1..4
    correct_option = db.Column(
        db.Integer,
        nullable=False
    )

    quiz_id = db.Column(
        db.Integer,
        db.ForeignKey('quiz.id'),
        nullable=False
    )


# =========================================================
# QUIZ ATTEMPT MODEL
# =========================================================

class QuizAttempt(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    student_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    quiz_id = db.Column(
        db.Integer,
        db.ForeignKey('quiz.id'),
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    total_marks = db.Column(
        db.Integer,
        nullable=False
    )

    percentage = db.Column(
        db.Float
    )

    status = db.Column(
        db.String(10)
    )

    attempted_on = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ---------------------------------------------------------
# Relationships for QuizAttempt
# ---------------------------------------------------------

user = db.relationship(
    'User',
    backref='quiz_attempts'
)

quiz = db.relationship(
    'Quiz',
    backref='attempts'
)


# =========================================================
# ENROLLMENT MODEL
# =========================================================

class Enrollment(db.Model):
    __tablename__ = 'enrollment'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    student_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id')
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey('course.id')
    )


# =========================================================
# CERTIFICATE MODEL
# =========================================================

class Certificate(db.Model):
    __tablename__ = 'certificate'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    student_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id')
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey('course.id')
    )

    date = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================================================
# PENDING REGISTRATION MODEL
# =========================================================

class PendingRegistration(db.Model):
    __tablename__ = 'pending_registration'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(120),
        nullable=False
    )

    username = db.Column(
        db.String(120),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(50),
        nullable=False,
        default='student'
    )

    security_question = db.Column(
        db.String(255),
        nullable=False
    )

    security_answer = db.Column(
        db.String(255),
        nullable=False
    )

    verification_token = db.Column(
        db.String(255),
        nullable=False,
        unique=True
    )

    verification_token_expiry = db.Column(
        db.DateTime,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    # =========================================================
    # AUDIT LOG MODEL
    # =========================================================
class AuditLog(db.Model):
        __tablename__ = 'audit_logs'

        id = db.Column(
            db.Integer,
            primary_key=True
        )

        # -----------------------------------------------------
        # User who performed the action
        # -----------------------------------------------------

        user_id = db.Column(
            db.Integer,
            db.ForeignKey('user.id'),
            nullable=True
        )

        # -----------------------------------------------------
        # Type of security/system event
        # -----------------------------------------------------

        event_type = db.Column(
            db.String(100),
            nullable=False
        )

        # -----------------------------------------------------
        # Description of the event
        # -----------------------------------------------------

        description = db.Column(
            db.Text,
            nullable=False
        )

        # -----------------------------------------------------
        # IP address
        # -----------------------------------------------------

        ip_address = db.Column(
            db.String(45),
            nullable=True
        )

        # -----------------------------------------------------
        # Browser / device information
        # -----------------------------------------------------

        user_agent = db.Column(
            db.String(255),
            nullable=True
        )

        # -----------------------------------------------------
        # Date and time of event
        # -----------------------------------------------------

        created_at = db.Column(
            db.DateTime,
            default=datetime.utcnow,
            nullable=False
        )

        # -----------------------------------------------------
        # Relationship with User
        # -----------------------------------------------------

        user = db.relationship(
            'User',
            backref=db.backref('audit_logs', lazy=True)
        )

        # -----------------------------------------------------
        # Human-readable Audit ID
        # -----------------------------------------------------

        @property
        def audit_id(self):
            return f"AUD-{self.id:06d}"

# =========================================================
# SECURITY REPORT MODEL
# =========================================================

class SecurityReport(db.Model):
    __tablename__ = 'security_reports'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # -----------------------------------------------------
    # User who reported the suspicious activity
    # -----------------------------------------------------

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    # -----------------------------------------------------
    # Audit log associated with the report
    # -----------------------------------------------------

    audit_log_id = db.Column(
        db.Integer,
        db.ForeignKey('audit_logs.id'),
        nullable=False
    )

    # -----------------------------------------------------
    # Reason / explanation provided by the user
    # -----------------------------------------------------

    reason = db.Column(
        db.Text,
        nullable=False
    )

    # -----------------------------------------------------
    # IP address from which report was submitted
    # -----------------------------------------------------

    ip_address = db.Column(
        db.String(45),
        nullable=True
    )

    # -----------------------------------------------------
    # Date and time when report was submitted
    # -----------------------------------------------------

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # -----------------------------------------------------
    # Report status
    # -----------------------------------------------------

    status = db.Column(
        db.String(50),
        nullable=False,
        default='Open',
        server_default='Open'
    )

    # -----------------------------------------------------
    # Relationship with User
    # -----------------------------------------------------

    user = db.relationship(
        'User',
        backref=db.backref(
            'security_reports',
            lazy=True
        )
    )

    # -----------------------------------------------------
    # Relationship with AuditLog
    # -----------------------------------------------------

    audit_log = db.relationship(
        'AuditLog',
        backref=db.backref(
            'security_reports',
            lazy=True
        )
    )

    # -----------------------------------------------------
    # Human-readable Security Report ID
    # -----------------------------------------------------

    @property
    def report_id(self):
        return f"REP-{self.id:06d}"