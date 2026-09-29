from flask import (
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session,
    jsonify
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_mail import Message

from security.security_config import PASSWORD_HASH_METHOD

from . import auth_bp
from app import db, mail
from app.models import User, PendingRegistration
from .forms import RegistrationForm, LoginForm
from app.audit import log_event

import secrets
import hashlib
import face_recognition
import numpy as np
import base64
import io
import json

from PIL import Image

from datetime import datetime, timedelta


# ============================================================
# HELPER FUNCTION
# ============================================================

def validate_password(password, username=None, email=None):
    """
    Validate password security requirements.

    Password must:
    - Be at least 12 characters long
    - Contain a lowercase letter
    - Contain an uppercase letter
    - Contain a number
    - Contain a special character
    - Not contain the username
    - Not contain the email address

    Returns:
        None -> password is valid
        String -> validation error message
    """

    # --------------------------------------------------------
    # Basic password length
    # --------------------------------------------------------

    if len(password) < 12:

        return (
            "Password must be at least 12 characters long."
        )

    # --------------------------------------------------------
    # Lowercase character
    # --------------------------------------------------------

    if not any(
        char.islower()
        for char in password
    ):

        return (
            "Password must contain at least one lowercase letter."
        )

    # --------------------------------------------------------
    # Uppercase character
    # --------------------------------------------------------

    if not any(
        char.isupper()
        for char in password
    ):

        return (
            "Password must contain at least one uppercase letter."
        )

    # --------------------------------------------------------
    # Number
    # --------------------------------------------------------

    if not any(
        char.isdigit()
        for char in password
    ):

        return (
            "Password must contain at least one number."
        )

    # --------------------------------------------------------
    # Special character
    # --------------------------------------------------------

    if not any(
        char in "@$!%*?&"
        for char in password
    ):

        return (
            "Password must contain at least one special character."
        )

    # --------------------------------------------------------
    # Normalize values for comparison
    # --------------------------------------------------------

    password_lower = password.lower()

    username_lower = (
        username.strip().lower()
        if username
        else ""
    )

    email_lower = (
        email.strip().lower()
        if email
        else ""
    )

    # --------------------------------------------------------
    # Password must not contain username
    # --------------------------------------------------------

    if (
        username_lower
        and
        username_lower in password_lower
    ):

        return (
            "Password must not contain your username."
        )

    # --------------------------------------------------------
    # Password must not contain email address
    # --------------------------------------------------------

    if (
        email_lower
        and
        email_lower in password_lower
    ):

        return (
            "Password must not contain your email address."
        )

    # --------------------------------------------------------
    # Password is valid
    # --------------------------------------------------------

    return None

# ============================================================
# BIOMETRIC FACE ENCODING HELPER
# ============================================================

def get_face_encoding(image):

    """
    Detect exactly one face in an image and
    return its facial encoding.

    Returns:
        Face encoding -> if exactly one face is detected
        None -> if zero or multiple faces are detected
    """

    # --------------------------------------------------------
    # Detect faces
    # --------------------------------------------------------

    face_locations = face_recognition.face_locations(
        image
    )

    # --------------------------------------------------------
    # Exactly one face must be present
    # --------------------------------------------------------

    if len(face_locations) != 1:
        return None

    # --------------------------------------------------------
    # Generate face encoding
    # --------------------------------------------------------

    encodings = face_recognition.face_encodings(
        image,
        face_locations
    )

    # --------------------------------------------------------
    # Make sure encoding was generated
    # --------------------------------------------------------

    if not encodings:
        return None

    return encodings[0]


# ============================================================
# BIOMETRIC IMAGE DECODING HELPER
# ============================================================

def decode_base64_image(image_data):

    """
    Convert a Base64-encoded image received from the browser
    into a NumPy image array.

    Returns:
        NumPy image array -> if decoding is successful
        None -> if the image is invalid
    """

    try:

        # ----------------------------------------------------
        # Remove the Data URL prefix
        # ----------------------------------------------------

        if "," in image_data:

            image_data = image_data.split(
                ",",
                1
            )[1]

        # ----------------------------------------------------
        # Decode Base64 data
        # ----------------------------------------------------

        image_bytes = base64.b64decode(
            image_data
        )

        # ----------------------------------------------------
        # Convert bytes into an image
        # ----------------------------------------------------

        image = Image.open(
            io.BytesIO(image_bytes)
        ).convert("RGB")

        # ----------------------------------------------------
        # Convert image to NumPy array
        # ----------------------------------------------------

        return np.array(
            image
        )

    except Exception:

        return None

# ============================================================
# MFA OTP HELPER
# ============================================================
#
# Generates a secure 6-digit OTP for two-factor authentication.
#
# The OTP itself is never stored in the database.
# Only its hash is stored.
#
# ============================================================

def generate_mfa_otp():

    # Generate a random 6-digit OTP
    otp = str(
        secrets.randbelow(900000) + 100000
    )

    return otp


# ============================================================
# SEND MFA OTP EMAIL
# ============================================================

def send_mfa_otp_email(user, otp):

    """
    Send the MFA OTP to the user's registered email address.
    """

    msg = Message(
        subject="SecureCloud Learn - Login Verification Code",

        recipients=[
            user.email
        ]
    )

    msg.body = f"""
Hello {user.username},

A login attempt was made on your SecureCloud Learn account.

Your verification code is:

{otp}

This verification code will expire in 5 minutes.

If you did not attempt to log in, please secure your account
and change your password.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    mail.send(msg)

# ============================================================
# SEND SUSPICIOUS LOGIN ALERT EMAIL
# ============================================================

def send_suspicious_login_email(
    user,
    audit_log
):

    """
    Notify the user when an unusual login is detected.

    The email contains a link to review and report
    the specific security activity.
    """

    report_link = url_for(
        'dashboard_bp.report_suspicious_activity',
        audit_log_id=audit_log.id,
        _external=True
    )

    msg = Message(
        subject="SecureCloud Learn - Suspicious Login Detected",

        recipients=[
            user.email
        ]
    )

    msg.body = f"""
Hello {user.username},

We detected a login to your SecureCloud Learn account
that appears different from your previous login activity.

Security Activity Details:

Audit ID:
AUD-{audit_log.id:06d}

IP Address:
{audit_log.ip_address or 'N/A'}

Date & Time:
{audit_log.created_at.strftime('%d %b %Y, %H:%M:%S')}

Event:
{audit_log.event_type}

Description:
{audit_log.description or 'N/A'}


If you recognize this activity, no action is required.

If you do NOT recognize this activity, please review
the security event and report it as suspicious:

{report_link}


You will be asked to authenticate yourself before the
security report can be submitted.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    mail.send(msg)

# =========================================================
# SEND SECURITY ACTIVITY ALERT EMAIL
# =========================================================

def send_security_activity_email(user, audit_log):

    """
    Send a security activity alert to the user's
    registered email address.

    This does NOT submit a suspicious-activity report.
    It only informs the user that a security event
    was recorded and gives them the option to report it.
    """

    report_url = url_for(
        'dashboard_bp.report_suspicious_activity',
        audit_log_id=audit_log.id,
        _external=True
    )

    msg = Message(
        subject="SecureCloud Learn - Security Activity Alert",
        recipients=[
            user.email
        ]
    )

    msg.body = f"""
Hello {user.username},

We detected security-related activity on your
SecureCloud Learn account.

Activity details:

Audit ID:
AUD-{audit_log.id:06d}

Event:
{audit_log.event_type}

Date & Time:
{audit_log.created_at.strftime('%d %b %Y, %I:%M %p')}

IP Address:
{audit_log.ip_address or 'N/A'}

Description:
{audit_log.description or 'N/A'}


Was this you?

If you recognize this activity, no action is required.

If you do NOT recognize this activity, you can report it
as suspicious using the following link:

{report_url}


Important:

Clicking the link does NOT immediately submit a report.
You will first be asked to verify your identity.


Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    mail.send(msg)

# ============================================================
# EMAIL CHECK / VERIFY BUTTON
# ============================================================
#
# This route is used by the "Verify Email" button present
# beside the email field on the Register and Login pages.
#
# It checks the application's database.
#
# Register:
#   - Email available
#   - Email already registered
#   - Verification pending
#
# Login:
#   - Email found and verified
#   - Email found but not verified
#   - Email not found
#
# IMPORTANT:
# This checks database registration status.
# It does NOT prove ownership of the external email address.
# Actual ownership is verified through the email verification link.
#
# ============================================================

@auth_bp.route(
    '/check-email',
    methods=['POST']
)
def check_email():

    # --------------------------------------------------------
    # Get email from request
    # --------------------------------------------------------

    email = (
        request.form.get(
            'email',
            ''
        )
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Empty email
    # --------------------------------------------------------

    if not email:

        return jsonify({
            'success': False,
            'status': 'empty',
            'message': 'Please enter an email address.'
        }), 400

    # --------------------------------------------------------
    # Basic email format check
    #
    # This is only a basic client-independent validation.
    # The actual WTForms validation remains responsible for
    # complete registration validation.
    # --------------------------------------------------------

    if (
        '@' not in email
        or
        '.' not in email.split('@')[-1]
    ):

        return jsonify({
            'success': False,
            'status': 'invalid',
            'message': 'Please enter a valid email address.'
        }), 400

    # ========================================================
    # CHECK ACTUAL USER ACCOUNT
    # ========================================================

    user = User.query.filter_by(
        email=email
    ).first()

    if user:

        # ----------------------------------------------------
        # Email exists and has been verified
        # ----------------------------------------------------

        if user.email_verified:

            return jsonify({
                'success': True,
                'status': 'verified',
                'message': 'Email address is registered and verified.'
            })

        # ----------------------------------------------------
        # Email exists but is not verified
        # ----------------------------------------------------

        return jsonify({
            'success': False,
            'status': 'unverified',
            'message': (
                'This email address is registered but has not '
                'been verified yet.'
            )
        })

    # ========================================================
    # CHECK PENDING REGISTRATION
    # ========================================================

    pending = PendingRegistration.query.filter_by(
        email=email
    ).first()

    if pending:

        # ----------------------------------------------------
        # Check pending registration expiry
        # ----------------------------------------------------

        if (
            pending.verification_token_expiry
            and
            datetime.utcnow()
            >
            pending.verification_token_expiry
        ):

            db.session.delete(
                pending
            )

            db.session.commit()

        else:

            return jsonify({
                'success': False,
                'status': 'pending',
                'message': (
                    'A registration using this email is '
                    'already waiting for email verification.'
                )
            })

    # ========================================================
    # EMAIL IS AVAILABLE
    # ========================================================

    return jsonify({
        'success': True,
        'status': 'available',
        'message': (
            'Email address is available for registration.'
        )
    })


# ============================================================
# REGISTER ROUTE
# ============================================================

@auth_bp.route(
    '/register',
    methods=['GET', 'POST']
)
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        # ----------------------------------------------------
        # Get and normalize registration data
        # ----------------------------------------------------

        name = form.name.data.strip()

        username = (
            form.username.data
            .strip()
        )

        email = (
            form.email.data
            .strip()
            .lower()
        )

        password_error = validate_password(
            form.password.data,
            username=username,
            email=email
        )

        if password_error:
            flash(
                password_error,
                "danger"
            )

            return render_template(
                "register.html",
                form=form
            )

        role = form.role.data

        # ----------------------------------------------------
        # Security question
        # ----------------------------------------------------

        security_question = (
            form.security_question.data
            .strip()
        )

        # ----------------------------------------------------
        # Normalize security answer
        # ----------------------------------------------------

        security_answer = (
            form.security_answer.data
            .strip()
            .lower()
        )

        # ----------------------------------------------------
        # Check existing User account
        # ----------------------------------------------------

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:

            flash(
                "Username or Email already exists.",
                "danger"
            )

            return redirect(
                url_for('auth_bp.register')
            )

        # ----------------------------------------------------
        # Check PendingRegistration
        # ----------------------------------------------------

        pending_registration = (
            PendingRegistration.query.filter(
                (PendingRegistration.username == username) |
                (PendingRegistration.email == email)
            ).first()
        )

        if pending_registration:

            # ------------------------------------------------
            # Remove expired pending registration
            # ------------------------------------------------

            if (
                pending_registration.verification_token_expiry
                and
                datetime.utcnow()
                >
                pending_registration.verification_token_expiry
            ):

                db.session.delete(
                    pending_registration
                )

                db.session.commit()

            else:

                flash(
                    "A verification email has already been sent. "
                    "Please check your email.",
                    "warning"
                )

                return redirect(
                    url_for('auth_bp.login')
                )

        # ----------------------------------------------------
        # Validate password against username and email
        # ----------------------------------------------------

        password_error = validate_password(
            form.password.data,
            username=username,
            email=email
        )

        if password_error:
            flash(
                password_error,
                "danger"
            )

            return render_template(
                "register.html",
                form=form
            )

        # ----------------------------------------------------
        # Hash password
        # ----------------------------------------------------

        hashed_password = generate_password_hash(
            form.password.data,
            method=PASSWORD_HASH_METHOD
        )

        # ----------------------------------------------------
        # Hash security answer
        # ----------------------------------------------------

        hashed_security_answer = (
            generate_password_hash(
                security_answer,
                method=PASSWORD_HASH_METHOD
            )
        )

        # ----------------------------------------------------
        # Generate verification token
        # ----------------------------------------------------

        verification_token = (
            secrets.token_urlsafe(32)
        )

        # ----------------------------------------------------
        # Hash verification token
        # ----------------------------------------------------

        verification_token_hash = (
            hashlib.sha256(
                verification_token.encode('utf-8')
            ).hexdigest()
        )

        # ----------------------------------------------------
        # Verification token expires after 30 minutes
        # ----------------------------------------------------

        verification_expiry = (
            datetime.utcnow()
            +
            timedelta(minutes=30)
        )

        # ----------------------------------------------------
        # Create PendingRegistration
        # ----------------------------------------------------

        pending = PendingRegistration(

            name=name,

            username=username,

            email=email,

            password=hashed_password,

            role=role,

            security_question=security_question,

            security_answer=hashed_security_answer,

            verification_token=verification_token_hash,

            verification_token_expiry=verification_expiry
        )

        db.session.add(
            pending
        )

        db.session.commit()

        # ----------------------------------------------------
        # Create verification URL
        # ----------------------------------------------------

        verification_url = url_for(
            'auth_bp.verify_email',
            token=verification_token,
            _external=True
        )

        # ----------------------------------------------------
        # Create verification email
        # ----------------------------------------------------

        msg = Message(
            subject=(
                "SecureCloud Learn - Verify Your Email"
            ),

            recipients=[
                email
            ]
        )

        msg.body = f"""
Hello {name},

Thank you for registering with SecureCloud Learn.

To complete your registration and create your account,
please verify your email address using the secure link below:

{verification_url}

This verification link will expire in 30 minutes.

Your SecureCloud Learn account will only be created
after your email address has been successfully verified.

If you did not register for a SecureCloud Learn account,
kindly ignore this email.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

        # ----------------------------------------------------
        # Send verification email
        # ----------------------------------------------------

        try:

            mail.send(
                msg
            )

            print(
                f"VERIFICATION EMAIL SENT TO: {email}"
            )

        except Exception as e:

            print(
                "VERIFICATION EMAIL ERROR:",
                type(e).__name__,
                str(e)
            )

            db.session.delete(
                pending
            )

            db.session.commit()

            flash(
                "Unable to send verification email. "
                "Please try again.",
                "danger"
            )

            return redirect(
                url_for('auth_bp.register')
            )

        # ----------------------------------------------------
        # Registration received
        # ----------------------------------------------------

        flash(
            "Registration received successfully! "
            "Please check your email and verify your "
            "email address to create your account.",
            "success"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        "register.html",
        form=form
    )
# ============================================================
# EMAIL EXISTENCE CHECK
# ============================================================
#
# ============================================================
# VERIFY EMAIL REQUEST
# ============================================================
#
# Used by the "Verify Email" button on the
# registration/login page.
#
# This does NOT verify ownership of the email.
# It only checks whether the email already exists
# in the database.
#
# ============================================================

@auth_bp.route(
    '/verify-email-request',
    methods=['POST']
)
def verify_email_request():

    # --------------------------------------------------------
    # Get JSON data sent by JavaScript
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    email = (
        data.get(
            'email',
            ''
        )
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Empty email
    # --------------------------------------------------------

    if not email:

        return {
            'success': False,
            'exists': False,
            'message': 'Please enter an email address.'
        }, 400

    # --------------------------------------------------------
    # Check registered User account
    # --------------------------------------------------------

    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:

        return {
            'success': True,
            'exists': True,
            'pending': False,
            'message': (
                'This email address is already registered.'
            )
        }

    # --------------------------------------------------------
    # Check pending registration
    #
    # This means the user has already started registration
    # but has not completed email verification yet.
    # --------------------------------------------------------

    pending_registration = (
        PendingRegistration.query
        .filter_by(
            email=email
        )
        .first()
    )

    if pending_registration:

        # ----------------------------------------------------
        # Check whether pending verification has expired
        # ----------------------------------------------------

        if (
            pending_registration.verification_token_expiry
            and
            datetime.utcnow()
            >
            pending_registration.verification_token_expiry
        ):

            db.session.delete(
                pending_registration
            )

            db.session.commit()

        else:

            return {
                'success': True,
                'exists': False,
                'pending': True,
                'message': (
                    'A verification email has already '
                    'been sent to this email address.'
                )
            }

    # --------------------------------------------------------
    # Email is available
    # --------------------------------------------------------

    return {
        'success': True,
        'exists': False,
        'pending': False,
        'message': 'Verified.'
    }

# ============================================================
# EMAIL VERIFICATION ROUTE
# ============================================================

@auth_bp.route(
    '/verify-email/<token>'
)
def verify_email(token):

    # --------------------------------------------------------
    # Hash received token
    # --------------------------------------------------------

    token_hash = (
        hashlib.sha256(
            token.encode('utf-8')
        ).hexdigest()
    )

    # --------------------------------------------------------
    # Find pending registration
    # --------------------------------------------------------

    pending = (
        PendingRegistration.query
        .filter_by(
            verification_token=token_hash
        )
        .first()
    )

    # --------------------------------------------------------
    # Invalid / already used token
    # --------------------------------------------------------

    if not pending:

        flash(
            "This verification link is invalid or has already "
            "been used. If you have not completed registration, "
            "please register again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Check token expiry
    # --------------------------------------------------------

    if (
        not pending.verification_token_expiry
        or
        datetime.utcnow()
        >
        pending.verification_token_expiry
    ):

        db.session.delete(
            pending
        )

        db.session.commit()

        flash(
            "This verification link has expired. "
            "Please register again to receive a new "
            "verification link.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.register')
        )

    # --------------------------------------------------------
    # Double-check username/email
    # --------------------------------------------------------

    existing_user = User.query.filter(
        (User.username == pending.username) |
        (User.email == pending.email)
    ).first()

    if existing_user:

        db.session.delete(
            pending
        )

        db.session.commit()

        flash(
            "This username or email is already registered. "
            "Please use the existing account to log in.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Create actual User account
    # --------------------------------------------------------

    user = User(

        username=pending.username,

        email=pending.email,

        password=pending.password,

        # ----------------------------------------------------
        # Password change tracking
        # ----------------------------------------------------

        password_changed_at=datetime.utcnow(),

        role=pending.role,

        email_verified=True,

        security_question=(
            pending.security_question
        ),

        security_answer=(
            pending.security_answer
        )
    )

    db.session.add(user)

    # --------------------------------------------------------
    # Delete pending registration
    # --------------------------------------------------------

    db.session.delete(pending)

    db.session.commit()

    # --------------------------------------------------------
    # Success
    # --------------------------------------------------------

    flash(
        "Email verified successfully! "
        "Your account has been created. "
        "You can now log in.",
        "success"
    )

    return redirect(
        url_for('auth_bp.login')
    )


# ============================================================
# RESEND EMAIL VERIFICATION
# ============================================================

@auth_bp.route(
    '/resend-verification',
    methods=['POST']
)
def resend_verification():

    # --------------------------------------------------------
    # Get email
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    email = (
        data.get(
            'email',
            ''
        )
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Validate email
    # --------------------------------------------------------

    if not email:
        return jsonify({
            'success': False,
            'message': (
                'Please enter your email address.'
            )
        }), 400

    # --------------------------------------------------------
    # Find existing user
    # --------------------------------------------------------

    user = User.query.filter_by(
        email=email
    ).first()

    # --------------------------------------------------------
    # User does not exist
    # --------------------------------------------------------

    if not user:
        return jsonify({
            'success': False,
            'message': (
                'No registered account was found '
                'with this email address.'
            )
        }), 404

    # --------------------------------------------------------
    # Already verified
    # --------------------------------------------------------

    if user.email_verified:
        return jsonify({
            'success': False,
            'message': (
                'This email address is already verified.'
            )
        }), 400

    # --------------------------------------------------------
    # Generate new verification token
    # --------------------------------------------------------

    verification_token = (
        secrets.token_urlsafe(32)
    )

    # --------------------------------------------------------
    # Hash verification token
    # --------------------------------------------------------

    verification_token_hash = (
        hashlib.sha256(
            verification_token.encode('utf-8')
        ).hexdigest()
    )

    # --------------------------------------------------------
    # Set expiry - 30 minutes
    # --------------------------------------------------------

    verification_expiry = (
            datetime.utcnow()
            +
            timedelta(minutes=30)
    )

    # --------------------------------------------------------
    # Store verification information
    # --------------------------------------------------------

    user.verification_token = (
        verification_token_hash
    )

    user.verification_token_expiry = (
        verification_expiry
    )

    db.session.commit()

    # --------------------------------------------------------
    # Create verification URL
    # --------------------------------------------------------

    verification_url = url_for(
        'auth_bp.verify_existing_email',
        token=verification_token,
        _external=True
    )

    # --------------------------------------------------------
    # Create email
    # --------------------------------------------------------

    msg = Message(
        subject=(
            "SecureCloud Learn - Verify Your Email"
        ),
        recipients=[
            user.email
        ]
    )

    msg.body = f"""
Hello {user.username},

Your SecureCloud Learn account already exists,
but your email address has not yet been verified.

Please verify your email address using the secure
link below:

{verification_url}

This verification link will expire in 30 minutes.

If you did not request this verification email,
please ignore this message.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    # --------------------------------------------------------
    # Send email
    # --------------------------------------------------------

    try:

        mail.send(
            msg
        )

        print(
            f"VERIFICATION EMAIL RESENT TO: {user.email}"
        )

    except Exception as e:

        print(
            "VERIFICATION EMAIL RESEND ERROR:",
            type(e).__name__,
            str(e)
        )

        user.verification_token = None

        user.verification_token_expiry = None

        db.session.commit()

        return jsonify({
            'success': False,
            'message': (
                'Unable to send the verification email. '
                'Please try again.'
            )
        }), 500

    # --------------------------------------------------------
    # Success
    # --------------------------------------------------------

    return jsonify({
        'success': True,
        'message': (
            'A new verification email has been sent '
            'to your registered email address.'
        )
    })

# ============================================================
# VERIFY EMAIL FOR EXISTING USER
# ============================================================

@auth_bp.route(
    '/verify-existing-email/<token>'
)
def verify_existing_email(token):

    # --------------------------------------------------------
    # Hash received token
    # --------------------------------------------------------

    token_hash = (
        hashlib.sha256(
            token.encode('utf-8')
        ).hexdigest()
    )

    # --------------------------------------------------------
    # Find existing user
    # --------------------------------------------------------

    user = User.query.filter_by(
        verification_token=token_hash
    ).first()

    # --------------------------------------------------------
    # Invalid token
    # --------------------------------------------------------

    if not user:
        flash(
            "This verification link is invalid or "
            "has already been used.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Already verified
    # --------------------------------------------------------

    if user.email_verified:
        user.verification_token = None

        user.verification_token_expiry = None

        db.session.commit()

        flash(
            "Your email address is already verified.",
            "info"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Check expiry
    # --------------------------------------------------------

    if (
            not user.verification_token_expiry
            or
            datetime.utcnow()
            >
            user.verification_token_expiry
    ):
        user.verification_token = None

        user.verification_token_expiry = None

        db.session.commit()

        flash(
            "This verification link has expired. "
            "Please request a new verification email.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Verify email
    # --------------------------------------------------------

    user.email_verified = True

    # --------------------------------------------------------
    # Invalidate token
    # --------------------------------------------------------

    user.verification_token = None

    user.verification_token_expiry = None

    db.session.commit()

    # --------------------------------------------------------
    # Success
    # --------------------------------------------------------

    flash(
        "Email verified successfully! "
        "You can now log in to your account.",
        "success"
    )

    return redirect(
        url_for('auth_bp.login')
    )


# ============================================================
# UNUSUAL LOGIN DETECTION
# ============================================================

def is_unusual_login(user, ip_address, user_agent):
    """
    Check whether the current successful login appears unusual
    compared with the user's previous successful logins.
    """

    from app.models import AuditLog

    # --------------------------------------------------------
    # Get previous successful login
    # --------------------------------------------------------

    previous_login = AuditLog.query.filter_by(
        user_id=user.id,
        event_type='LOGIN_SUCCESS'
    ).order_by(
        AuditLog.id.desc()
    ).first()

    # --------------------------------------------------------
    # No previous successful login
    #
    # First login is treated as normal.
    # --------------------------------------------------------

    if not previous_login:
        return False

    # --------------------------------------------------------
    # Check IP address
    # --------------------------------------------------------

    unusual_ip = False

    if (
            previous_login.ip_address
            and
            ip_address
            and
            previous_login.ip_address != ip_address
    ):
        unusual_ip = True

    # --------------------------------------------------------
    # Check browser / device
    # --------------------------------------------------------

    unusual_device = False

    if (
            previous_login.user_agent
            and
            user_agent
            and
            previous_login.user_agent != user_agent
    ):
        unusual_device = True

    # --------------------------------------------------------
    # Check login time
    # --------------------------------------------------------

    unusual_time = False

    if previous_login.created_at:

        current_hour = datetime.utcnow().hour
        previous_hour = previous_login.created_at.hour

        # Calculate difference between login hours
        hour_difference = abs(
            current_hour - previous_hour
        )

        # Handle midnight crossing
        hour_difference = min(
            hour_difference,
            24 - hour_difference
        )

        # Consider a difference of 6+ hours unusual
        if hour_difference >= 6:
            unusual_time = True

    # --------------------------------------------------------
    # Determine whether login is unusual
    # --------------------------------------------------------

    return (
            unusual_ip
            or
            unusual_device
            or
            unusual_time
    )

# =========================================================
# SEND UNUSUAL LOGIN SECURITY ALERT EMAIL
# =========================================================

def send_unusual_login_alert_email(
    user,
    ip_address,
    user_agent,
    audit_log_id
):

    msg = Message(
        subject="SecureCloud Learn - Unusual Login Detected",
        recipients=[
            user.email
        ]
    )

    msg.body = f"""
Hello {user.username},

A login to your SecureCloud Learn account was detected
from an unusual login environment.

Login details:

Audit ID:
AUD-{audit_log_id:06d}

IP Address:
{ip_address or 'N/A'}

Browser / Device:
{user_agent or 'N/A'}

Date & Time:
{datetime.utcnow().strftime('%d %b %Y, %H:%M:%S')} UTC


If this was you:
You can safely ignore this email.

If this was NOT you:
Please review the security activity in your account
and report the suspicious activity.

You should also change your password if you believe
your account may have been compromised.


Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    mail.send(msg)

# ============================================================
# LOGIN ROUTE
# ============================================================

@auth_bp.route(
    '/login',
    methods=['GET', 'POST']
)
def login():

    if session.pop(
        "inactivity_logout",
        False
    ):

        flash(
            "You have been logged out due to inactivity. "
            "Please log in again.",
            "warning"
        )

    form = LoginForm()

    if form.validate_on_submit():

        # ----------------------------------------------------
        # Normalize email
        # ----------------------------------------------------

        email = (
            form.email.data
            .strip()
            .lower()
        )

        # ----------------------------------------------------
        # Find user
        # ----------------------------------------------------

        user = User.query.filter_by(
            email=email
        ).first()

        # ----------------------------------------------------
        # Check whether account is already locked
        # ----------------------------------------------------

        if user and user.account_locked:

            flash(
                "Your account is locked due to multiple "
                "failed login attempts. "
                "Please use a recovery method to regain access.",
                "danger"
            )

            return redirect(
                url_for('auth_bp.try_another_way')
            )

        # ----------------------------------------------------
        # Validate credentials
        # ----------------------------------------------------

        if (
            not user
            or
            not check_password_hash(
                user.password,
                form.password.data
            )
        ):

            # ------------------------------------------------
            # User does not exist
            # ------------------------------------------------
            # We cannot count failed attempts for a user
            # that does not exist.

            if not user:
                log_event(
                    user=None,
                    event_type='LOGIN_FAILED',
                    description='Login failed: invalid credentials.',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )

                flash(
                    "Invalid credentials.",
                    "danger"
                )

                return redirect(
                    url_for('auth_bp.login')
                )
            # ------------------------------------------------
            # User exists - count failed login attempt
            # ------------------------------------------------

            log_event(
                user=user,
                event_type='LOGIN_FAILED',
                description='Login failed: incorrect password.',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

            user.failed_login_attempts += 1

            # ------------------------------------------------
            # Lock account after 3 failed attempts
            # ------------------------------------------------

            if user.failed_login_attempts >= 3:
                user.account_locked = True

                log_event(
                    user=user,
                    event_type='ACCOUNT_LOCKED',
                    description='Account locked after 3 failed login attempts.',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )

                db.session.commit()

                flash(
                    "Your account has been locked after "
                    "3 failed login attempts. "
                    "Please use a recovery method to regain access.",
                    "danger"
                )

                return redirect(
                    url_for('auth_bp.try_another_way')
                )

            # ------------------------------------------------
            # Save failed attempt
            # ------------------------------------------------

            db.session.commit()

            remaining_attempts = (
                3 - user.failed_login_attempts
            )

            flash(
                f"Invalid credentials. "
                f"{remaining_attempts} login attempt(s) remaining.",
                "danger"
            )

            return redirect(
                url_for('auth_bp.login')
            )

        # ----------------------------------------------------
        # Make sure email is verified
        # ----------------------------------------------------

        if not user.email_verified:

            flash(
                "Please verify your email address before logging in.",
                "warning"
            )

            return redirect(
                url_for('auth_bp.login')
            )

        # ----------------------------------------------------
        # POINT 9 - CHECK PASSWORD AND PIN AGE
        # ----------------------------------------------------

        password_expired = (
                not user.password_changed_at
                or
                datetime.utcnow()
                >=
                user.password_changed_at
                +
                timedelta(days=180)
        )

        pin_expired = False

        if user.pin and user.pin_changed_at:
            pin_expired = (
                    datetime.utcnow()
                    >= user.pin_changed_at + timedelta(days=90)
            )
        # ----------------------------------------------------
        # Password expired
        # ----------------------------------------------------

        if password_expired:
            session['password_expired_user_id'] = user.id

            flash(
                "Your password has expired. "
                "Please change your password before continuing.",
                "warning"
            )

            return redirect(
                url_for('auth_bp.change_password')
            )

        # ----------------------------------------------------
        # PIN expired
        # ----------------------------------------------------

        if pin_expired:
            session['pin_expired_user_id'] = user.id

            flash(
                "Your PIN has expired. "
                "Please change your PIN before continuing.",
                "warning"
            )

            return redirect(
                url_for('auth_bp.change_pin')
            )

        # ----------------------------------------------------
        # MFA CHECK
        # ----------------------------------------------------

        if user.mfa_enabled:

            # ------------------------------------------------
            # Generate a new 6-digit OTP
            # ------------------------------------------------

            otp = generate_mfa_otp()

            # ------------------------------------------------
            # Hash OTP before storing it
            # ------------------------------------------------

            user.mfa_otp_hash = generate_password_hash(
                otp,
                method=PASSWORD_HASH_METHOD
            )

            # ------------------------------------------------
            # OTP expires after 5 minutes
            # ------------------------------------------------

            user.mfa_otp_expiry = (
                    datetime.utcnow()
                    +
                    timedelta(minutes=1)
            )

            db.session.commit()

            # ------------------------------------------------
            # Store user ID temporarily in session
            #
            # The user is NOT logged in yet.
            # ------------------------------------------------

            session['mfa_user_id'] = user.id

            # ------------------------------------------------
            # Send OTP to registered email
            # ------------------------------------------------

            try:

                send_mfa_otp_email(
                    user,
                    otp
                )

            except Exception as e:

                print(
                    "MFA OTP EMAIL ERROR:",
                    type(e).__name__,
                    str(e)
                )

                # Clear OTP if email could not be sent

                user.mfa_otp_hash = None

                user.mfa_otp_expiry = None

                db.session.commit()

                session.pop(
                    'mfa_user_id',
                    None
                )

                flash(
                    "Unable to send the login verification code. "
                    "Please try again.",
                    "danger"
                )

                return redirect(
                    url_for('auth_bp.login')
                )

            # ------------------------------------------------
            # Send user to MFA verification page
            # ------------------------------------------------

            flash(
                "A verification code has been sent to your "
                "registered email address.",
                "info"
            )

            return redirect(
                url_for('auth_bp.verify_mfa')
            )

        # ====================================================
        # MFA NOT ENABLED
        # ====================================================
        #
        # Continue with the normal login process.
        #

        login_result = login_user(
            user
        )

        print(
            "========== MFA LOGIN DEBUG =========="
        )

        print(
            "login_user result:",
            login_result
        )

        print(
            "current_user authenticated:",
            current_user.is_authenticated
        )

        print(
            "current_user id:",
            current_user.get_id()
        )

        print(
            "current_user role:",
            current_user.role
        )

        print(
            "session after login:",
            dict(session)
        )

        print(
            "====================================="
        )
        # ----------------------------------------------------
        # Check whether this login is unusual
        # ----------------------------------------------------

        unusual_login = is_unusual_login(
            user=user,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Record successful login
        # ----------------------------------------------------

        login_audit = log_event(
            user=user,
            event_type='LOGIN_SUCCESS',
            description='User logged in successfully.',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Send suspicious activity email if unusual
        # ----------------------------------------------------

        if unusual_login:
            send_suspicious_activity_email(
                user,
                login_audit
            )

        # ----------------------------------------------------
        # Check password age
        # ----------------------------------------------------

        if (
                not user.password_changed_at
                or
                datetime.utcnow()
                >=
                user.password_changed_at + timedelta(days=180)
        ):
            flash(
                "Your password has expired after 6 months. "
                "Please change your password to continue.",
                "warning"
            )

            return redirect(
                url_for(
                    'auth_bp.change_password'
                )
            )

        # ----------------------------------------------------
        # Role-based redirect
        # ----------------------------------------------------

        if user.role == 'admin':
            return redirect(
                url_for(
                    'dashboard_bp.admin_dashboard'
                )
            )

        if user.role == 'instructor':
            return redirect(
                url_for(
                    'dashboard_bp.instructor_dashboard'
                )
            )

        if user.role == 'student':
            return redirect(
                url_for(
                    'dashboard_bp.student_dashboard'
                )
            )

        return redirect(
            url_for(
                'main_bp.home'
            )
        )
    return render_template(
        "login.html",
        form=form
    )

# ============================================================
# MFA VERIFICATION
# ============================================================

@auth_bp.route(
    '/verify-mfa',
    methods=['GET', 'POST']
)
def verify_mfa():

    # --------------------------------------------------------
    # Get pending MFA user
    # --------------------------------------------------------

    user_id = session.get(
        'mfa_user_id'
    )

    if not user_id:

        flash(
            "Your MFA verification session has expired. "
            "Please log in again.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = User.query.get(
        user_id
    )

    if not user:

        session.pop(
            'mfa_user_id',
            None
        )

        flash(
            "Unable to verify your account. "
            "Please log in again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Make sure MFA is still enabled
    # --------------------------------------------------------

    if not user.mfa_enabled:

        session.pop(
            'mfa_user_id',
            None
        )

        flash(
            "MFA verification is not required.",
            "info"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # ========================================================
    # POST - VERIFY OTP
    # ========================================================

    if request.method == 'POST':

        otp = (
            request.form.get(
                'otp',
                ''
            )
            .strip()
        )

        # ----------------------------------------------------
        # Basic OTP validation
        # ----------------------------------------------------

        if (
            not otp
            or
            len(otp) != 6
            or
            not otp.isdigit()
        ):

            flash(
                "Please enter a valid 6-digit verification code.",
                "danger"
            )

            return render_template(
                'mfa_verify.html',
            otp_expiry = user.mfa_otp_expiry,
            )

        # ----------------------------------------------------
        # Check OTP expiry
        # ----------------------------------------------------

        if (
            not user.mfa_otp_expiry
            or
            datetime.utcnow()
            >
            user.mfa_otp_expiry
        ):

            user.mfa_otp_hash = None
            user.mfa_otp_expiry = None

            db.session.commit()

            flash(
                "The verification code has expired. "
                "Please request a new code.",
                "warning"
            )

            return render_template(
                'mfa_verify.html',
            otp_expiry = user.mfa_otp_expiry,
            )

        # ----------------------------------------------------
        # Verify OTP
        # ----------------------------------------------------

        if (
            not user.mfa_otp_hash
            or
            not check_password_hash(
                user.mfa_otp_hash,
                otp
            )
        ):
            log_event(
                user=user,
                event_type='MFA_FAILED',
                description='MFA verification failed: incorrect verification code.',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

            flash(
                "Incorrect verification code. "
                "Please try again.",
                "danger"
            )

            return render_template(
                'mfa_verify.html',
            otp_expiry = user.mfa_otp_expiry,
            )

        # ----------------------------------------------------
        # OTP is correct
        # ----------------------------------------------------

        user.mfa_otp_hash = None

        user.mfa_otp_expiry = None

        db.session.commit()

        log_event(
            user=user,
            event_type='MFA_SUCCESS',
            description='MFA verification completed successfully.',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
# ----------------------------------------------------
        # Remove pending MFA session
        # ----------------------------------------------------

        session.pop(
            'mfa_user_id',
            None
        )

        # ----------------------------------------------------
        # Complete login
        # ----------------------------------------------------

        login_user(
            user,
            remember=False,
            fresh=True
        )

        print("========== MFA LOGIN DEBUG ==========")
        print("User ID:", user.id)
        print("Username:", user.username)
        print("Login successful:", current_user.is_authenticated)
        print("Current user:", current_user)
        print("Session:", dict(session))
        print("=====================================")

        # ----------------------------------------------------
        # Check whether this login is unusual
        # ----------------------------------------------------

        unusual_login = is_unusual_login(
            user=user,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Record successful login
        # ----------------------------------------------------

        login_audit = log_event(
            user=user,
            event_type='LOGIN_SUCCESS',
            description='User logged in successfully.',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Send suspicious-login alert if unusual
        # ----------------------------------------------------

        if unusual_login:

            try:

                send_suspicious_login_email(
                    user=user,
                    audit_log=login_audit
                )

            except Exception as e:

                print(
                    "SUSPICIOUS LOGIN EMAIL ERROR:",
                    type(e).__name__,
                    str(e)
                )

        # ----------------------------------------------------
        # Check password age
        # ----------------------------------------------------

        if (
                not user.password_changed_at
                or
                datetime.utcnow()
                >=
                user.password_changed_at + timedelta(days=180)
        ):
            flash(
                "Your password has expired after 6 months. "
                "Please change your password to continue.",
                "warning"
            )

            return redirect(
                url_for(
                    'auth_bp.change_password'
                )
            )

        # ----------------------------------------------------
        # Role-based redirect
        # ----------------------------------------------------

        if user.role == 'admin':
            return redirect(
                url_for(
                    'dashboard_bp.admin_dashboard'
                )
            )

        if user.role == 'instructor':
            return redirect(
                url_for(
                    'dashboard_bp.instructor_dashboard'
                )
            )

        if user.role == 'student':
            return redirect(
                url_for(
                    'dashboard_bp.student_dashboard'
                )
            )

        return redirect(
            url_for(
                'main_bp.home'
            )
        )
    # ========================================================
    # GET
    # ========================================================

    return render_template(
        'mfa_verify.html',
        otp_expiry=user.mfa_otp_expiry
    )

# ============================================================
# RESEND MFA OTP
# ============================================================

@auth_bp.route(
    '/resend-mfa',
    methods=['GET']
)
def resend_mfa():

    # --------------------------------------------------------
    # Get pending MFA user
    # --------------------------------------------------------

    user_id = session.get(
        'mfa_user_id'
    )

    if not user_id:

        flash(
            "Your MFA session has expired. "
            "Please log in again.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = User.query.get(
        user_id
    )

    if not user:

        session.pop(
            'mfa_user_id',
            None
        )

        flash(
            "Unable to continue MFA verification.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Make sure MFA is enabled
    # --------------------------------------------------------

    if not user.mfa_enabled:

        session.pop(
            'mfa_user_id',
            None
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Generate new OTP
    # --------------------------------------------------------

    otp = generate_mfa_otp()

    # --------------------------------------------------------
    # Hash OTP before storing
    # --------------------------------------------------------

    user.mfa_otp_hash = generate_password_hash(
        otp,
        method=PASSWORD_HASH_METHOD
    )

    # --------------------------------------------------------
    # OTP valid for 5 minutes
    # --------------------------------------------------------

    user.mfa_otp_expiry = (
        datetime.utcnow()
        +
        timedelta(minutes=1)
    )

    db.session.commit()

    # --------------------------------------------------------
    # Send OTP
    # --------------------------------------------------------

    try:

        send_mfa_otp_email(
            user,
            otp
        )

    except Exception as e:

        print(
            "MFA OTP EMAIL ERROR:",
            type(e).__name__,
            str(e)
        )

        user.mfa_otp_hash = None
        user.mfa_otp_expiry = None

        db.session.commit()

        flash(
            "Unable to send the verification code. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    flash(
        "A new verification code has been sent to your email.",
        "success"
    )

    return redirect(
        url_for('auth_bp.verify_mfa')
    )

# ============================================================
# ENABLE MFA
# ============================================================

@auth_bp.route(
    '/enable-mfa',
    methods=['GET']
)
@login_required
def enable_mfa():

    user = current_user

    # --------------------------------------------------------
    # MFA already enabled
    # --------------------------------------------------------

    if user.mfa_enabled:

        flash(
            "Two-Factor Authentication is already enabled.",
            "info"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    # --------------------------------------------------------
    # Generate OTP
    # --------------------------------------------------------

    otp = generate_mfa_otp()

    # --------------------------------------------------------
    # Hash OTP
    # --------------------------------------------------------

    user.mfa_otp_hash = generate_password_hash(
        otp,
        method=PASSWORD_HASH_METHOD
    )

    # --------------------------------------------------------
    # OTP expires after 5 minutes
    # --------------------------------------------------------

    user.mfa_otp_expiry = (
        datetime.utcnow()
        +
        timedelta(minutes=1)
    )

    db.session.commit()

    # --------------------------------------------------------
    # Store user ID for MFA setup verification
    # --------------------------------------------------------

    session['mfa_setup_user_id'] = user.id

    # --------------------------------------------------------
    # Send OTP
    # --------------------------------------------------------

    try:

        send_mfa_otp_email(
            user,
            otp
        )

    except Exception as e:

        print(
            "MFA SETUP OTP EMAIL ERROR:",
            type(e).__name__,
            str(e)
        )

        user.mfa_otp_hash = None
        user.mfa_otp_expiry = None

        db.session.commit()

        session.pop(
            'mfa_setup_user_id',
            None
        )

        flash(
            "Unable to send the verification code. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    flash(
        "A verification code has been sent to your registered email.",
        "success"
    )

    return redirect(
        url_for('auth_bp.verify_mfa_setup')
    )
# ============================================================
# VERIFY MFA SETUP
# ============================================================

@auth_bp.route(
    '/verify-mfa-setup',
    methods=['GET', 'POST']
)
@login_required
def verify_mfa_setup():

    # --------------------------------------------------------
    # Get pending MFA setup user
    # --------------------------------------------------------

    user_id = session.get(
        'mfa_setup_user_id'
    )

    if not user_id:

        flash(
            "Your MFA setup session has expired. "
            "Please try again.",
            "warning"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    # --------------------------------------------------------
    # Make sure current user matches session
    # --------------------------------------------------------

    if user_id != current_user.id:

        session.pop(
            'mfa_setup_user_id',
            None
        )

        flash(
            "Unable to continue MFA setup.",
            "danger"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    user = current_user

    # --------------------------------------------------------
    # POST - VERIFY OTP
    # --------------------------------------------------------

    if request.method == 'POST':

        otp = (
            request.form.get(
                'otp',
                ''
            )
            .strip()
        )

        # ----------------------------------------------------
        # Validate OTP format
        # ----------------------------------------------------

        if (
            not otp
            or
            len(otp) != 6
            or
            not otp.isdigit()
        ):

            flash(
                "Please enter a valid 6-digit verification code.",
                "danger"
            )

            return render_template(
                'mfa_setup_verify.html'
            )

        # ----------------------------------------------------
        # Check expiry
        # ----------------------------------------------------

        if (
            not user.mfa_otp_expiry
            or
            datetime.utcnow()
            >
            user.mfa_otp_expiry
        ):

            user.mfa_otp_hash = None
            user.mfa_otp_expiry = None

            db.session.commit()

            flash(
                "The verification code has expired. "
                "Please request a new code.",
                "warning"
            )

            return render_template(
                'mfa_setup_verify.html'
            )

        # ----------------------------------------------------
        # Verify OTP
        # ----------------------------------------------------

        if (
            not user.mfa_otp_hash
            or
            not check_password_hash(
                user.mfa_otp_hash,
                otp
            )
        ):

            flash(
                "Incorrect verification code. "
                "Please try again.",
                "danger"
            )

            return render_template(
                'mfa_setup_verify.html'
            )

        # ====================================================
        # OTP CORRECT
        # ====================================================

        user.mfa_enabled = True

        user.mfa_otp_hash = None

        user.mfa_otp_expiry = None

        db.session.commit()

        log_event(
            user=user,
            event_type='MFA_ENABLED',
            description='Two-Factor Authentication was enabled successfully.',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Remove setup session
        # ----------------------------------------------------

        session.pop(
            'mfa_setup_user_id',
            None
        )

        flash(
            "Two-Factor Authentication has been enabled successfully.",
            "success"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        'mfa_setup_verify.html'
    )

# ============================================================
# RESEND MFA SETUP OTP
# ============================================================

@auth_bp.route(
    '/resend-mfa-setup',
    methods=['GET']
)
@login_required
def resend_mfa_setup():

    # --------------------------------------------------------
    # Get pending MFA setup user
    # --------------------------------------------------------

    user_id = session.get(
        'mfa_setup_user_id'
    )

    if not user_id:

        flash(
            "Your MFA setup session has expired. "
            "Please try again.",
            "warning"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    # --------------------------------------------------------
    # Make sure current user matches session
    # --------------------------------------------------------

    if user_id != current_user.id:

        session.pop(
            'mfa_setup_user_id',
            None
        )

        flash(
            "Unable to continue MFA setup.",
            "danger"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    user = current_user

    # --------------------------------------------------------
    # MFA already enabled
    # --------------------------------------------------------

    if user.mfa_enabled:

        session.pop(
            'mfa_setup_user_id',
            None
        )

        flash(
            "Two-Factor Authentication is already enabled.",
            "info"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    # --------------------------------------------------------
    # Generate new OTP
    # --------------------------------------------------------

    otp = generate_mfa_otp()

    # --------------------------------------------------------
    # Hash OTP
    # --------------------------------------------------------

    user.mfa_otp_hash = generate_password_hash(
        otp,
        method=PASSWORD_HASH_METHOD
    )

    # --------------------------------------------------------
    # New OTP valid for 5 minutes
    # --------------------------------------------------------

    user.mfa_otp_expiry = (
        datetime.utcnow()
        +
        timedelta(minutes=1)
    )

    db.session.commit()

    # --------------------------------------------------------
    # Send new OTP
    # --------------------------------------------------------

    try:

        send_mfa_otp_email(
            user,
            otp
        )

    except Exception as e:

        print(
            "MFA SETUP RESEND EMAIL ERROR:",
            type(e).__name__,
            str(e)
        )

        user.mfa_otp_hash = None
        user.mfa_otp_expiry = None

        db.session.commit()

        flash(
            "Unable to send the verification code. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.verify_mfa_setup')
        )

    flash(
        "A new verification code has been sent to your email.",
        "success"
    )

    return redirect(
        url_for('auth_bp.verify_mfa_setup')
    )

# ============================================================
# DISABLE TWO-FACTOR AUTHENTICATION
# ============================================================

@auth_bp.route(
    '/disable-mfa',
    methods=['POST']
)
@login_required
def disable_mfa():

    user = current_user

    # --------------------------------------------------------
    # Make sure MFA is currently enabled
    # --------------------------------------------------------

    if not user.mfa_enabled:

        flash(
            "Two-Factor Authentication is already disabled.",
            "info"
        )

        return redirect(
            url_for('dashboard_bp.mfa_settings')
        )

    # --------------------------------------------------------
    # Disable MFA
    # --------------------------------------------------------

    user.mfa_enabled = False

    # --------------------------------------------------------
    # Clear any pending MFA OTP
    # --------------------------------------------------------

    user.mfa_otp_hash = None

    user.mfa_otp_expiry = None

    db.session.commit()

    log_event(
        user=user,
        event_type='MFA_DISABLED',
        description='Two-Factor Authentication was disabled.',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )

    flash(
        "Two-Factor Authentication has been disabled.",
        "success"
    )

    return redirect(
        url_for('dashboard_bp.mfa_settings')
    )

def send_suspicious_activity_email(user, audit_log):
    report_url = url_for(
        'dashboard_bp.security_report_auth',
        audit_log_id=audit_log.id,
        _external=True
    )

    msg = Message(
        subject="SecureCloud Learn - Suspicious Login Activity Detected",
        recipients=[user.email]
    )

    msg.body = f"""
Hello {user.username},

We detected a login to your SecureCloud Learn account that appears unusual.

Login Details:

Date & Time:
{audit_log.created_at.strftime('%d %b %Y, %I:%M %p')}

IP Address:
{audit_log.ip_address or 'Not available'}

Event:
{audit_log.event_type}

If this login was made by you, no action is required.

If you do not recognize this activity, please review it and report it here:

{report_url}

You will be asked to authenticate yourself before the security report can be submitted.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    mail.send(msg)

# ============================================================
# CHANGE PASSWORD
# ============================================================

@auth_bp.route(
    '/change-password',
    methods=['GET', 'POST']
)
@login_required
def change_password():

    user = current_user

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == 'POST':

        current_password = request.form.get(
            'current_password',
            ''
        )

        new_password = request.form.get(
            'new_password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        # ----------------------------------------------------
        # Verify current password
        # ----------------------------------------------------

        if not check_password_hash(
            user.password,
            current_password
        ):

            flash(
                "Current password is incorrect.",
                "danger"
            )

            return render_template(
                'change_password.html'
            )

        # ----------------------------------------------------
        # New password must be different
        # ----------------------------------------------------

        if check_password_hash(
            user.password,
            new_password
        ):

            flash(
                "New password must be different from "
                "your previous password.",
                "danger"
            )

            return render_template(
                'change_password.html'
            )

        # ----------------------------------------------------
        # Validate new password
        # ----------------------------------------------------

        password_error = validate_password(
            new_password,
            username=user.username,
            email=user.email
        )

        if password_error:

            flash(
                password_error,
                "danger"
            )

            return render_template(
                'change_password.html'
            )

        # ----------------------------------------------------
        # Confirm password
        # ----------------------------------------------------

        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                'change_password.html'
            )

        # ----------------------------------------------------
        # Update password
        # ----------------------------------------------------

        user.password = generate_password_hash(
            new_password,
            method=PASSWORD_HASH_METHOD
        )

        user.password_changed_at = datetime.utcnow()

        db.session.commit()

        flash(
            "Your password has been changed successfully.",
            "success"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        'change_password.html'
    )


# ============================================================
# SET / CHANGE PIN
# ============================================================

@auth_bp.route(
    '/change-pin',
    methods=['GET', 'POST']
)
@login_required
def change_pin():

    user = current_user

    # ========================================================
    # CHECK WHETHER USER ALREADY HAS A PIN
    # ========================================================

    has_pin = bool(user.pin)

    # ========================================================
    # POST
    # ========================================================

    if request.method == 'POST':

        current_pin = request.form.get(
            'current_pin',
            ''
        ).strip()

        new_pin = request.form.get(
            'new_pin',
            ''
        ).strip()

        confirm_pin = request.form.get(
            'confirm_pin',
            ''
        ).strip()

        # ====================================================
        # IF PIN ALREADY EXISTS
        # ====================================================
        #
        # User must provide the current PIN.
        #
        # ====================================================

        if has_pin:

            if not current_pin:

                flash(
                    "Please enter your current PIN.",
                    "danger"
                )

                return render_template(
                    'change_pin.html',
                    has_pin=has_pin
                )

            if not check_password_hash(
                user.pin,
                current_pin
            ):

                flash(
                    "Current PIN is incorrect.",
                    "danger"
                )

                return render_template(
                    'change_pin.html',
                    has_pin=has_pin
                )

            # ------------------------------------------------
            # New PIN must be different
            # ------------------------------------------------

            if check_password_hash(
                user.pin,
                new_pin
            ):

                flash(
                    "New PIN must be different from "
                    "your previous PIN.",
                    "danger"
                )

                return render_template(
                    'change_pin.html',
                    has_pin=has_pin
                )

        # ====================================================
        # VALIDATE NEW PIN
        # ====================================================

        if (
            not new_pin
            or
            not new_pin.isdigit()
            or
            len(new_pin) != 4
        ):

            flash(
                "PIN must contain exactly 4 digits.",
                "danger"
            )

            return render_template(
                'change_pin.html',
                has_pin=has_pin
            )

        # ====================================================
        # CONFIRM PIN
        # ====================================================

        if new_pin != confirm_pin:

            flash(
                "PINs do not match.",
                "danger"
            )

            return render_template(
                'change_pin.html',
                has_pin=has_pin
            )

        # ====================================================
        # SAVE PIN
        # ====================================================

        user.pin = generate_password_hash(
            new_pin,
            method=PASSWORD_HASH_METHOD
        )

        user.pin_changed_at = datetime.utcnow()

        # ----------------------------------------------------
        # Clear expired-PIN session flag
        # ----------------------------------------------------

        session.pop(
            'pin_expired_user_id',
            None
        )

        db.session.commit()

        # ====================================================
        # SUCCESS MESSAGE
        # ====================================================

        if has_pin:

            flash(
                "Your PIN has been changed successfully.",
                "success"
            )

        else:

            flash(
                "Your PIN has been set successfully.",
                "success"
            )

        # ----------------------------------------------------
        # Return to Settings
        # ----------------------------------------------------

        return redirect(
            url_for('dashboard_bp.settings')
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        'change_pin.html',
        has_pin=has_pin
    )

# ============================================================
# LOGOUT ROUTE
# ============================================================

@auth_bp.route(
    '/logout'
)
@login_required
def logout():

    # --------------------------------------------------------
    # Store user information BEFORE logout
    # --------------------------------------------------------

    user = current_user

    # --------------------------------------------------------
    # Audit log
    # --------------------------------------------------------

    log_event(
        user=user,
        event_type='LOGOUT',
        description='User logged out successfully.',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )

    # --------------------------------------------------------
    # Logout user
    # --------------------------------------------------------

    logout_user()

    flash(
        "Logged out successfully.",
        "success"
    )

    return redirect(
        url_for('auth_bp.login')
    )
# ============================================================
# FORGOT PASSWORD
# ============================================================

@auth_bp.route(
    '/forgot-password',
    methods=['GET', 'POST']
)
def forgot_password():

    if request.method == 'POST':

        # ----------------------------------------------------
        # Normalize email
        # ----------------------------------------------------

        email = (
            request.form.get(
                'email',
                ''
            )
            .strip()
            .lower()
        )

        # ----------------------------------------------------
        # Find registered account
        # ----------------------------------------------------

        user = User.query.filter_by(
            email=email
        ).first()

        # ----------------------------------------------------
        # Security:
        #
        # Do not reveal whether account exists.
        # ----------------------------------------------------

        if not user:

            flash(
                "If an account exists with this email, "
                "recovery options will be provided.",
                "success"
            )

            return redirect(
                url_for('auth_bp.login')
            )

        # ----------------------------------------------------
        # Store recovery email
        # ----------------------------------------------------

        session['recovery_email'] = (
            user.email
        )

        # ----------------------------------------------------
        # Show recovery options
        # ----------------------------------------------------

        return render_template(
            'recovery_options.html',
            user=user
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        'forgot_password.html'
    )


# ============================================================
# RECOVERY OPTIONS
# ============================================================

@auth_bp.route(
    '/recovery-options'
)
def recovery_options():

    email = session.get(
        'recovery_email'
    )

    print("FACE RECOVERY EMAIL:", email)

    if not email:

        flash(
            "Please start the password recovery process again.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        session.pop(
            'recovery_email',
            None
        )

        flash(
            "Unable to continue account recovery.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    return render_template(
        'recovery_options.html',
        user=user
    )


# ============================================================
# SEND PASSWORD RESET LINK
# ============================================================

@auth_bp.route(
    '/send-reset-link',
    methods=['POST']
)
def send_reset_link():

    email = session.get(
        'recovery_email'
    )

    if not email:

        flash(
            "Your recovery session has expired. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        session.pop(
            'recovery_email',
            None
        )

        flash(
            "If an account exists with this email, "
            "password reset instructions will be provided.",
            "success"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Generate reset token
    # --------------------------------------------------------

    reset_token = (
        secrets.token_urlsafe(32)
    )

    token_hash = (
        hashlib.sha256(
            reset_token.encode('utf-8')
        ).hexdigest()
    )

    expiry_time = (
        datetime.utcnow()
        +
        timedelta(minutes=30)
    )

    user.reset_token = token_hash

    user.reset_token_expiry = expiry_time

    db.session.commit()

    # --------------------------------------------------------
    # Generate reset URL
    # --------------------------------------------------------

    reset_url = url_for(
        'auth_bp.reset_password',
        token=reset_token,
        _external=True
    )

    # --------------------------------------------------------
    # Password reset email
    # --------------------------------------------------------

    msg = Message(
        subject=(
            "SecureCloud Learn - Password Reset"
        ),

        recipients=[
            user.email
        ]
    )

    msg.body = f"""
Hello {user.username},

We received a request to reset the password
for your SecureCloud Learn account.

To create a new password, please click on the link below:

{reset_url}

This link will expire in 30 minutes.

The link can only be used once.

If you did not request a password reset, kindly ignore
this email. Your current password will remain unchanged.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

    try:

        mail.send(
            msg
        )

        print(
            f"PASSWORD RESET EMAIL SENT TO: {user.email}"
        )

    except Exception as e:

        print(
            "PASSWORD RESET EMAIL ERROR:",
            type(e).__name__,
            str(e)
        )

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        flash(
            "Unable to send the password reset email. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    session.pop(
        'recovery_email',
        None
    )

    flash(
        "If an account exists with this email, "
        "password reset instructions have been sent.",
        "success"
    )

    return redirect(
        url_for('auth_bp.login')
    )


# ============================================================
# SEND RESET EMAIL - COMPATIBILITY ROUTE
# ============================================================

@auth_bp.route(
    '/send-reset-email',
    methods=['GET', 'POST']
)
def send_reset_email():

    return send_reset_link()


# ============================================================
# TRY ANOTHER WAY
# ============================================================

@auth_bp.route(
    '/try-another-way',
    methods=['GET']
)
def try_another_way():

    # --------------------------------------------------------
    # Get recovery email from session
    # --------------------------------------------------------

    email = session.get(
        'recovery_email'
    )

    if not email:

        flash(
            "Your recovery session has expired. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        session.pop(
            'recovery_email',
            None
        )

        flash(
            "Unable to continue account recovery.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Display available recovery methods
    # --------------------------------------------------------

    return render_template(
        'recovery_methods.html',
        user=user
    )

# ============================================================
# VERIFY SECURITY QUESTION
# ============================================================

@auth_bp.route(
    '/verify-security-question',
    methods=['GET', 'POST']
)
def verify_security_question():

    # --------------------------------------------------------
    # Get recovery email from session
    # --------------------------------------------------------

    email = session.get(
        'recovery_email'
    )

    if not email:

        flash(
            "Your recovery session has expired. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        session.pop(
            'recovery_email',
            None
        )

        flash(
            "Unable to continue account recovery.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # ========================================================
    # SECURITY QUESTIONS
    # ========================================================
    #
    # These are the SAME questions used during registration.
    #
    # Registration:
    #   User selects ONE question.
    #
    # Recovery:
    #   User must identify which question they selected.
    #
    # The system does NOT reveal the stored question.
    #
    # ========================================================

    security_questions = [

        'What was the name of your first school?',

        'What is your favorite food?',

        'What was the name of your childhood best friend?',

        'What is the name of your favorite place?'

    ]

    # ========================================================
    # GET
    # ========================================================

    if request.method == 'GET':

        return render_template(
            'security_question.html',
            user=user,
            security_questions=security_questions
        )

    # ========================================================
    # POST
    # ========================================================

    selected_question = (
        request.form.get(
            'security_question',
            ''
        )
        .strip()
    )

    answer = (
        request.form.get(
            'security_answer',
            ''
        )
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Validate selected question
    # --------------------------------------------------------

    if selected_question not in security_questions:

        flash(
            "Please select a valid security question.",
            "danger"
        )

        return render_template(
            'security_question.html',
            user=user,
            security_questions=security_questions
        )

    # --------------------------------------------------------
    # Validate answer
    # --------------------------------------------------------

    if not answer:

        flash(
            "Please enter your security answer.",
            "danger"
        )

        return render_template(
            'security_question.html',
            user=user,
            security_questions=security_questions,
            selected_question=selected_question
        )

    # ========================================================
    # VERIFY QUESTION
    # ========================================================
    #
    # The selected question must be the SAME question
    # originally selected during registration.
    #
    # ========================================================

    question_matches = (
        selected_question
        ==
        user.security_question
    )

    # ========================================================
    # VERIFY ANSWER
    # ========================================================
    #
    # The security answer is stored as a password hash.
    #
    # ========================================================

    answer_matches = (

        user.security_answer

        and

        check_password_hash(
            user.security_answer,
            answer
        )
    )

    # ========================================================
    # BOTH QUESTION AND ANSWER MUST MATCH
    # ========================================================

    if not question_matches or not answer_matches:

        flash(
            "The selected security question or answer "
            "is incorrect. Please try again.",
            "danger"
        )

        return render_template(
            'security_question.html',
            user=user,
            security_questions=security_questions,
            selected_question=selected_question
        )

    # ========================================================
    # SECURITY VERIFICATION SUCCESSFUL
    # ========================================================
    #
    # We DO NOT directly allow password reset.
    #
    # Instead:
    #
    # Security Question
    #       ↓
    # Successful verification
    #       ↓
    # Generate reset token
    #       ↓
    # Send reset email
    #       ↓
    # User opens reset link
    #       ↓
    # Reset password
    #
    # ========================================================

    try:

        # ----------------------------------------------------
        # Generate secure reset token
        # ----------------------------------------------------

        reset_token = secrets.token_urlsafe(
            32
        )

        # ----------------------------------------------------
        # Hash reset token before storing
        # ----------------------------------------------------

        token_hash = hashlib.sha256(
            reset_token.encode(
                'utf-8'
            )
        ).hexdigest()

        # ----------------------------------------------------
        # Reset link expiry
        # ----------------------------------------------------

        expiry_time = (
            datetime.utcnow()
            +
            timedelta(minutes=30)
        )

        # ----------------------------------------------------
        # Store reset token
        # ----------------------------------------------------

        user.reset_token = token_hash

        user.reset_token_expiry = expiry_time

        db.session.commit()

        # ----------------------------------------------------
        # Generate password reset URL
        # ----------------------------------------------------

        reset_url = url_for(
            'auth_bp.reset_password',
            token=reset_token,
            _external=True
        )

        # ----------------------------------------------------
        # Create password reset email
        # ----------------------------------------------------

        msg = Message(

            subject=(
                "SecureCloud Learn - Password Reset"
            ),

            recipients=[
                user.email
            ]
        )

        msg.body = f"""
Hello {user.username},

To create a new password for your
SecureCloud Learn account, please cick on the link below:

{reset_url}

This password reset link will expire in 30 minutes.

The link can only be used once.

If you did not request a password reset,
please ignore this email. Your current password
will remain unchanged.

Regards,
SecureCloud Learn
Cloud Computing & Cybersecurity Project
"""

        # ----------------------------------------------------
        # Send password reset email
        # ----------------------------------------------------

        mail.send(
            msg
        )

        print(
            f"SECURITY QUESTION RESET EMAIL SENT TO: "
            f"{user.email}"
        )

    except Exception as e:

        print(
            "SECURITY QUESTION RESET EMAIL ERROR:",
            type(e).__name__,
            str(e)
        )

        # ----------------------------------------------------
        # Clear reset token if email fails
        # ----------------------------------------------------

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        flash(
            "Unable to send the password reset email. "
            "Please try again.",
            "danger"
        )

        return render_template(
            'security_question.html',
            user=user,
            security_questions=security_questions,
            selected_question=selected_question
        )

    # ========================================================
    # CLEAR RECOVERY SESSION
    # ========================================================

    session.pop(
        'recovery_email',
        None
    )

    # ========================================================
    # SUCCESS
    # ========================================================

    flash(

        "A password reset link has been sent to your "
        "registered email address.",
        "success"
    )

    return redirect(
        url_for('auth_bp.login')
    )
# ============================================================
# PASSWORD RESET AFTER SECURITY QUESTION
# ============================================================

@auth_bp.route(
    '/security-reset-password',
    methods=['GET', 'POST']
)
def security_reset_password():

    if not session.get(
        'security_question_verified'
    ):

        flash(
            "Please complete the security verification first.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    email = session.get(
        'recovery_email'
    )

    if not email:

        session.pop(
            'security_question_verified',
            None
        )

        flash(
            "Your recovery session has expired. "
            "Please try again.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        session.pop(
            'recovery_email',
            None
        )

        session.pop(
            'security_question_verified',
            None
        )

        flash(
            "Unable to complete password recovery.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == 'POST':

        password = request.form.get(
            'password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        password_error = validate_password(
            password,
            username=user.username,
            email=user.email
        )

        if password_error:

            flash(
                password_error,
                "danger"
            )

            return render_template(
                'security_reset_password.html',
                user=user
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                'security_reset_password.html',
                user=user
            )

        user.password = (
            generate_password_hash(
                password,
                method=PASSWORD_HASH_METHOD
            )
        )

        user.password_changed_at = datetime.utcnow()

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        session.pop(
            'recovery_email',
            None
        )

        session.pop(
            'security_question_verified',
            None
        )

        flash(
            "Your password has been reset successfully. "
            "You can now log in with your new password.",
            "success"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        'security_reset_password.html',
        user=user
    )


# ============================================================
# EMAIL TOKEN PASSWORD RESET
# ============================================================

@auth_bp.route(
    '/reset-password/<token>',
    methods=['GET', 'POST']
)
def reset_password(token):

    # --------------------------------------------------------
    # Hash token
    # --------------------------------------------------------

    token_hash = (
        hashlib.sha256(
            token.encode('utf-8')
        ).hexdigest()
    )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = User.query.filter_by(
        reset_token=token_hash
    ).first()

    if not user:

        flash(
            "Invalid or expired password reset link.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # Check expiry
    # --------------------------------------------------------

    if (
        not user.reset_token_expiry
        or
        datetime.utcnow()
        >
        user.reset_token_expiry
    ):

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        flash(
            "Invalid or expired password reset link.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == 'POST':

        password = request.form.get(
            'password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        password_error = validate_password(
            password,
            username=user.username,
            email=user.email
        )

        if password_error:

            flash(
                password_error,
                "danger"
            )

            return render_template(
                'reset_password.html',
                user=user
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return render_template(
                'reset_password.html',
                user=user
            )

        # ----------------------------------------------------
        # Prevent reuse of current password
        # ----------------------------------------------------

        if check_password_hash(
            user.password,
            password
        ):

            flash(
                "New password cannot be the same as your current password.",
                "danger"
            )

            return render_template(
                'reset_password.html',
                user=user
            )

        # ----------------------------------------------------
        # Update password
        # ----------------------------------------------------

        user.password = (
            generate_password_hash(
                password,
                method=PASSWORD_HASH_METHOD
            )
        )

        user.password_changed_at = datetime.utcnow()

        # ----------------------------------------------------
        # Unlock account after successful password recovery
        # ----------------------------------------------------

        user.failed_login_attempts = 0

        user.account_locked = False

        # ----------------------------------------------------
        # Invalidate token
        # ----------------------------------------------------

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        # ----------------------------------------------------
        # Clear recovery sessions
        # ----------------------------------------------------

        session.pop(
            'recovery_email',
            None
        )

        session.pop(
            'security_question_verified',
            None
        )

        # ----------------------------------------------------
        # Success
        # ----------------------------------------------------

        flash(
            "Your password has been reset successfully. "
            "You can now log in with your new password.",
            "success"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    return render_template(
        'reset_password.html',
        user=user
    )

# ============================================================
# BIOMETRIC FACE REGISTRATION
# ============================================================

@auth_bp.route(
    '/register-face',
    methods=['POST']
)
@login_required
def register_face():

    # --------------------------------------------------------
    # Get image data from request
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    image_data = data.get(
        'image'
    )

    if not image_data:

        return jsonify({
            'success': False,
            'message': 'No face image was provided.'
        }), 400

    # --------------------------------------------------------
    # Decode image
    # --------------------------------------------------------

    image = decode_base64_image(
        image_data
    )

    if image is None:

        return jsonify({
            'success': False,
            'message': 'Unable to process the image.'
        }), 400

    # --------------------------------------------------------
    # Generate face encoding
    # --------------------------------------------------------

    encoding = get_face_encoding(
        image
    )

    if encoding is None:

        return jsonify({
            'success': False,
            'message': (
                'Please make sure exactly one face '
                'is visible in the image.'
            )
        }), 400

    # --------------------------------------------------------
    # Store face encoding
    # --------------------------------------------------------

    login_user_id = current_user.id

    user = User.query.get(
        login_user_id
    )

    if not user:

        return jsonify({
            'success': False,
            'message': 'User account could not be found.'
        }), 404

    # Convert NumPy encoding into a normal Python list
    encoding_list = encoding.tolist()

    # Store the encoding as a JSON string
    # because SQLite cannot store Python lists directly.
    user.face_encoding = json.dumps(
        encoding_list
    )

    # Enable face authentication
    user.face_enabled = True

    db.session.commit()
    # --------------------------------------------------------
    # Success
    # --------------------------------------------------------

    return jsonify({
        'success': True,
        'message': (
            'Face authentication has been enabled successfully.'
        )
    })

# ============================================================
# DISABLE FACE AUTHENTICATION
# ============================================================

@auth_bp.route(
    '/disable-face',
    methods=['POST']
)
@login_required
def disable_face():

    # --------------------------------------------------------
    # Get logged-in user
    # --------------------------------------------------------

    user = User.query.get(
        current_user.id
    )

    if not user:

        flash(
            "User account could not be found.",
            "danger"
        )

        return redirect(
            url_for('dashboard_bp.face_settings')
        )

    # --------------------------------------------------------
    # Disable face authentication
    # --------------------------------------------------------

    user.face_enabled = False

    # Remove stored face encoding
    user.face_encoding = None

    db.session.commit()

    # --------------------------------------------------------
    # Success message
    # --------------------------------------------------------

    flash(
        "Face authentication has been disabled successfully.",
        "success"
    )

    return redirect(
        url_for('dashboard_bp.face_settings')
    )

# ============================================================
# FACE REGISTRATION PAGE
# ============================================================

@auth_bp.route(
    '/face-register',
    methods=['GET']
)
@login_required
def face_register():

    return render_template(
        'face_register.html'
    )


# ============================================================
# FACE RECOGNITION PASSWORD RECOVERY
# ============================================================

@auth_bp.route(
    '/face-recovery',
    methods=['GET', 'POST']
)
def face_recovery():

    # --------------------------------------------------------
    # Get recovery email from session
    # --------------------------------------------------------

    email = session.get(
        'recovery_email'
    )

    if not email:

        if request.method == 'POST':

            return jsonify({
                "success": False,
                "message": (
                    "Your recovery session has expired. "
                    "Please start the recovery process again."
                )
            }), 401

        flash(
            "Your recovery session has expired. "
            "Please start the recovery process again.",
            "warning"
        )

        return redirect(
            url_for('auth_bp.forgot_password')
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:

        session.pop(
            'recovery_email',
            None
        )

        if request.method == 'POST':

            return jsonify({
                "success": False,
                "message": (
                    "Unable to continue account recovery."
                )
            }), 404

        flash(
            "Unable to continue account recovery.",
            "danger"
        )

        return redirect(
            url_for('auth_bp.login')
        )

    # ========================================================
    # CHECK FACE AUTHENTICATION BEFORE SHOWING CAMERA
    # ========================================================

    if not user.face_enabled:

        return render_template(
            'face_recovery.html',
            user=user,
            face_enabled=False,
            face_error=(
                "Face authentication is not enabled "
                "for your account."
            )
        )

    # ========================================================
    # CHECK REGISTERED FACE ENCODING
    # ========================================================

    if not user.face_encoding:

        return render_template(
            'face_recovery.html',
            user=user,
            face_enabled=False,
            face_error=(
                "No registered face data is available "
                "for your account."
            )
        )

    # ========================================================
    # POST - FACE VERIFICATION
    # ========================================================

    if request.method == 'POST':

        print("========================================")
        print("FACE RECOVERY POST REQUEST RECEIVED")
        print("========================================")

        print(
            "RECOVERY EMAIL:",
            email
        )

        print(
            "USER ID:",
            user.id
        )

        print(
            "USERNAME:",
            user.username
        )

        print(
            "FACE ENABLED:",
            user.face_enabled
        )

        print(
            "FACE ENCODING EXISTS:",
            bool(user.face_encoding)
        )

        # ----------------------------------------------------
        # Get JSON request
        # ----------------------------------------------------

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "message": (
                    "No face verification data was received."
                )
            }), 400

        # ----------------------------------------------------
        # Get captured image
        # ----------------------------------------------------

        image_data = data.get(
            "image"
        )

        if not image_data:

            return jsonify({
                "success": False,
                "message": (
                    "No face image was received."
                )
            }), 400

        print(
            "FACE IMAGE RECEIVED"
        )

        # ====================================================
        # DECODE CAPTURED FACE IMAGE
        # ====================================================

        image = decode_base64_image(
            image_data
        )

        if image is None:

            return jsonify({
                "success": False,
                "face_match": False,
                "message": (
                    "Unable to process the captured face image."
                )
            }), 400


        # ====================================================
        # GENERATE ENCODING FOR CAPTURED FACE
        # ====================================================

        captured_encoding = get_face_encoding(
            image
        )

        if captured_encoding is None:

            return jsonify({
                "success": False,
                "face_match": False,
                "message": (
                    "No clear face was detected. "
                    "Please position your face clearly "
                    "inside the camera frame."
                )
            }), 400

        # ====================================================
        # CONVERT STORED DATABASE ENCODING
        # ====================================================

        # ====================================================
        # CONVERT STORED DATABASE ENCODING
        # ====================================================

        try:

            print(
                "STORED FACE ENCODING TYPE:",
                type(user.face_encoding)
            )

            # ------------------------------------------------
            # Database stores the encoding as a JSON string
            # ------------------------------------------------

            if isinstance(user.face_encoding, str):

                stored_encoding = json.loads(
                    user.face_encoding
                )

            else:

                stored_encoding = user.face_encoding

            # ------------------------------------------------
            # Convert to NumPy array
            # ------------------------------------------------

            stored_encoding = np.asarray(
                stored_encoding,
                dtype=np.float64
            )

            # ------------------------------------------------
            # Make sure encoding is one-dimensional
            # ------------------------------------------------

            stored_encoding = (
                stored_encoding.flatten()
            )

            print(
                "STORED FACE ENCODING LENGTH:",
                len(stored_encoding)
            )

            # ------------------------------------------------
            # A face_recognition encoding contains 128 values
            # ------------------------------------------------

            if stored_encoding.size != 128:
                print(
                    "INVALID STORED FACE ENCODING LENGTH:",
                    stored_encoding.size
                )

                return jsonify({
                    "success": False,
                    "face_match": False,
                    "message": (
                        "Registered face data is invalid. "
                        "Please register your face again."
                    )
                }), 500


        except Exception as e:

            print(
                "STORED FACE ENCODING ERROR:",
                type(e).__name__,
                str(e)
            )

            return jsonify({
                "success": False,
                "face_match": False,
                "message": (
                    "Registered face data could not be processed."
                )
            }), 500
        # ====================================================
        # COMPARE FACES
        # ====================================================

        try:

            face_distance = (
                face_recognition.face_distance(
                    [stored_encoding],
                    captured_encoding
                )[0]
            )

            face_match = (
                face_recognition.compare_faces(
                    [stored_encoding],
                    captured_encoding,
                    tolerance=0.6
                )[0]
            )

            print(
                "FACE DISTANCE:",
                face_distance
            )

            print(
                "FACE MATCH:",
                face_match
            )


        except Exception as e:

            print(
                "FACE COMPARISON ERROR:",
                type(e).__name__,
                str(e)
            )

            return jsonify({
                "success": False,
                "face_match": False,
                "message": (
                    "Unable to compare the captured face "
                    "with the registered face."
                )
            }), 500


        # ====================================================
        # FACE MATCH RESULT
        # ====================================================

        if not face_match:

            return jsonify({
                "success": True,
                "face_match": False,
                "message": (
                    "Face verification failed. "
                    "The captured face does not match "
                    "the registered face."
                )
            })

        # ====================================================
        # FACE MATCH SUCCESS
        # ====================================================

        print(
            "FACE VERIFICATION SUCCESSFUL"
        )

        # ----------------------------------------------------
        # Generate secure password reset token
        # ----------------------------------------------------

        reset_token = secrets.token_urlsafe(
            32
        )

        # ----------------------------------------------------
        # Hash token before storing
        # ----------------------------------------------------

        token_hash = hashlib.sha256(
            reset_token.encode('utf-8')
        ).hexdigest()

        # ----------------------------------------------------
        # Set token expiry
        # ----------------------------------------------------

        expiry_time = (
                datetime.utcnow()
                +
                timedelta(minutes=30)
        )

        # ----------------------------------------------------
        # Store hashed token in database
        # ----------------------------------------------------

        user.reset_token = token_hash

        user.reset_token_expiry = expiry_time

        db.session.commit()

        # ----------------------------------------------------
        # Generate password reset URL
        # ----------------------------------------------------

        reset_url = url_for(
            'auth_bp.reset_password',
            token=reset_token,
            _external=True
        )

        print(
            "FACE RECOVERY RESET URL:",
            reset_url
        )

        # ----------------------------------------------------
        # Return reset URL to browser
        # ----------------------------------------------------

        return jsonify({
            "success": True,
            "face_match": True,
            "message": (
                "Face verification successful."
            ),
            "redirect_url": reset_url
        })

    # ========================================================
    # GET - DISPLAY FACE VERIFICATION PAGE
    # ========================================================

    return render_template(
        'face_recovery.html',
        user=user,
        face_enabled=True,
        face_error=None
    )