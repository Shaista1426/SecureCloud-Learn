from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import User, Course, Quiz, QuizAttempt, Enrollment
from app import db
from app.auth.decorators import role_required
from datetime import datetime
from werkzeug.security import check_password_hash
from app.audit import log_event
from app.utils.smslocal import send_mobile_otp

dashboard_bp = Blueprint('dashboard_bp', __name__, template_folder='../templates/dashboard')

# ------------------------------------------
# INSTRUCTOR DASHBOARD
# ------------------------------------------
@dashboard_bp.route('/instructor/dashboard')
@login_required
@role_required('instructor', 'admin')
def instructor_dashboard():
    # Courses created by instructor
    instructor_courses = Course.query.filter_by(instructor_id=current_user.id).all()

    # Total quizzes in these courses
    course_ids = [c.id for c in instructor_courses]
    quizzes = Quiz.query.filter(Quiz.course_id.in_(course_ids)).all()

    return render_template(
        'dashboard/instructor_dashboard.html',
        courses=instructor_courses,
        quizzes=quizzes
    )


# ------------------------------------------
# ADMIN DASHBOARD
# ------------------------------------------

@dashboard_bp.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():

    # --------------------------------------
    # Statistics
    # --------------------------------------

    total_users = User.query.count()

    total_students = User.query.filter_by(
        role='student'
    ).count()

    total_instructors = User.query.filter_by(
        role='instructor'
    ).count()

    total_courses = Course.query.count()

    return render_template(
        'dashboard/admin_dashboard.html',
        total_users=total_users,
        total_students=total_students,
        total_instructors=total_instructors,
        total_courses=total_courses
    )

# ------------------------------------------
# STUDENT DASHBOARD
# ------------------------------------------
@dashboard_bp.route('/student/dashboard')
@login_required
@role_required('student')
def student_dashboard():
    courses = Course.query.all()

    # List of attempted quiz IDs
    attempted_quiz_ids = [
        attempt.quiz_id for attempt in QuizAttempt.query.filter_by(student_id=current_user.id).all()
    ]

    # Precompute completed status for each course
    completed_status = {
        course.id: course_quizzes_completed(course, current_user)
        for course in courses
    }

    return render_template(
        'dashboard/student_dashboard.html',
        courses=courses,
        attempted_quiz_ids=attempted_quiz_ids,
        completed_status=completed_status
    )
def course_quizzes_completed(course, user):
    total_quizzes = len(course.quizzes)
    if total_quizzes == 0:
        return False

    attempted_quiz_ids = {
        a.quiz_id
        for a in QuizAttempt.query.filter_by(student_id=user.id).all()
    }

    course_quiz_ids = {q.id for q in course.quizzes}

    return course_quiz_ids.issubset(attempted_quiz_ids)

# ------------------------------------------
# SETTINGS
# ------------------------------------------
@dashboard_bp.route('/settings')
@login_required
def settings():

    return render_template(
        'dashboard/settings.html',
        user=current_user
    )


# ------------------------------------------
# MFA SETTINGS
# ------------------------------------------

@dashboard_bp.route('/settings/mfa')
@login_required
def mfa_settings():

    return render_template(
        'dashboard/mfa_settings.html',
        user=current_user
    )


# ------------------------------------------
# FACE AUTHENTICATION SETTINGS
# ------------------------------------------
@dashboard_bp.route('/settings/face')
@login_required
def face_settings():

    return render_template(
        'dashboard/face_settings.html'
    )

# ------------------------------------------
# MOBILE NUMBER & MPIN SETTINGS
# ------------------------------------------

@dashboard_bp.route(
    '/settings/mpin',
    methods=['GET', 'POST']
)
@login_required
def mpin_settings():

    user = current_user

    return render_template(
        'dashboard/mpin_settings.html',
        user=user
    )

    # ========================================================
    # SAVE MOBILE NUMBER
    # ========================================================

    if request.method == 'POST':

        mobile_number = request.form.get(
            'mobile_number',
            ''
        ).strip()

        # ----------------------------------------------------
        # Validate mobile number
        # ----------------------------------------------------

        if (
            not mobile_number
            or
            not mobile_number.isdigit()
            or
            len(mobile_number) != 10
        ):

            flash(
                "Please enter a valid 10-digit mobile number.",
                "danger"
            )

            return render_template(
                'dashboard/mpin_settings.html',
                user=user
            )

        # ----------------------------------------------------
        # Check whether another account already uses it
        # ----------------------------------------------------

        existing_user = User.query.filter(
            User.mobile_number == mobile_number,
            User.id != user.id
        ).first()

        if existing_user:

            flash(
                "This mobile number is already registered "
                "with another account.",
                "danger"
            )

            return render_template(
                'dashboard/mpin_settings.html',
                user=user
            )

        # ----------------------------------------------------
        # Save mobile number
        # ----------------------------------------------------

        user.mobile_number = mobile_number

        # Mobile number must be verified again
        user.mobile_verified = False

        # ----------------------------------------------------
        # MPIN must not remain active when mobile changes
        # ----------------------------------------------------

        user.mpin = None
        user.mpin_changed_at = None

        db.session.commit()

        flash(
            "Mobile number saved. Please verify your mobile "
            "number before setting an MPIN.",
            "success"
        )

        return redirect(
            url_for('dashboard_bp.mpin_settings')
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        'dashboard/mpin_settings.html',
        user=user
    )

# ------------------------------------------
# VERIFY MOBILE NUMBER - SEND OTP
# ------------------------------------------

@dashboard_bp.route(
    '/settings/mpin/mobile',
    methods=['POST']
)
@login_required
def update_mobile_number():

    mobile_number = (
        request.form.get(
            'mobile_number',
            ''
        )
        .strip()
    )

    # ------------------------------------------
    # Validate mobile number
    # ------------------------------------------

    if (
        not mobile_number
        or
        not mobile_number.isdigit()
        or
        len(mobile_number) != 10
    ):

        flash(
            "Please enter a valid 10-digit mobile number.",
            "danger"
        )

        return redirect(
            url_for(
                'dashboard_bp.mpin_settings'
            )
        )

    # ------------------------------------------
    # Check duplicate number
    # ------------------------------------------

    existing_user = User.query.filter(
        User.mobile_number == mobile_number,
        User.id != current_user.id
    ).first()

    if existing_user:

        flash(
            "This mobile number is already registered "
            "with another account.",
            "danger"
        )

        return redirect(
            url_for(
                'dashboard_bp.mpin_settings'
            )
        )

    # ------------------------------------------
    # Save number temporarily
    # ------------------------------------------

    current_user.mobile_number = mobile_number

    # Important:
    # It remains unverified until OTP succeeds.

    current_user.mobile_verified = False

    # Existing MPIN becomes unusable if
    # the mobile number changes.

    current_user.mpin = None
    current_user.mpin_changed_at = None

    db.session.commit()

    # ------------------------------------------
    # Send OTP
    # ------------------------------------------

    try:

        send_mobile_otp(
            mobile_number
        )

    except Exception as e:
        print(
            "SMSLOCAL OTP ERROR:",
            type(e).__name__,
            str(e)
        )

        flash(
            f"SMSLocal error: {str(e)}",
            "danger"
        )

        return redirect(
            url_for('dashboard_bp.mpin_settings')
        )


    # ------------------------------------------
    # Redirect to OTP verification page
    # ------------------------------------------

    return redirect(
        url_for(
            'dashboard_bp.verify_mobile'
        )
    )

# ------------------------------------------
# VERIFY MOBILE NUMBER - OTP
# ------------------------------------------

@dashboard_bp.route(
    '/settings/mpin/mobile/verify',
    methods=['GET', 'POST']
)
@login_required
def verify_mobile():

    user = current_user

    # ------------------------------------------
    # Mobile number must exist
    # ------------------------------------------

    if not user.mobile_number:

        flash(
            "Please enter your mobile number first.",
            "warning"
        )

        return redirect(
            url_for(
                'dashboard_bp.mpin_settings'
            )
        )

    # ------------------------------------------
    # POST - VERIFY OTP
    # ------------------------------------------

    if request.method == 'POST':

        otp = (
            request.form.get(
                'otp',
                ''
            )
            .strip()
        )

        # --------------------------------------
        # Validate OTP format
        # --------------------------------------

        if (
            not otp
            or
            not otp.isdigit()
            or
            len(otp) != 6
        ):

            flash(
                "Please enter the 6-digit verification code.",
                "danger"
            )

            return render_template(
                'dashboard/verify_mobile.html',
                user=user
            )

        # --------------------------------------
        # Verify through SMSLocal
        # --------------------------------------

        try:

            result = verify_mobile_otp(
                user.mobile_number,
                otp
            )

        except Exception:

            flash(
                "Unable to verify the code. "
                "Please try again.",
                "danger"
            )

            return render_template(
                'dashboard/verify_mobile.html',
                user=user
            )

        # --------------------------------------
        # Check SMSLocal result
        # --------------------------------------

        verified = (
            result.get('verified') is True
            or
            result.get('success') is True
            or
            result.get('status') == 'verified'
        )

        if not verified:

            flash(
                "Invalid or expired verification code.",
                "danger"
            )

            return render_template(
                'dashboard/verify_mobile.html',
                user=user
            )

        # --------------------------------------
        # Mark mobile as verified
        # --------------------------------------

        user.mobile_verified = True

        db.session.commit()

        # --------------------------------------
        # Audit event
        # --------------------------------------

        log_event(
            user=user,
            event_type='MOBILE_VERIFIED',
            description='User verified their mobile number using OTP.',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # --------------------------------------
        # Success
        # --------------------------------------

        flash(
            "Mobile number verified successfully.",
            "success"
        )

        return redirect(
            url_for(
                'dashboard_bp.mpin_settings'
            )
        )

    # ------------------------------------------
    # GET
    # ------------------------------------------

    return render_template(
        'dashboard/verify_mobile.html',
        user=user
    )

# ------------------------------------------
# SET / CHANGE MPIN
# ------------------------------------------

@dashboard_bp.route(
    '/settings/mpin/set',
    methods=['GET', 'POST']
)
@login_required
def set_mpin():

    user = current_user
    had_mpin = bool(user.mpin)

    # ========================================================
    # MOBILE NUMBER VERIFICATION REQUIRED
    # ========================================================

    if (
        not user.mobile_number
        or
        not user.mobile_verified
    ):

        flash(
            "Please add and verify your mobile number "
            "before setting an MPIN.",
            "warning"
        )

        return redirect(
            url_for(
                'dashboard_bp.mpin_settings'
            )
        )

    # ========================================================
    # POST
    # ========================================================

    if request.method == 'POST':

        mpin = request.form.get(
            'mpin',
            ''
        ).strip()

        confirm_mpin = request.form.get(
            'confirm_mpin',
            ''
        ).strip()

        # ----------------------------------------------------
        # MPIN validation
        # ----------------------------------------------------

        if (
            not mpin
            or
            not mpin.isdigit()
            or
            len(mpin) != 6
        ):

            flash(
                "MPIN must contain exactly 6 digits.",
                "danger"
            )

            return render_template(
                'dashboard/set_mpin.html',
                user=user
            )

        # ----------------------------------------------------
        # Confirm MPIN
        # ----------------------------------------------------

        if mpin != confirm_mpin:

            flash(
                "MPINs do not match.",
                "danger"
            )

            return render_template(
                'dashboard/set_mpin.html',
                user=user
            )

        # ----------------------------------------------------
        # Prevent reuse of current MPIN
        # ----------------------------------------------------

        if user.mpin:

            if check_password_hash(
                user.mpin,
                mpin
            ):

                flash(
                    "New MPIN must be different from "
                    "your previous MPIN.",
                    "danger"
                )

                return render_template(
                    'dashboard/set_mpin.html',
                    user=user
                )

        # ====================================================
        # SAVE MPIN
        # ====================================================

        user.mpin = generate_password_hash(
            mpin,
            method=PASSWORD_HASH_METHOD
        )

        user.mpin_changed_at = datetime.utcnow()

        db.session.commit()

        # ----------------------------------------------------
        # Audit event
        # ----------------------------------------------------

        log_event(
            user=user,
            event_type='MPIN_CHANGED',
            description='User set or changed their mobile MPIN.',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Success
        # ----------------------------------------------------

        flash(
            "Your MPIN has been "
            + (
                "changed"
                if had_mpin
                else "set"
            )
            + " successfully.",
            "success"
        )

        return redirect(
            url_for(
                'dashboard_bp.mpin_settings'
            )
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        'dashboard/set_mpin.html',
        user=user
    )

# ------------------------------------------
# DISABLE FACE AUTHENTICATION
# ------------------------------------------
@dashboard_bp.route('/settings/disable-face', methods=['POST'])
@login_required
def disable_face():

    # Disable face authentication
    current_user.face_enabled = False

    # Remove the stored face encoding
    current_user.face_encoding = None

    db.session.commit()

    flash(
        "Face authentication has been disabled successfully.",
        "success"
    )

    return redirect(
        url_for('dashboard_bp.settings')
    )

# ============================================================
# ADMIN AUDIT LOGS
# ============================================================

@dashboard_bp.route('/admin/audit-logs')
@login_required
@role_required('admin')
def audit_logs():

    from app.models import AuditLog

    # --------------------------------------------------------
    # Get filter values
    # --------------------------------------------------------

    audit_id = request.args.get(
        'audit_id',
        ''
    ).strip()

    username = request.args.get(
        'username',
        ''
    ).strip()

    event_type = request.args.get(
        'event_type',
        ''
    ).strip()

    log_date = request.args.get(
        'log_date',
        ''
    ).strip()

    # --------------------------------------------------------
    # Start query
    # --------------------------------------------------------

    query = AuditLog.query.join(
        AuditLog.user,
        isouter=True
    )

    # --------------------------------------------------------
    # Audit ID filter
    # --------------------------------------------------------

    if audit_id:

        audit_search = audit_id.upper().replace(
            'AUD-',
            ''
        )

        if audit_search.isdigit():

            query = query.filter(
                AuditLog.id == int(audit_search)
            )

        else:

            # Invalid Audit ID format
            query = query.filter(
                db.false()
            )

    # --------------------------------------------------------
    # Username filter
    # --------------------------------------------------------

    if username:

        query = query.filter(
            User.username.ilike(
                f'%{username}%'
            )
        )

    # --------------------------------------------------------
    # Event type filter
    # --------------------------------------------------------

    if event_type:

        query = query.filter(
            AuditLog.event_type.ilike(
                f'%{event_type}%'
            )
        )

    # --------------------------------------------------------
    # Date filter
    # --------------------------------------------------------

    if log_date:

        try:

            selected_date = datetime.strptime(
                log_date,
                '%Y-%m-%d'
            ).date()

            query = query.filter(
                db.func.date(
                    AuditLog.created_at
                ) == selected_date
            )

        except ValueError:

            pass

    # --------------------------------------------------------
    # Get final logs
    # --------------------------------------------------------

    logs = query.order_by(
        AuditLog.id.desc()
    ).all()

    # --------------------------------------------------------
    # Display audit logs
    # --------------------------------------------------------

    return render_template(
        'dashboard/audit_logs.html',
        logs=logs,
        audit_id=audit_id,
        username=username,
        event_type=event_type,
        log_date=log_date
    )

# ============================================================
# USER SECURITY ACTIVITY
# ============================================================

@dashboard_bp.route('/security-activity')
@login_required
def security_activity():

    from app.models import AuditLog

    # --------------------------------------------------------
    # Get filter values
    # --------------------------------------------------------

    audit_id = request.args.get(
        'audit_id',
        ''
    ).strip()

    event_type = request.args.get(
        'event_type',
        ''
    ).strip()

    from_date = request.args.get(
        'from_date',
        ''
    ).strip()

    to_date = request.args.get(
        'to_date',
        ''
    ).strip()

    # --------------------------------------------------------
    # Start query
    # --------------------------------------------------------

    query = AuditLog.query.filter(
        AuditLog.user_id == current_user.id
    )

    # --------------------------------------------------------
    # Audit ID filter
    # --------------------------------------------------------

    if audit_id:

        audit_search = audit_id.upper().replace(
            'AUD-',
            ''
        )

        if audit_search.isdigit():

            query = query.filter(
                AuditLog.id == int(audit_search)
            )

        else:

            query = query.filter(
                db.false()
            )

    # --------------------------------------------------------
    # Event type filter
    # --------------------------------------------------------

    if event_type:

        query = query.filter(
            AuditLog.event_type.ilike(
                f'%{event_type}%'
            )
        )

    # --------------------------------------------------------
    # From date filter
    # --------------------------------------------------------

    if from_date:

        try:

            selected_from_date = datetime.strptime(
                from_date,
                '%Y-%m-%d'
            ).date()

            query = query.filter(
                db.func.date(
                    AuditLog.created_at
                ) >= selected_from_date
            )

        except ValueError:

            pass

    # --------------------------------------------------------
    # To date filter
    # --------------------------------------------------------

    if to_date:

        try:

            selected_to_date = datetime.strptime(
                to_date,
                '%Y-%m-%d'
            ).date()

            query = query.filter(
                db.func.date(
                    AuditLog.created_at
                ) <= selected_to_date
            )

        except ValueError:

            pass

    # --------------------------------------------------------
    # Get final logs
    # --------------------------------------------------------

    logs = query.order_by(
        AuditLog.id.desc()
    ).all()

    # --------------------------------------------------------
    # Display security activity
    # --------------------------------------------------------

    return render_template(
        'dashboard/security_activity.html',
        logs=logs,
        audit_id=audit_id,
        event_type=event_type,
        from_date=from_date,
        to_date=to_date
    )


# ============================================================
# REPORT SUSPICIOUS ACTIVITY
# ============================================================

@dashboard_bp.route(
    '/report-suspicious-activity/<int:audit_log_id>',
    methods=['GET']
)
@login_required
def report_suspicious_activity(audit_log_id):

    from app.models import AuditLog

    # --------------------------------------------------------
    # Find the audit log
    # --------------------------------------------------------

    audit_log = AuditLog.query.get_or_404(
        audit_log_id
    )

    # --------------------------------------------------------
    # Security check
    # --------------------------------------------------------
    # A user should only be able to report an activity
    # belonging to their own account.

    if audit_log.user_id != current_user.id:

        flash(
            "You are not authorized to report this activity.",
            "danger"
        )

        return redirect(
            url_for('main_bp.home')
        )

    # --------------------------------------------------------
    # Display report page
    # --------------------------------------------------------

    return render_template(
        'dashboard/report_suspicious_activity.html',
        audit_log=audit_log
    )

# ============================================================
# SECURITY REPORT AUTHENTICATION SELECTION
# ============================================================

@dashboard_bp.route(
    '/security-report-auth/<int:audit_log_id>',
    methods=['GET']
)
@login_required
def security_report_auth(audit_log_id):

    from app.models import AuditLog

    # --------------------------------------------------------
    # Find the audit log
    # --------------------------------------------------------

    audit_log = AuditLog.query.get_or_404(
        audit_log_id
    )

    # --------------------------------------------------------
    # Security check
    # --------------------------------------------------------
    # User can only report activity belonging to
    # their own account.

    if audit_log.user_id != current_user.id:

        flash(
            "You are not authorized to report this activity.",
            "danger"
        )

        return redirect(
            url_for('main_bp.home')
        )

    # --------------------------------------------------------
    # Check available authentication methods
    # --------------------------------------------------------

    face_available = (
        current_user.face_enabled
        and current_user.face_encoding
    )

    pin_available = bool(
        current_user.pin
    )

    # --------------------------------------------------------
    # Display authentication selection page
    # --------------------------------------------------------

    return render_template(
        'dashboard/security_report_auth.html',
        audit_log=audit_log,
        face_available=face_available,
        pin_available=pin_available
    )

# ============================================================
# SECURITY REPORT - MPIN AUTHENTICATION
# ============================================================

@dashboard_bp.route(
    '/security-report-pin-auth/<int:audit_log_id>',
    methods=['GET', 'POST']
)
@login_required
def security_report_pin_auth(audit_log_id):

    from app.models import AuditLog

    # --------------------------------------------------------
    # Find the audit log
    # --------------------------------------------------------

    audit_log = AuditLog.query.get_or_404(
        audit_log_id
    )

    # --------------------------------------------------------
    # Security check
    # --------------------------------------------------------
    # User can only report activity belonging to
    # their own account.

    if audit_log.user_id != current_user.id:

        flash(
            "You are not authorized to report this activity.",
            "danger"
        )

        return redirect(
            url_for('main_bp.home')
        )

    # --------------------------------------------------------
    # Make sure user has an mPIN
    # --------------------------------------------------------

    if not current_user.pin:

        flash(
            "mPIN authentication is not available for your account.",
            "warning"
        )

        return redirect(
            url_for(
                'dashboard_bp.security_report_auth',
                audit_log_id=audit_log.id
            )
        )

    # ========================================================
    # POST - VERIFY mPIN
    # ========================================================

    if request.method == 'POST':

        entered_pin = (
            request.form.get(
                'pin',
                ''
            )
            .strip()
        )

        # ----------------------------------------------------
        # Validate PIN input
        # ----------------------------------------------------

        if not entered_pin:

            flash(
                "Please enter your mPIN.",
                "danger"
            )

            return render_template(
                'dashboard/security_report_pin_auth.html',
                audit_log=audit_log
            )

        # ----------------------------------------------------
        # Verify hashed PIN
        # ----------------------------------------------------

        if not check_password_hash(
            current_user.pin,
            entered_pin
        ):

            log_event(
                user=current_user,
                event_type='SECURITY_REPORT_AUTH_FAILED',
                description=(
                    'Security report authentication failed: '
                    'incorrect mPIN.'
                ),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

            flash(
                "Incorrect mPIN. Please try again.",
                "danger"
            )

            return render_template(
                'dashboard/security_report_pin_auth.html',
                audit_log=audit_log
            )

        # ====================================================
        # mPIN VERIFIED
        # ====================================================

        log_event(
            user=current_user,
            event_type='SECURITY_REPORT_AUTH_SUCCESS',
            description=(
                'Security report authentication completed '
                'successfully using mPIN.'
            ),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Store authenticated report information temporarily
        # ----------------------------------------------------

        session['security_report_authenticated'] = True
        session['security_report_audit_log_id'] = audit_log.id

        # ----------------------------------------------------
        # Continue to report form
        # ----------------------------------------------------

        return redirect(
            url_for(
                'dashboard_bp.submit_security_report',
                audit_log_id=audit_log.id
            )
        )

    # ========================================================
    # GET
    # ========================================================

    return render_template(
        'dashboard/security_report_pin_auth.html',
        audit_log=audit_log
    )

# ============================================================
# SECURITY REPORT - SUBMIT REPORT
# ============================================================

@dashboard_bp.route(
    '/submit-security-report/<int:audit_log_id>',
    methods=['GET', 'POST']
)
@login_required
def submit_security_report(audit_log_id):

    from app.models import AuditLog, SecurityReport

    # --------------------------------------------------------
    # Find the audit log
    # --------------------------------------------------------

    audit_log = AuditLog.query.get_or_404(
        audit_log_id
    )

    # --------------------------------------------------------
    # Security check
    # --------------------------------------------------------
    # User can only report activity belonging to
    # their own account.

    if audit_log.user_id != current_user.id:

        flash(
            "You are not authorized to report this activity.",
            "danger"
        )

        return redirect(
            url_for('main_bp.home')
        )

    # --------------------------------------------------------
    # Verify that mPIN authentication was completed
    # for THIS specific audit log.
    # --------------------------------------------------------

    if not session.get(
        'security_report_authenticated'
    ):

        flash(
            "Please authenticate yourself before "
            "submitting the security report.",
            "warning"
        )

        return redirect(
            url_for(
                'dashboard_bp.security_report_auth',
                audit_log_id=audit_log.id
            )
        )

    if session.get(
        'security_report_audit_log_id'
    ) != audit_log.id:

        flash(
            "Security report authentication is not valid "
            "for this activity.",
            "danger"
        )

        session.pop(
            'security_report_authenticated',
            None
        )

        session.pop(
            'security_report_audit_log_id',
            None
        )

        return redirect(
            url_for(
                'dashboard_bp.security_report_auth',
                audit_log_id=audit_log.id
            )
        )

    # ========================================================
    # POST - SUBMIT SECURITY REPORT
    # ========================================================

    if request.method == 'POST':

        reason = (
            request.form.get(
                'reason',
                ''
            )
            .strip()
        )

        # ----------------------------------------------------
        # Validate report reason
        # ----------------------------------------------------

        if not reason:

            flash(
                "Please provide a reason for reporting "
                "this activity.",
                "danger"
            )

            return render_template(
                'dashboard/submit_security_report.html',
                audit_log=audit_log
            )

        # ----------------------------------------------------
        # Create security report
        # ----------------------------------------------------

        security_report = SecurityReport(
            user_id=current_user.id,
            audit_log_id=audit_log.id,
            reason=reason,
            ip_address=request.remote_addr,
            status='Open'
        )

        db.session.add(
            security_report
        )

        db.session.commit()

        # ----------------------------------------------------
        # Log security report submission
        # ----------------------------------------------------

        log_event(
            user=current_user,
            event_type='SECURITY_REPORT_SUBMITTED',
            description=(
                f'Security report submitted for '
                f'Audit ID AUD-{audit_log.id:06d}.'
            ),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # ----------------------------------------------------
        # Clear authentication session
        # ----------------------------------------------------
        # mPIN authentication is one-time for this report.

        session.pop(
            'security_report_authenticated',
            None
        )

        session.pop(
            'security_report_audit_log_id',
            None
        )

        # ----------------------------------------------------
        # Success message
        # ----------------------------------------------------

        flash(
            "Your security report has been submitted successfully.",
            "success"
        )

        return redirect(
            url_for(
                'dashboard_bp.security_report_success',
                report_id=security_report.id
            )
        )

    # ========================================================
    # GET - DISPLAY REPORT FORM
    # ========================================================

    return render_template(
        'dashboard/submit_security_report.html',
        audit_log=audit_log
    )

# ============================================================
# SECURITY REPORT - SUCCESS
# ============================================================

@dashboard_bp.route(
    '/security-report-success/<int:report_id>',
    methods=['GET']
)
@login_required
def security_report_success(report_id):

    from app.models import SecurityReport

    # --------------------------------------------------------
    # Find the security report
    # --------------------------------------------------------

    security_report = SecurityReport.query.get_or_404(
        report_id
    )

    # --------------------------------------------------------
    # Security check
    # --------------------------------------------------------
    # User can only view the success page for
    # their own security report.

    if security_report.user_id != current_user.id:

        flash(
            "You are not authorized to view this security report.",
            "danger"
        )

        return redirect(
            url_for('main_bp.home')
        )

    # --------------------------------------------------------
    # Display success page
    # --------------------------------------------------------

    return render_template(
        'dashboard/security_report_success.html',
        security_report=security_report
    )