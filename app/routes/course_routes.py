# app/routes/course_routes.py

import os
from flask import current_app
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import Course, QuizAttempt, Enrollment
from app import allowed_file
from datetime import datetime

course_bp = Blueprint('course_bp', __name__, template_folder='../templates')

# ===============================
# IMAGE UPLOAD CONFIG
# ===============================

UPLOAD_FOLDER = "app/static/images"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )



# ---------------------------
# LIST ALL PUBLISHED COURSES
# ---------------------------
@course_bp.route('/all')
def all_courses():
    courses = Course.query.filter_by(is_published=True).all()
    return render_template('courses/all_courses.html', courses=courses)


# ---------------------------
# CREATE COURSE (INSTRUCTOR)
# ---------------------------
@course_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_course():

    if current_user.role != 'instructor':
        flash("Unauthorized", "danger")
        return redirect(url_for('main_bp.home'))

    if request.method == 'POST':

        title = request.form.get('title')
        description = request.form.get('description')
        content = request.form.get('content')

        image = request.files.get('image')
        filename = None

        if image and image.filename != "" and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(
                current_app.config["UPLOAD_FOLDER"], filename
            ))

        new_course = Course(
            title=title,
            description=description,
            content=content,
            image_filename=filename,
            instructor_id=current_user.id
        )

        db.session.add(new_course)
        db.session.commit()

        flash("Course created successfully!", "success")
        return redirect(url_for('course_bp.view_course', course_id=new_course.id))

    return render_template("courses/create_course.html")


# -----------------------------------------------------------
# SINGLE UNIFIED VIEW COURSE (USED BY BOTH: STUDENT + ADMIN)
# -----------------------------------------------------------
@course_bp.route('/<int:course_id>')
@login_required
def view_course(course_id):

    course = Course.query.get_or_404(course_id)

    # quizzes inside the course
    quizzes = course.quizzes if hasattr(course, 'quizzes') else []

    # quizzes attempted by current student
    attempted = set()
    if current_user.is_authenticated and current_user.role == "student":
        attempted = {a.quiz_id for a in QuizAttempt.query.filter_by(student_id=current_user.id).all()}

    return render_template(
        'courses/view_course.html',
        course=course,
        quizzes=quizzes,
        attempted_quiz_ids=attempted
    )


# ---------------------------
# EDIT COURSE (INSTRUCTOR)
# ---------------------------
@course_bp.route("/<int:course_id>/edit", methods=["GET", "POST"])
@login_required
def edit_course(course_id):

    course = Course.query.get_or_404(course_id)

    if course.instructor_id != current_user.id:
        flash("Unauthorized!", "danger")
        return redirect(url_for("course_bp.view_course", course_id=course.id))

    if request.method == "POST":
        course.title = request.form.get("title")
        course.description = request.form.get("description")
        course.content = request.form.get("content")

        image = request.files.get("image")
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(UPLOAD_FOLDER, filename))
            course.image_url = filename

        db.session.commit()
        flash("Course updated successfully!", "success")
        return redirect(url_for("course_bp.view_course", course_id=course.id))

    return render_template("courses/edit_course.html", course=course)


# ---------------------------
# DELETE COURSE
# ---------------------------
@course_bp.route('/<int:course_id>/delete', methods=['POST'])
@login_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)

    if course.instructor_id != current_user.id:
        flash("Unauthorized!", "danger")
        return redirect(url_for('course_bp.view_course', course_id=course_id))

    db.session.delete(course)
    db.session.commit()

    flash("Course deleted successfully!", "success")
    return redirect(url_for('dashboard_bp.instructor_dashboard'))


# ---------------------------
# PUBLISH COURSE
# ---------------------------
@course_bp.route('/<int:course_id>/publish', methods=['POST'])
@login_required
def publish_course(course_id):
    course = Course.query.get_or_404(course_id)

    if course.instructor_id != current_user.id:
        flash("Unauthorized!", "danger")
        return redirect(url_for('course_bp.view_course', course_id=course_id))

    course.is_published = True
    db.session.commit()

    flash("Course published successfully!", "success")
    return redirect(url_for('course_bp.view_course', course_id=course_id))


# ---------------------------
# ENROLL COURSE (STUDENT)
# ---------------------------
@course_bp.route('/<int:course_id>/enroll', methods=['POST'])
@login_required
def enroll_course(course_id):
    course = Course.query.get_or_404(course_id)

    if current_user.role != "student":
        flash("Only students can enroll!", "danger")
        return redirect(url_for('course_bp.view_course', course_id=course_id))

    existing = Enrollment.query.filter_by(
        course_id=course_id,
        student_id=current_user.id
    ).first()

    if existing:
        flash("Already enrolled!", "info")
        return redirect(url_for('dashboard_bp.student_dashboard'))

    enroll = Enrollment(course_id=course_id, student_id=current_user.id)
    db.session.add(enroll)
    db.session.commit()

    flash("Enrolled successfully!", "success")
    return redirect(url_for('dashboard_bp.student_dashboard'))


# ---------------------------
# COMPLETION CERTIFICATE
# ---------------------------
@course_bp.route('/courses/<int:course_id>/certificate')
@login_required
def certificate(course_id):

    course = Course.query.get_or_404(course_id)

    # ---------------------------
    # 1️⃣ Get course quizzes
    # ---------------------------
    quizzes = course.quizzes or []

    quiz_ids = {quiz.id for quiz in quizzes}

    # ---------------------------
    # 2️⃣ Get passed quizzes
    # ---------------------------
    passed_quiz_ids = {
        a.quiz_id
        for a in QuizAttempt.query.filter_by(
            student_id=current_user.id,
            status="PASS"
        ).all()
    }

    # ---------------------------
    # 3️⃣ Eligibility check
    # ---------------------------
    if not quiz_ids.issubset(passed_quiz_ids):
        eligible = False
    else:
        eligible = True

    # ---------------------------
    # 4️⃣ Safety re-check per quiz
    # ---------------------------
    for quiz in quizzes:
        attempt = QuizAttempt.query.filter_by(
            student_id=current_user.id,
            quiz_id=quiz.id
        ).order_by(QuizAttempt.attempted_on.desc()).first()

        if not attempt or attempt.status != "PASS":
            flash(
                "Complete and pass all quizzes to unlock certificate.",
                "danger"
            )
            return redirect(
                url_for('dashboard.student_dashboard')
            )

    # ---------------------------
    # 5️⃣ Render certificate
    # ---------------------------
    return render_template(
        'certificates/completion_certificate.html',
        course=course,
        issued_date=datetime.utcnow(),
        eligible=eligible,
        student_name=current_user.username
    )
