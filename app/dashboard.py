from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

from app.models import Course, Quiz, Enrollment

dashboard_bp = Blueprint(
    "dashboard_bp",
    __name__,
    template_folder="templates",
    url_prefix=""
)

# ----------------------------------------
# INSTRUCTOR DASHBOARD
# ----------------------------------------
@dashboard_bp.route('/instructor/dashboard')
@login_required
def instructor_dashboard():

    # Only instructors are allowed
    if current_user.role != "instructor":
        return redirect(
            url_for("main_bp.home")
        )

    # Fetch courses created by the
    # currently logged-in instructor
    courses = Course.query.filter_by(
        instructor_id=current_user.id
    ).all()

    # Attach quiz count for each course
    course_info = []

    for course in courses:

        quizzes = Quiz.query.filter_by(
            course_id=course.id
        ).all()

        course_info.append({
            "course": course,
            "quiz_count": len(quizzes)
        })

    return render_template(
        'instructor/dashboard.html',
        course_info=course_info
    )
# ----------------------------------------
# STUDENT DASHBOARD
# ----------------------------------------
@dashboard_bp.route("/student/dashboard")
@login_required
def student_dashboard():
    if current_user.role != "student":
        return redirect(url_for("main_bp.home"))

    # Fetch routes student is enrolled in
    enrollments = Enrollment.query.filter_by(student_id=current_user.id).all()

    return render_template("student_dashboard.html", enrollments=enrollments)
