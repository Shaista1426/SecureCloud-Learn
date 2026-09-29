from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app import db
from app.models import Course, Quiz

instructor_bp = Blueprint('instructor', __name__, url_prefix='/instructor')


# -------------------------
# CREATE COURSE
# -------------------------
@instructor_bp.route('/create-course', methods=['GET', 'POST'])
@login_required
def create_course():
    if request.method == 'POST':
        title = request.form.get('title')
        if not title:
            flash("Course title is required", "danger")
            return redirect(url_for('instructor.create_course'))
        new_course = Course(title=title, instructor_id=current_user.id)
        db.session.add(new_course)
        db.session.commit()
        flash("Course created successfully!", "success")
        return redirect(url_for('instructor.view_courses'))
    return render_template('instructor/create_course.html')


# -------------------------
# VIEW ALL COURSES
# -------------------------
@instructor_bp.route('/courses')
@login_required
def view_courses():
    courses = Course.query.filter_by(instructor_id=current_user.id).all()
    return render_template('instructor/view_course.html', courses=courses)



# -------------------------
# ADD QUIZ TO COURSE
# -------------------------
@instructor_bp.route('/<int:course_id>/add-quiz', methods=['GET', 'POST'])
@login_required
def add_quiz(course_id):
    course = Course.query.get_or_404(course_id)
    if course.instructor_id != current_user.id:
        flash("Unauthorized access", "danger")
        return redirect(url_for('course_bp.view_course'))

    if request.method == 'POST':
        title = request.form.get('title')
        if not title:
            flash("Quiz title is required", "danger")
            return redirect(url_for('instructor.add_quiz', course_id=course.id))
        new_quiz = Quiz(title=title, course_id=course.id)
        db.session.add(new_quiz)
        db.session.commit()
        flash("Quiz created successfully! Now add questions.", "success")
        return redirect(url_for('quiz_bp.add_question', quiz_id=new_quiz.id))
    return render_template('instructor/add_quiz.html', course=course)