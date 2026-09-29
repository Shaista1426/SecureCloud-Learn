# app/routes/student.py
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app import db
from app.models import Course, Enrollment, Quiz, QuizAttempt, Certificate, QuizQuestion
import json

student_bp = Blueprint('student', __name__, template_folder='../templates')

@student_bp.route('/dashboard')
@login_required
def student_dashboard():
    # all published courses
    all_courses = Course.query.filter_by(is_published=True).all()

    # enrolled course ids via Enrollment model
    enrolled_objs = Enrollment.query.filter_by(student_id=current_user.id).all()
    enrolled_course_ids = [e.course_id for e in enrolled_objs]

    # Available courses (published and not enrolled)
    available_courses = [c for c in all_courses if c.id not in enrolled_course_ids]

    # Enrolled courses detail
    enrolled_courses = []
    if enrolled_course_ids:
        enrolled_course_objs = Course.query.filter(Course.id.in_(enrolled_course_ids)).all()
    else:
        enrolled_course_objs = []

    for course in enrolled_course_objs:
        quizzes = Quiz.query.filter_by(course_id=course.id).all()
        quiz_list = []
        for q in quizzes:
            attempted = QuizAttempt.query.filter_by(quiz_id=q.id, student_id=current_user.id).first()
            quiz_list.append({
                "id": q.id,
                "title": q.title,
                "attempted": bool(attempted)
            })

        certificate = Certificate.query.filter_by(student_id=current_user.id, course_id=course.id).first()
        completed = bool(certificate)
        progress = int(sum(1 for q in quiz_list if q["attempted"]) / len(quiz_list) * 100) if quiz_list else 0

        enrolled_courses.append({
            "id": course.id,
            "title": course.title,
            "instructor": course.instructor,
            "quizzes": quiz_list,
            "completed": completed,
            "progress": progress
        })

    return render_template(
        'student_dashboard.html',
        available_courses=available_courses,
        enrolled_courses=enrolled_courses
    )

@student_bp.route('/enroll/<int:course_id>')
@login_required
def enroll_course(course_id):
    existing = Enrollment.query.filter_by(student_id=current_user.id, course_id=course_id).first()
    if not existing:
        enrollment = Enrollment(student_id=current_user.id, course_id=course_id)
        db.session.add(enrollment)
        db.session.commit()
    return redirect(url_for('student.student_dashboard'))

@student_bp.route('/complete/<int:course_id>')
@login_required
def complete_course(course_id):
    certificate = Certificate.query.filter_by(student_id=current_user.id, course_id=course_id).first()
    if not certificate:
        certificate = Certificate(student_id=current_user.id, course_id=course_id)
        db.session.add(certificate)
        db.session.commit()
    return redirect(url_for('student.student_dashboard'))

@student_bp.route('/attempt/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    # Only allow students who are enrolled in the course
    enrolled = Enrollment.query.filter_by(student_id=current_user.id, course_id=quiz.course_id).first()
    if not enrolled:
        flash("You must enroll in the course to take this quiz.", "danger")
        return redirect(url_for('student.student_dashboard'))

    # If already attempted, redirect to result
    existing = QuizAttempt.query.filter_by(quiz_id=quiz_id, student_id=current_user.id).first()
    if existing:
        return redirect(url_for('student.view_quiz_result', quiz_id=quiz_id))

    return render_template('attempt_quiz.html', quiz=quiz)

@student_bp.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    # collect answers from form: q{question.id} => '1'..'4'
    answers = {}
    score = 0
    for question in quiz.questions:
        selected = request.form.get(f"q{question.id}")
        if selected:
            try:
                sel_int = int(selected)
            except ValueError:
                sel_int = None
        else:
            sel_int = None
        answers[str(question.id)] = sel_int
        if sel_int and question.correct_option == sel_int:
            score += 1

    attempt = QuizAttempt.query.filter_by(quiz_id=quiz_id, student_id=current_user.id).first()
    if attempt:
        attempt.score = score
        attempt.answers = json.dumps(answers)
    else:
        attempt = QuizAttempt(student_id=current_user.id, quiz_id=quiz_id, score=score, answers=json.dumps(answers))
        db.session.add(attempt)
    db.session.commit()

    flash(f'Quiz submitted! Your score: {score}/{len(quiz.questions)}', 'success')
    return redirect(url_for('student.view_quiz_result', quiz_id=quiz_id))

@student_bp.route('/view_quiz_result/<int:quiz_id>')
@login_required
def view_quiz_result(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    attempt = QuizAttempt.query.filter_by(quiz_id=quiz_id, student_id=current_user.id).first()
    if not attempt:
        return redirect(url_for('student.take_quiz', quiz_id=quiz_id))

    # parse answers
    answers = {}
    if attempt.answers:
        try:
            answers = json.loads(attempt.answers)
        except Exception:
            answers = {}

    return render_template('view_quiz_result.html', quiz=quiz, attempt=attempt, answers=answers)

@student_bp.route('/download_certificate_pdf/<int:course_id>')
@login_required
def download_certificate_pdf(course_id):
    certificate = Certificate.query.filter_by(student_id=current_user.id, course_id=course_id).first()
    if not certificate:
        return redirect(url_for('student.student_dashboard'))

    rendered = render_template('certificate.html', certificate=certificate, student=current_user)
    # NOTE: pdfkit must be configured on your system. Keep existing approach.
    import pdfkit
    from flask import make_response
    pdf = pdfkit.from_string(rendered, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Certificate_{certificate.course.title}.pdf'
    return response
