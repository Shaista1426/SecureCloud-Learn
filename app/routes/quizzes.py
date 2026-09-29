from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app import db
from app.models import Course, Quiz, QuizQuestion, QuizAttempt
from datetime import datetime

quiz_bp = Blueprint("quiz_bp", __name__, template_folder="../templates/quiz")


# ---------------------------------------------------
# CREATE QUIZ (Instructor Only)
# ---------------------------------------------------
@quiz_bp.route('/create/<int:course_id>', methods=['GET', 'POST'])
@login_required
def create_quiz(course_id):
    course = Course.query.get_or_404(course_id)

    if current_user.id != course.instructor_id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('course_bp.view_course', course_id=course.id))

    if request.method == "POST":
        title = request.form.get("title")

        new_quiz = Quiz(title=title, course_id=course.id)
        db.session.add(new_quiz)
        db.session.commit()

        flash("Quiz created. Now add questions.", "success")
        return redirect(url_for("quiz_bp.add_question", quiz_id=new_quiz.id))

    return render_template("quiz/create_quiz.html", course=course)


# ---------------------------------------------------
# ADD **MULTIPLE** MCQs AT ONCE  (Your Original Feature)
# ---------------------------------------------------
@quiz_bp.route('/<int:quiz_id>/add-questions', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    if request.method == "POST":
        questions = request.form.getlist("question[]")
        option1_list = request.form.getlist("option1[]")
        option2_list = request.form.getlist("option2[]")
        option3_list = request.form.getlist("option3[]")
        option4_list = request.form.getlist("option4[]")
        correct_options = request.form.getlist("correct_option[]")

        total_questions = len(questions)

        for i in range(total_questions):
            new_question = QuizQuestion(
                quiz_id=quiz_id,
                question_text=questions[i],
                option1=option1_list[i],
                option2=option2_list[i],
                option3=option3_list[i],
                option4=option4_list[i],
                correct_option=int(correct_options[i])
            )

            db.session.add(new_question)

        db.session.commit()
        flash("Questions added successfully!", "success")
        return redirect(url_for('quiz_bp.view_quiz', quiz_id=quiz_id))

    return render_template("quiz/add_question.html")


# ---------------------------------------------------
# EDIT QUIZ
# ---------------------------------------------------
@quiz_bp.route("/<int:quiz_id>/edit", methods=["GET", "POST"])
@login_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if current_user.id != quiz.course.instructor_id:
        flash("Unauthorized", "danger")
        return redirect(url_for("course_bp.view_course", course_id=quiz.course.id))

    if request.method == "POST":
        quiz.title = request.form.get("title")
        db.session.commit()

        flash("Quiz updated successfully!", "success")
        return redirect(url_for("quiz_bp.view_course_quizzes", course_id=quiz.course.id))

    return render_template("quiz/edit_quiz.html", quiz=quiz)


# ---------------------------------------------------
# DELETE QUIZ
# ---------------------------------------------------
@quiz_bp.route("/<int:quiz_id>/delete", methods=["POST"])
@login_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if current_user.id != quiz.course.instructor_id:
        flash("Unauthorized", "danger")
        return redirect(url_for("course_bp.view_course", course_id=quiz.course.id))

    db.session.delete(quiz)
    db.session.commit()

    flash("Quiz deleted.", "success")
    return redirect(url_for("quiz_bp.view_course_quizzes", course_id=quiz.course.id))


# ---------------------------------------------------
# EDIT QUESTION
# ---------------------------------------------------
@quiz_bp.route("/question/<int:question_id>/edit", methods=["GET", "POST"])
@login_required
def edit_question(question_id):
    question = QuizQuestion.query.get_or_404(question_id)
    quiz = question.quiz

    if current_user.id != quiz.course.instructor_id:
        flash("Unauthorized", "danger")
        return redirect(url_for("quiz_bp.view_course_quizzes", course_id=quiz.course.id))

    if request.method == "POST":
        question.question_text = request.form.get("question_text")
        question.option1 = request.form.get("option1")
        question.option2 = request.form.get("option2")
        question.option3 = request.form.get("option3")
        question.option4 = request.form.get("option4")
        question.correct_option = int(request.form.get("correct_option"))

        db.session.commit()

        flash("Question updated!", "success")
        return redirect(url_for("quiz_bp.view_course_quizzes", course_id=quiz.course.id))

    return render_template("quiz/edit_question.html", question=question)


# ---------------------------------------------------
# DELETE QUESTION
# ---------------------------------------------------
@quiz_bp.route("/question/<int:question_id>/delete", methods=["POST"])
@login_required
def delete_question(question_id):
    question = QuizQuestion.query.get_or_404(question_id)
    quiz = question.quiz

    if current_user.id != quiz.course.instructor_id:
        flash("Unauthorized", "danger")
        return redirect(url_for("quiz_bp.view_course_quizzes", course_id=quiz.course.id))

    db.session.delete(question)
    db.session.commit()

    flash("Question deleted!", "success")
    return redirect(url_for("quiz_bp.view_course_quizzes", course_id=quiz.course.id))


# ---------------------------------------------------
# LIST QUIZZES OF A COURSE (Instructor + Student)
# ---------------------------------------------------
@quiz_bp.route("/course/<int:course_id>/quizzes")
@login_required
def view_course_quizzes(course_id):
    course = Course.query.get_or_404(course_id)
    quizzes = course.quizzes
    return render_template("quiz/course_quizzes.html", course=course, quizzes=quizzes)


# ---------------------------------------------------
# VIEW QUIZ (Student)
# ---------------------------------------------------
@quiz_bp.route("/<int:quiz_id>/view")
@login_required
def view_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions
    return render_template("quiz/view_quiz.html", quiz=quiz, questions=questions)


@quiz_bp.route('/quiz/<int:quiz_id>/attempt', methods=['GET'])
@login_required
def attempt_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    # ✅ relationship already returns a list
    questions = quiz.questions

    if not questions:
        flash("No questions are available for this quiz.", "warning")
        return redirect(url_for(
            'course_bp.view_course',
            course_id=quiz.course_id
        ))

    latest_attempt = QuizAttempt.query.filter_by(
        student_id=current_user.id,
        quiz_id=quiz_id
    ).order_by(QuizAttempt.attempted_on.desc()).first()

    # ❌ Block only if PASSED
    if latest_attempt and latest_attempt.status == "PASS":
        flash("You have already passed this quiz.", "info")
        return redirect(url_for(
            'quiz_bp.view_quiz_result',
            quiz_id=quiz_id
        ))

    # ✅ Allow attempt if FAILED or first time
    return render_template(
        'quiz/attempt_quiz.html',
        quiz=quiz,
        questions=questions   # ✅ THIS WAS MISSING
    )




# ---------------------------------------------------
# SUBMIT QUIZ (Your Original Logic Restored)
# ---------------------------------------------------
@quiz_bp.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):

    quiz = Quiz.query.get_or_404(quiz_id)

    # ✅ CHECK LAST ATTEMPT
    last_attempt = QuizAttempt.query.filter_by(
        student_id=current_user.id,
        quiz_id=quiz.id
    ).order_by(QuizAttempt.attempted_on.desc()).first()

    if last_attempt and last_attempt.status == "PASS":
        flash("You have already passed this quiz.", "info")
        return redirect(
            url_for('course_bp.view_course', course_id=quiz.course_id)
        )

    # -----------------------
    # your score calculation
    # -----------------------

    score = 0
    for question in quiz.questions:
        selected = request.form.get(f"q{question.id}")
        if selected and selected == str(question.correct_option):
            score += 1

    total_marks = len(quiz.questions)

    if total_marks == 0:
        percentage = 0
    else:
        percentage = round((score / total_marks) * 100, 2)

    PASSING_PERCENTAGE = current_app.config.get("PASSING_PERCENTAGE", 40)
    status = "PASS" if percentage >= PASSING_PERCENTAGE else "FAIL"

    attempt = QuizAttempt(
        student_id=current_user.id,
        quiz_id=quiz.id,
        score=score,
        total_marks=total_marks,
        percentage=percentage,
        status=status
    )

    db.session.add(attempt)
    db.session.commit()


    return redirect(
        url_for('quiz_bp.view_quiz_result', quiz_id=quiz.id)
    )





# ---------------------------------------------------
# VIEW RESULT
# ---------------------------------------------------
@quiz_bp.route('/quiz/<int:quiz_id>/result')
@login_required
def view_quiz_result(quiz_id):

    # latest attempt of this quiz by student
    attempt = QuizAttempt.query.filter_by(
        student_id=current_user.id,
        quiz_id=quiz_id
    ).order_by(QuizAttempt.attempted_on.desc()).first_or_404()

    quiz = Quiz.query.get_or_404(attempt.quiz_id)

    course = quiz.course

    # ✅ FIX: define quizzes properly
    quizzes = course.quizzes

    # all quiz IDs in this course
    quiz_ids = {q.id for q in quizzes}

    # quizzes passed by student
    passed_quiz_ids = {
        a.quiz_id
        for a in QuizAttempt.query.filter_by(
            student_id=current_user.id,
            status="PASS"
        ).all()
    }

    # eligible only if all quizzes passed
    eligible_for_certificate = quiz_ids.issubset(passed_quiz_ids)

    return render_template(
        'quiz/view_quiz_result.html',
        attempt=attempt,
        quiz=quiz,
        course=course,
        eligible_for_certificate=eligible_for_certificate
    )



@quiz_bp.route('/course/<int:course_id>/certificate')
@login_required
def certificate(course_id):

    course = Course.query.get_or_404(course_id)

    # ----------------------------------
    # 1️⃣ GET ALL QUIZZES OF THIS COURSE
    # ----------------------------------
    quizzes = Quiz.query.filter_by(course_id=course.id).all()

    # create quiz_ids (❗ this was missing)
    quiz_ids = {quiz.id for quiz in quizzes}

    # ----------------------------------
    # 2️⃣ GET PASSED QUIZ ATTEMPTS
    # ----------------------------------
    passed_attempts = QuizAttempt.query.filter_by(
        student_id=current_user.id,
        status="PASS"
    ).all()

    passed_quiz_ids = {attempt.quiz_id for attempt in passed_attempts}

    # ----------------------------------
    # 3️⃣ CHECK ELIGIBILITY
    # ----------------------------------
    if not quiz_ids.issubset(passed_quiz_ids):
        flash(
            "You must pass all quizzes to download the certificate.",
            "warning"
        )
        return redirect(
            url_for('course_bp.view_course', course_id=course.id)
        )

    # ----------------------------------
    # 4️⃣ SHOW CERTIFICATE
    # ----------------------------------
    return render_template(
        'course/certificate.html',
        course=course,
        student=current_user
    )
