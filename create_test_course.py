from app import create_app, db
from app.models import User, Course, Quiz

# Initialize app
app = create_app()

with app.app_context():
    # 1️⃣ Create Instructor (if not exists)
    instructor = User.query.filter_by(username="instructor1").first()
    if not instructor:
        instructor = User(username="instructor1", role="instructor")
        db.session.add(instructor)
        db.session.commit()
        print("Instructor created")
    else:
        print("Instructor already exists")

    # 2️⃣ Create Course (if not exists)
    course = Course.query.filter_by(title="Data Science Basics").first()
    if not course:
        course = Course(
            title="Data Science Basics",
            description="Learn the basics of Data Science",
            instructor_id=instructor.id
        )
        db.session.add(course)
        db.session.commit()
        print("Course created")
    else:
        print("Course already exists")

    # 3️⃣ Create Quizzes (if not exists)
    quizzes = [
        "Quiz 1: Introduction",
        "Quiz 2: Statistics Basics"
    ]
    for q_title in quizzes:
        existing_quiz = Quiz.query.filter_by(title=q_title, course_id=course.id).first()
        if not existing_quiz:
            quiz = Quiz(title=q_title, course_id=course.id)
            db.session.add(quiz)
            print(f"Quiz '{q_title}' created")
    db.session.commit()
    print("All quizzes created successfully!")
