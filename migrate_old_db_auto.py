import sqlite3
from app import create_app, db
from app.models import User, Course, Quiz

# --- Initialize Flask app ---
app = create_app()

# --- Path to your OLD database ---
OLD_DB_PATH = r"C:\Users\sarwa\PycharmProjects\E Learning\old_db.sqlite"  # change as needed

with app.app_context():
    # Connect to old SQLite database
    old_conn = sqlite3.connect(OLD_DB_PATH)
    old_cursor = old_conn.cursor()

    # Step 1: List all tables in old DB
    old_cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in old_cursor.fetchall()]
    print("Tables in old DB:", tables)

    # Step 2: Determine correct tables for courses and quizzes
    # Adjust if table names are different in your old DB
    courses_table = "courses" if "courses" in tables else "course"
    quizzes_table = "quizzes" if "quizzes" in tables else "quiz"

    # Step 3: Fetch all courses
    old_cursor.execute(f"SELECT id, title, description, instructor_id FROM {courses_table}")
    old_courses = old_cursor.fetchall()
    print(f"Found {len(old_courses)} courses in old DB.")

    for old_course in old_courses:
        old_course_id, title, description, old_instructor_id = old_course

        # Map old instructor to current DB instructor
        instructor = User.query.filter_by(id=old_instructor_id).first()
        if not instructor:
            print(f"Skipping course '{title}' because instructor {old_instructor_id} not found.")
            continue

        # Check if course already exists in current DB
        existing_course = Course.query.filter_by(title=title).first()
        if not existing_course:
            # Create course
            new_course = Course(title=title, description=description, instructor_id=instructor.id)
            db.session.add(new_course)
            db.session.commit()
            print(f"Added course: {title}")
        else:
            new_course = existing_course
            print(f"Course already exists: {title}")

        # Step 4: Fetch quizzes for this course
        old_cursor.execute(f"SELECT id, title FROM {quizzes_table} WHERE course_id = ?", (old_course_id,))
        old_quizzes = old_cursor.fetchall()

        for old_quiz in old_quizzes:
            old_quiz_id, quiz_title = old_quiz
            # Check if quiz exists
            existing_quiz = Quiz.query.filter_by(title=quiz_title, course_id=new_course.id).first()
            if not existing_quiz:
                quiz = Quiz(title=quiz_title, course_id=new_course.id)
                db.session.add(quiz)
                db.session.commit()
                print(f"Added quiz: {quiz_title} for course: {title}")
            else:
                print(f"Quiz already exists: {quiz_title} for course: {title}")

    old_conn.close()
    print("✅ Migration complete! All courses and quizzes are now in the current DB.")
