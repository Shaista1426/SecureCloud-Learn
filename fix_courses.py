# fix_courses.py
from app import create_app, db
from app.models import User, Course

app = create_app()

with app.app_context():
    # List all instructors
    instructors = User.query.filter_by(role='instructor').all()
    if not instructors:
        print("No instructors found in the database!")
        exit()

    # Assign all courses without a valid instructor_id to the first instructor
    default_instructor = instructors[0]  # you can change index if needed

    # Find courses with invalid instructor_id
    courses = Course.query.all()
    fixed_count = 0

    for course in courses:
        instructor = User.query.get(course.instructor_id)
        if not instructor:
            print(f"Fixing course '{course.title}' (id={course.id})")
            course.instructor_id = default_instructor.id
            fixed_count += 1

    db.session.commit()
    print(f"Fixed {fixed_count} courses. All courses should now be visible to the instructor.")
