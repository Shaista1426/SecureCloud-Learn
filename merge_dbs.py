import os
import sqlite3

# Function to read courses from a given DB file
def list_courses(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, title FROM course")  # adjust table name if different
        courses = cursor.fetchall()
        conn.close()
        return courses
    except Exception as e:
        return f"Error reading {db_path}: {e}"

# Scan project folder for .db files
project_root = os.path.dirname(os.path.abspath(__file__))
for root, dirs, files in os.walk(project_root):
    for file in files:
        if file.endswith(".db"):
            db_path = os.path.join(root, file)
            courses = list_courses(db_path)
            print(f"\nDatabase: {db_path}")
            if courses:
                for course in courses:
                    print(f"  ID: {course[0]}, Title: {course[1]}")
            else:
                print("  No courses found or table missing.")
