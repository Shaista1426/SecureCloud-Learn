import sqlite3

OLD_DB_PATH = r"C:\Users\sarwa\PycharmProjects\E Learning\old_db.sqlite"  # change if needed
conn = sqlite3.connect(OLD_DB_PATH)
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables in old DB:")
for t in tables:
    print(t[0])

conn.close()
