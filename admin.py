# create_admin.py
import sqlite3, bcrypt

DB = "users.db"
email = "admin@local"
password = "StrongPass123!"   # change to whatever you want

conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password BLOB NOT NULL
)
""")
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
try:
    cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed))
    conn.commit()
    print(f"Created user: {email} / {password}")
except sqlite3.IntegrityError:
    print("User already exists — choose a different email or delete the old one.")
conn.close()
