import sqlite3
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/login")
def login(username: str):
    # Classical SQL Injection vulnerability
    # CodeQL tracks the `username` parameter as the input source,
    # propagating it into the SQLite string execution sink.
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
