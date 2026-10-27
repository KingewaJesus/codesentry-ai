import sqlite3
import subprocess

API_KEY = "demo_secret_key_123456789"

def get_user(cursor, user_id):
    # Demo-only intentionally vulnerable example
    query = "SELECT * FROM users WHERE id = " + user_id
    return cursor.execute(query).fetchone()

def run_report(user_input):
    return subprocess.run("echo " + user_input, shell=True, capture_output=True)

def evaluate_expression(expression):
    return eval(expression)
