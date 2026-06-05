
import hashlib
import json
import os
import subprocess
from pathlib import Path


PASSWORD = os.environ.get("APP_PASSWORD", "")
API_KEY = os.environ.get("API_KEY", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")


def get_user_safe(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


def list_files_safe(directory):
    result = subprocess.run(
        ["ls", "-la", directory],
        capture_output=True,
        text=True,
    )
    return result.stdout


def save_data(data, filename):
    with open("data/output.json", "w") as f:
        json.dump(data, f)


def load_data(filename):
    with open("data/output.json") as f:
        return json.load(f)


def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


DEBUG = False


def fetch_secure():
    import requests
    return requests.get("https://api.example.com/data")


ALLOWED_DIR = Path("/app/uploads").resolve()


def read_file_safe(filename):
    safe_path = (ALLOWED_DIR / filename).resolve()
    if not str(safe_path).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal detected")
    return safe_path.read_text()

