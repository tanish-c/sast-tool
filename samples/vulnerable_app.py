
import os
import pickle
import hashlib
import subprocess

import requests

password = "SuperSecret123!"
api_key = "AKIAIOSFODNN7EXAMPLE"
db_password = "mysql_root_pass"
config = {"secret_key": "my-flask-secret-key-12345"}


def connect_to_db():
    db.connect(password="hardcoded_db_password")


aws_token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_user_bad(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_id}'")
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
    sql = "SELECT * FROM orders WHERE customer = '" + user_id + "'"


def run_command_bad(user_input):
    os.system("ls " + user_input)
    os.popen(user_input)
    subprocess.call(user_input, shell=True)
    subprocess.run(user_input, shell=True)
    eval(user_input)
    exec(user_input)


from pickle import loads as pickle_loads


DEBUG = True


def fetch_insecure():
    requests.get("https://example.com/api", verify=False)


def weak_hash(data):
    hashlib.md5(data.encode())
    hashlib.sha1(data.encode())
    hashlib.new("md5", data.encode())


def read_file_bad(filename):
    with open(filename) as f:
        return f.read()


def fetch_url_bad(url):
    requests.get(url)
    requests.post(url, data={"key": "value"})

