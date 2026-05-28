import sqlite3
import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()


@app.route("/user")
def user():
    user_id = request.args.get("id")
    result = get_user(user_id)
    return jsonify({"user": result})


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text


if __name__ == "__main__":
    app.run(debug=True)
