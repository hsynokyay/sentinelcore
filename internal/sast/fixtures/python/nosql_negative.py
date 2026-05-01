# internal/sast/fixtures/python/nosql_negative.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["app"]

@app.route("/login", methods=["POST"])
def login():
    username = str(request.json.get("username", ""))
    password = str(request.json.get("password", ""))
    user = db.users.find_one({"username": username, "password": password})
    return jsonify(user is not None)
