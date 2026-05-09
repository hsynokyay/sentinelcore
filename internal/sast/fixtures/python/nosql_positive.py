# internal/sast/fixtures/python/nosql_positive.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["app"]

@app.route("/login", methods=["POST"])
def login():
    user = db.users.find_one({"username": request.json["username"], "password": request.json["password"]})
    return jsonify(user is not None)
