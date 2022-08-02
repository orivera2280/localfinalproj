import os
from flask import Flask, render_template, request, session, redirect
from flask_session import Session
from functools import wraps
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
import psycopg2

DATABASE_URL = "postgres://kdwwsivrbhavjf:d3e7832a1ba7ee6055e00c9300f913227bdae6f398316babbf53f19ad2590486@ec2-44-208-88-195.compute-1.amazonaws.com:5432/d86u2pacceck0q"

conn = psycopg2.connect(DATABASE_URL, sslmode='require')

cur = conn.cursor()


app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


def login_required(f):
    """
    Decorate routes to require login.
    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login.html")
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login.html", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", invalid=0)
    if request.method == "POST":
        if not request.form.get("uname"):
            return render_template("login.html", invalid=1)
        if not request.form.get("psw"):
            return render_template("login.html", invalid=2)
        username = request.form.get("uname")
        login = cur.execute("SELECT hash FROM login WHERE username = ?", username)
        if login == None or not check_password_hash(login[0]["hash"], request.form.get("psw")):
            return render_template("login.html", invalid=3)
        user_id = cur.execute("SELECT id FROM login WHERE username = ?", username)
        session["user_id"] = user_id[0]["id"]
        return redirect("/")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
        return render_template("index.html")


@app.route("/midtown.html", methods=["GET", "POST"])
@login_required
def midtown():
    return render_template("midtown.html")


@app.route("/buckhead.html", methods=["GET", "POST"])
@login_required
def buckhead():
    return render_template("buckhead.html", methods=["GET", "POST"])


@app.route("/thepark.html")
@login_required
def thepark():
    return render_template("thepark.html", methods=["GET", "POST"])


@app.route("/register.html", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", invalid=0)
    if request.method == "POST":
        username = request.form.get("username")
        pass_one = request.form.get("psw")
        pass_two = request.form.get("psw-repeat")
        usernames = cur.execute("SELECT username FROM login")
        if username == usernames[0]["username"]:
            return render_template("register.html", invalid=1)
        if pass_one != pass_two:
            return render_template("register.html", invalid=2)
        hashed_pass = generate_password_hash(pass_one)
        cur.execute("INSERT INTO login (username, hash) VALUES (?, ?)", username, hashed_pass)
        return render_template("login.html")