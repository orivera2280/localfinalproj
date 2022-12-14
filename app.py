import os
from flask import Flask, render_template, request, session, redirect
from flask_session import Session
from functools import wraps
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
import psycopg2
from flask_mail import Mail, Message

# Connecting my PostgresSQL table so users can register and login
DATABASE_URL = os.environ['DATABASE_URL']
conn = psycopg2.connect(DATABASE_URL, sslmode='require')
cur = conn.cursor()


app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies) - From CS50 Finance
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# CS50 Finance login required function 

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

# Ensure responses aren't cached - From CS50 Finance
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Login page
@app.route("/login.html", methods=["GET", "POST"])
def login():
    # Renders page get requests
    if request.method == "GET":
        return render_template("login.html", invalid=0)
    # Checks login information and logs user in
    if request.method == "POST":
        if not request.form.get("uname"):
            # Pass an argument that causes an alert if the user uses incorrect login information
            return render_template("login.html", invalid=1)
        if not request.form.get("psw"):
            return render_template("login.html", invalid=2)
        username = request.form.get("uname")
        global email
        email = request.form.get("uname")
        cur.execute("SELECT hash FROM login WHERE username = %s", (username,))
        login = cur.fetchone()
        if login is None or not check_password_hash(login[0], request.form.get("psw")):
            return render_template("login.html", invalid=3)
        cur.execute("SELECT id FROM login WHERE username = %s", (username,))
        user_id = cur.fetchone()
        session["user_id"] = user_id[0]
        return redirect("/")

# Redirects to main page
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    return render_template("thepark.html")

# Page made for when my app scales up -- I will make more pages that include service opportunities in specific areas 
@app.route("/midtown.html", methods=["GET", "POST"])
@login_required
def midtown():
    return render_template("midtown.html")

@app.route("/marietta.html", methods=["GET", "POST"])
@login_required
def marietta():
    return render_template("marietta.html")

# Page made for when my app scales up -- I will make more pages that include service opportunities in specific areas 
@app.route("/buckhead.html", methods=["GET", "POST"])
@login_required
def buckhead():
    return render_template("buckhead.html")

# Working page that displays available service opportunities
@app.route("/thepark.html", methods=["GET", "POST"])
@login_required
def thepark():
    return render_template("thepark.html")

# Register page 
@app.route("/register.html", methods=["GET", "POST"])
def register():
    # Renders page upon get request
    if request.method == "GET":
        return render_template("register.html", invalid=0)
    # Inserts user into database upon post request
    if request.method == "POST":
        username = request.form.get("user")
        pass_one = request.form.get("psw")
        pass_two = request.form.get("rptpsw")
        cur.execute("SELECT username FROM login WHERE username = %s", (username,))
        usernames = cur.fetchone()
        # Makes sure passwords match and user doesn't already have an account
        if usernames is not None:
            invalid = 1
            return render_template("register.html", invalid=invalid)
        if pass_one != pass_two:
            invalid = 2
            return render_template("register.html", invalid=invalid)
        hashed_pass = generate_password_hash(pass_one)
        cur.execute("INSERT INTO login (username, hash) VALUES (%s, %s)", (username, hashed_pass,))
        conn.commit()
        return render_template("login.html")