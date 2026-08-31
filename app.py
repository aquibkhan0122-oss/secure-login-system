
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
import pyotp
import os
from dotenv import load_dotenv
import secrets
import time

load_dotenv()

app = Flask(__name__)


app.secret_key = os.getenv("SECRET_KEY")

DATABASE = "users.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


def valid_password(password):
    return (
        len(password) >= 8
        and re.search(r'[A-Z]', password)
        and re.search(r'[a-z]', password)
        and re.search(r'[0-9]', password)
    )


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.")
            return redirect(url_for("register"))

        if not valid_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("register"))

        if not valid_password(password):
            flash(
                "Password must be at least 8 characters "
                "with uppercase, lowercase and number."
            )
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()

        try:
            conn.execute(
                """
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
                """,
                (username, email, hashed_password)
            )

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            flash("Username or email already exists.")
            return redirect(url_for("register"))

        conn.close()

        flash("Registration successful! Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            # Generate a temporary OTP
            otp = str(secrets.randbelow(900000) + 100000)
            

            # Store OTP temporarily in session
            session["pending_user_id"] = user["id"]
            session["pending_username"] = user["username"]
            session["otp"] = otp
            session["otp_created_at"] = time.time()

            # Display OTP in terminal for demonstration
            print("\n" + "=" * 40)
            print("       TWO-FACTOR AUTHENTICATION")
            print("=" * 40)
            print(f"OTP for {user['username']}: {otp}")
            print("=" * 40 + "\n")

            return redirect(url_for("verify_otp"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        entered_otp = request.form.get("otp", "").strip()

        if entered_otp == session.get("otp"):

            otp_created_at = session.get("otp_created_at", 0)

            if time.time() - otp_created_at > 300:
                session.pop("otp", None)
                session.pop("otp_created_at", None)
                flash("OTP has expired. Please login again.")
                return redirect(url_for("login"))

            session["user_id"] = session.pop("pending_user_id")
            session["username"] = session.pop("pending_username")

            session.pop("otp", None)
            session.pop("otp_created_at", None)

            return redirect(url_for("dashboard"))

        flash("Invalid OTP. Please try again.")

    return render_template("verify_otp.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    response = make_response(render_template("dashboard.html"))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()

    app.run(debug=True)
