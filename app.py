from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import re
import secrets
import string

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ============================================================
# GOLDEN TRUST
# ============================================================

app = Flask(__name__)

app.secret_key = "golden-trust-change-this-secret-key"

DATABASE = "goldentrust.db"

ALLOWED_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp"
}

SUPPORT_USERNAME = "golden_trust_support"


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            profile_image TEXT,
            user_id TEXT UNIQUE,
            referred_by TEXT,
            wallet TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def migrate_database():

    conn = get_db()

    columns = conn.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    names = [column["name"] for column in columns]

    if "profile_image" not in names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN profile_image TEXT
        """)

    if "user_id" not in names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN user_id TEXT
        """)

    if "referred_by" not in names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN referred_by TEXT
        """)

    if "wallet" not in names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN wallet TEXT
        """)

    conn.commit()
    conn.close()


# ============================================================
# USER ID
# ============================================================

def generate_user_id():

    characters = string.ascii_lowercase + string.digits

    conn = get_db()

    try:

        while True:

            new_id = "".join(
                secrets.choice(characters)
                for _ in range(8)
            )

            exists = conn.execute("""
                SELECT id
                FROM users
                WHERE user_id = ?
            """, (new_id,)).fetchone()

            if not exists:
                return new_id

    finally:
        conn.close()


def assign_missing_user_ids():

    conn = get_db()

    users = conn.execute("""
        SELECT id
        FROM users
        WHERE user_id IS NULL
           OR user_id = ''
    """).fetchall()

    for user in users:

        while True:

            characters = string.ascii_lowercase + string.digits

            new_id = "".join(
                secrets.choice(characters)
                for _ in range(8)
            )

            exists = conn.execute("""
                SELECT id
                FROM users
                WHERE user_id = ?
            """, (new_id,)).fetchone()

            if not exists:
                break

        conn.execute("""
            UPDATE users
            SET user_id = ?
            WHERE id = ?
        """, (
            new_id,
            user["id"]
        ))

    conn.commit()
    conn.close()


# ============================================================
# CURRENT USER
# ============================================================

def get_current_user():

    if "user_id" not in session:
        return None

    conn = get_db()

    user = conn.execute("""
        SELECT
            id,
            user_id,
            username,
            email,
            profile_image,
            referred_by,
            wallet
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    return user


@app.context_processor
def inject_user():

    return {
        "current_user": get_current_user()
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    user = get_current_user()

    return render_template(
        "home.html",
        user=user,
        username=user["username"] if user else None,
        email=user["email"] if user else None
    )


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    referral_id = request.args.get(
        "ref",
        ""
    ).strip().lower()

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        form_ref = request.form.get(
            "ref",
            ""
        ).strip().lower()

        if form_ref:
            referral_id = form_ref

        if not username or not email or not password:

            return render_template(
                "register.html",
                error="Please fill in all fields.",
                referral_id=referral_id
            )

        if len(password) < 6:

            return render_template(
                "register.html",
                error="Password must be at least 6 characters.",
                referral_id=referral_id
            )

        if not re.fullmatch(
            r"[A-Za-z0-9_]{3,30}",
            username
        ):

            return render_template(
                "register.html",
                error="Username must contain only letters, numbers or underscore.",
                referral_id=referral_id
            )

        referred_by = None

        if referral_id:

            conn = get_db()

            referrer = conn.execute("""
                SELECT user_id
                FROM users
                WHERE user_id = ?
            """, (
                referral_id,
            )).fetchone()

            conn.close()

            if referrer:
                referred_by = referrer["user_id"]

        password_hash = generate_password_hash(
            password
        )

        new_user_id = generate_user_id()

        conn = get_db()

        try:

            conn.execute("""
                INSERT INTO users (
                    username,
                    email,
                    password,
                    user_id,
                    referred_by
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                username,
                email,
                password_hash,
                new_user_id,
                referred_by
            ))

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return render_template(
                "register.html",
                error="Username or email already exists.",
                referral_id=referral_id
            )

        conn.close()

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html",
        referral_id=referral_id
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username_or_email = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username = ?
               OR email = ?
        """, (
            username_or_email,
            username_or_email.lower()
        )).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]

            return redirect(
                url_for("home")
            )

        return render_template(
            "login.html",
            error="Invalid username/email or password."
        )

    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    if user is None:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        user=user,
        username=user["username"],
        email=user["email"],
        profile_image=user["profile_image"],
        balance=0
    )


# ============================================================
# PROFILE
# ============================================================

@app.route("/profile", methods=["GET", "POST"])
def profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    next_page = request.args.get(
        "next",
        request.form.get(
            "next",
            "/"
        )
    )

    allowed_pages = {
        "/",
        "/dashboard",
        "/team",
        "/plans",
        "/earn",
        "/deposit",
        "/transactions",
        "/settings"
    }

    if next_page not in allowed_pages:
        next_page = "/"

    conn = get_db()

    user = conn.execute("""
        SELECT
            id,
            user_id,
            username,
            email,
            profile_image,
            referred_by,
            wallet
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    if user is None:

        conn.close()

        session.clear()

        return redirect(
            url_for("login")
        )

    message = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        if not username:

            message = "Username cannot be empty."

        elif not re.fullmatch(
            r"[A-Za-z0-9_]{3,30}",
            username
        ):

            message = (
                "Username must contain only "
                "letters, numbers or underscore."
            )

        else:

            existing = conn.execute("""
                SELECT id
                FROM users
                WHERE username = ?
                AND id != ?
            """, (
                username,
                session["user_id"]
            )).fetchone()

            if existing:

                message = "This username is already taken."

            else:

                profile_image = user["profile_image"]

                uploaded_file = request.files.get(
                    "profile_image"
                )

                if uploaded_file and uploaded_file.filename:

                    upload_folder = os.path.join(
                        app.root_path,
                        "static",
                        "uploads",
                        "profiles"
                    )

                    os.makedirs(
                        upload_folder,
                        exist_ok=True
                    )

                    original_filename = secure_filename(
                        uploaded_file.filename
                    )

                    extension = os.path.splitext(
                        original_filename
                    )[1].lower()

                    if extension not in ALLOWED_IMAGE_EXTENSIONS:

                        message = "Invalid image format."

                    else:

                        filename = (
                            "user_"
                            + str(session["user_id"])
                            + extension
                        )

                        filepath = os.path.join(
                            upload_folder,
                            filename
                        )

                        uploaded_file.save(
                            filepath
                        )

                        profile_image = (
                            "/static/uploads/profiles/"
                            + filename
                        )

                if message is None:

                    conn.execute("""
                        UPDATE users
                        SET
                            username = ?,
                            profile_image = ?
                        WHERE id = ?
                    """, (
                        username,
                        profile_image,
                        session["user_id"]
                    ))

                    conn.commit()

                    session["username"] = username

                    conn.close()

                    return redirect(next_page)

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        message=message,
        next_page=next_page
    )


# ============================================================
# SETTINGS
# ============================================================

@app.route("/settings")
def settings():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "settings.html",
        user=user,
        username=user["username"],
        email=user["email"],
        profile_image=user["profile_image"],
        support_username=SUPPORT_USERNAME
    )


# ============================================================
# CHANGE PASSWORD
# VISUAL ONLY FOR NOW
# ============================================================

@app.route("/settings/password")
def change_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "change_password.html",
        user=user
    )


# ============================================================
# CHANGE EMAIL
# VISUAL ONLY FOR NOW
# ============================================================

@app.route("/settings/email")
def change_email():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "change_email.html",
        user=user
    )


# ============================================================
# CHANGE WALLET
# VISUAL ONLY FOR NOW
# ============================================================

@app.route("/settings/wallet")
def change_wallet():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "change_wallet.html",
        user=user
    )


# ============================================================
# CUSTOMER CARE
# ============================================================

@app.route("/customer-care")
def customer_care():

    return redirect(
        "https://t.me/" + SUPPORT_USERNAME
    )


# ============================================================
# PLANS
# ============================================================

@app.route("/plans")
def plans():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "plans.html",
        user=user,
        username=user["username"],
        email=user["email"],
        profile_image=user["profile_image"]
    )


# ============================================================
# DEPOSIT
# ============================================================

@app.route("/deposit")
def deposit():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "deposit.html",
        user=user,
        profile_image=user["profile_image"]
    )


# ============================================================
# TRANSACTIONS
# ============================================================

@app.route("/transactions")
def transactions():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "transactions.html",
        user=user,
        profile_image=user["profile_image"]
    )


# ============================================================
# TEAM
# ============================================================

@app.route("/team")
def team():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "team.html",
        user=user,
        username=user["username"],
        email=user["email"],
        profile_image=user["profile_image"]
    )


# ============================================================
# EARN
# ============================================================

@app.route("/earn")
def earn():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    return render_template(
        "earn.html",
        user=user,
        username=user["username"],
        email=user["email"],
        profile_image=user["profile_image"]
    )


# ============================================================
# REFERRAL
# ============================================================

@app.route("/referral")
def referral():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    referral_link = url_for(
        "register",
        ref=user["user_id"],
        _external=True
    )

    return render_template(
        "earn.html",
        user=user,
        username=user["username"],
        email=user["email"],
        profile_image=user["profile_image"],
        referral_link=referral_link
    )


# ============================================================
# ERROR HANDLING
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h2 style="font-family:Arial;text-align:center;margin-top:50px;">
        Page Not Found
    </h2>
    """, 404


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    init_db()

    migrate_database()

    assign_missing_user_ids()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
