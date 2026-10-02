from datetime import datetime, timedelta
import os
import psycopg

from flask import Flask, render_template, request, redirect, session

from database import create_database, get_connection
from werkzeug.security import check_password_hash, generate_password_hash
from security import decrypt_file


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set.")


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)


create_database()


@app.route("/")
def home():

    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        ip_address = request.remote_addr

        connection = get_connection()

        user = connection.execute(
            """
            SELECT username, password, role
            FROM users
            WHERE username = %s
            """,
            (username,)
        ).fetchone()

        is_admin = user is not None and user[2] == "admin"

        five_minutes_ago = (
            datetime.now() - timedelta(minutes=5)
        )

        if not is_admin:

            failed_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM login_attempts
                WHERE ip_address = %s
                AND status = 'FAILED'
                AND timestamp >= %s
                """,
                (
                    ip_address,
                    five_minutes_ago
                )
            ).fetchone()[0]

            if failed_count >= 3:

                existing_alert = connection.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE ip_address = %s
                    AND timestamp >= %s
                    """,
                    (
                        ip_address,
                        five_minutes_ago
                    )
                ).fetchone()

                if existing_alert is None:

                    connection.execute(
                        """
                        INSERT INTO alerts
                        (ip_address, message, timestamp)
                        VALUES (%s, %s, %s)
                        """,
                        (
                            ip_address,
                            "Three failed login attempts detected. IP address temporarily blocked for 5 minutes.",
                            datetime.now()
                        )
                    )

                    connection.commit()

                connection.close()

                return render_template(
                    "login.html",
                    error="This IP address is temporarily blocked. Try again after 5 minutes."
                )

        if user and check_password_hash(user[1], password):

            connection.execute(
                """
                INSERT INTO login_attempts
                (username, ip_address, timestamp, status)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    username,
                    ip_address,
                    datetime.now(),
                    "SUCCESS"
                )
            )

            connection.commit()
            connection.close()

            session["username"] = user[0]
            session["role"] = user[2]

            return redirect("/dashboard")

        connection.execute(
            """
            INSERT INTO login_attempts
            (username, ip_address, timestamp, status)
            VALUES (%s, %s, %s, %s)
            """,
            (
                username,
                ip_address,
                datetime.now(),
                "FAILED"
            )
        )

        if not is_admin:

            failed_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM login_attempts
                WHERE ip_address = %s
                AND status = 'FAILED'
                AND timestamp >= %s
                """,
                (
                    ip_address,
                    five_minutes_ago
                )
            ).fetchone()[0]

            if failed_count == 3:

                connection.execute(
                    """
                    INSERT INTO alerts
                    (ip_address, message, timestamp)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        ip_address,
                        "Three failed login attempts detected. IP address temporarily blocked for 5 minutes.",
                        datetime.now()
                    )
                )

        connection.commit()
        connection.close()

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


@app.route("/protected-file")
def protected_file():

    if "username" not in session:
        return redirect("/login")

    encrypted_file = "protected_files/secret.enc"
    decrypted_file = "protected_files/temp_secret.txt"

    try:

        decrypt_file(
            encrypted_file,
            decrypted_file
        )

        with open(decrypted_file, "r") as file:
            content = file.read()

        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)

        connection = get_connection()

        connection.execute(
            """
            INSERT INTO file_access_logs
            (username, ip_address, filename, timestamp)
            VALUES (%s, %s, %s, %s)
            """,
            (
                session["username"],
                request.remote_addr,
                "secret.enc",
                datetime.now()
            )
        )

        connection.commit()
        connection.close()

        return render_template(
            "protected_file.html",
            content=content
        )

    except Exception as e:

        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)

        return f"Unable to access protected file: {e}", 500


@app.route("/file-logs")
def file_logs():

    if "username" not in session or session["role"] != "admin":
        return "Access denied", 403

    connection = get_connection()

    logs = connection.execute(
        """
        SELECT username, ip_address, filename, timestamp
        FROM file_access_logs
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "file_logs.html",
        logs=logs
    )


@app.route("/users", methods=["GET", "POST"])
def users():

    if "username" not in session or session["role"] != "admin":
        return "Access denied", 403

    connection = get_connection()

    message = None
    error = None

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "" or password == "":
            error = "Username and password are required."

        else:

            password_hash = generate_password_hash(password)

            try:

                connection.execute(
                    """
                    INSERT INTO users
                    (username, password, role)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        username,
                        password_hash,
                        "user"
                    )
                )

                connection.commit()

                message = "User created successfully."

            except psycopg.errors.UniqueViolation:

                connection.rollback()

                error = "Username already exists."

    user_list = connection.execute(
        """
        SELECT username, role
        FROM users
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    return render_template(
        "users.html",
        users=user_list,
        message=message,
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


@app.route("/logs")
def logs():

    if "username" not in session or session["role"] != "admin":
        return "Access denied", 403

    connection = get_connection()

    attempts = connection.execute(
        """
        SELECT username, ip_address, timestamp, status
        FROM login_attempts
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "logs.html",
        attempts=attempts
    )


@app.route("/alerts")
def alerts():

    if "username" not in session or session["role"] != "admin":
        return "Access denied", 403

    connection = get_connection()

    alerts = connection.execute(
        """
        SELECT ip_address, message, timestamp
        FROM alerts
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "alerts.html",
        alerts=alerts
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )