from datetime import datetime, timedelta, timezone
import os
import psycopg
import secrets
import hashlib
import json
import urllib.request
import urllib.error

from flask import Flask, render_template, request, redirect, session
from database import create_database, get_connection
from werkzeug.security import check_password_hash, generate_password_hash
from security import decrypt_file
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from zoneinfo import ZoneInfo


def get_client_ip():

    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr


def utc_now():

    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_ist(value):

    if value is None:
        return ""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(
        ZoneInfo("Asia/Kolkata")
    ).strftime("%d-%m-%Y %I:%M:%S %p")


def send_otp_email(email, otp):

    api_key = os.environ.get("RESEND_API_KEY")

    if not api_key:
        raise RuntimeError(
            "RESEND_API_KEY environment variable is not set."
        )

    data = {
        "from": "onboarding@resend.dev",
        "to": [email],
        "subject": "Secure File Vault - Login OTP",
        "html": f"""
        <html>
        <body style="font-family: Arial, sans-serif;">

            <h2>Secure File Vault</h2>

            <p>Your login verification code is:</p>

            <h1 style="letter-spacing: 5px;">{otp}</h1>

            <p>
                This OTP is valid for
                <strong>5 minutes</strong>.
            </p>

            <p>
                Do not share this OTP with anyone.
            </p>

            <p>
                If you did not attempt to log in,
                you can safely ignore this email.
            </p>

        </body>
        </html>
        """
    }

    request_data = json.dumps(data).encode("utf-8")

    email_request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=request_data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            email_request,
            timeout=15
        ) as response:

            if response.status < 200 or response.status >= 300:

                raise RuntimeError(
                    "Unable to send OTP email."
                )

    except urllib.error.HTTPError as e:

        raise RuntimeError(
            f"Email service error: {e.code}"
        )

    except urllib.error.URLError:

        raise RuntimeError(
            "Unable to connect to email service."
        )


app = Flask(__name__)

app.jinja_env.filters["ist"] = to_ist

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:

    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is not set."
    )


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

        username = request.form["username"].strip()
        password = request.form["password"]

        ip_address = get_client_ip()

        connection = get_connection()

        user = connection.execute(
            """
            SELECT username, password, role, email
            FROM users
            WHERE username = %s
            """,
            (username,)
        ).fetchone()

        is_admin = (
            user is not None
            and user[2] == "admin"
        )

        now = utc_now()

        five_minutes_ago = (
            now - timedelta(minutes=5)
        )


        # Correct password.

        if user and check_password_hash(
            user[1],
            password
        ):

            email = user[3]

            if not email:

                connection.close()

                return render_template(
                    "login.html",
                    error="No email address is registered for this account."
                )


            # Generate secure 6-digit OTP.

            otp = f"{secrets.randbelow(1000000):06d}"

            otp_hash = hashlib.sha256(
                otp.encode()
            ).hexdigest()


            # Invalidate previous OTPs.

            connection.execute(
                """
                UPDATE otp_codes
                SET used = TRUE
                WHERE username = %s
                AND used = FALSE
                """,
                (username,)
            )


            # Store hashed OTP.

            connection.execute(
                """
                INSERT INTO otp_codes
                (username, otp_hash, created_at,
                 expires_at, attempts, used)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    username,
                    otp_hash,
                    now,
                    now + timedelta(minutes=5),
                    0,
                    False
                )
            )

            connection.commit()
            connection.close()


            # Send OTP.

            try:

                send_otp_email(
                    email,
                    otp
                )

            except Exception:

                connection = get_connection()

                connection.execute(
                    """
                    UPDATE otp_codes
                    SET used = TRUE
                    WHERE username = %s
                    AND used = FALSE
                    """,
                    (username,)
                )

                connection.commit()
                connection.close()

                return render_template(
                    "login.html",
                    error="Unable to send OTP. Please try again."
                )


            # Temporary OTP session.

            session["otp_pending"] = True
            session["otp_username"] = username
            session["otp_role"] = user[2]

            return redirect("/verify-otp")


        # Admin is never blocked.

        if is_admin:

            connection.execute(
                """
                INSERT INTO login_attempts
                (username, ip_address, timestamp, status)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    username,
                    ip_address,
                    now,
                    "FAILED"
                )
            )

            connection.commit()
            connection.close()

            return render_template(
                "login.html",
                error="Invalid username or password"
            )


        # Count failed attempts from this IP.

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


        # IP already blocked.

        if failed_count >= 3:

            connection.close()

            return render_template(
                "login.html",
                error="This IP address is temporarily blocked for invalid login attempts. Try again after 5 minutes."
            )


        # Record failed attempt.

        connection.execute(
            """
            INSERT INTO login_attempts
            (username, ip_address, timestamp, status)
            VALUES (%s, %s, %s, %s)
            """,
            (
                username,
                ip_address,
                now,
                "FAILED"
            )
        )

        failed_count += 1


        # Create alert on third attempt.

        if failed_count == 3:

            connection.execute(
                """
                INSERT INTO alerts
                (ip_address, message, timestamp)
                VALUES (%s, %s, %s)
                """,
                (
                    ip_address,
                    "Three failed login attempts detected. Further invalid login attempts from this IP are temporarily blocked for 5 minutes.",
                    now
                )
            )


        connection.commit()
        connection.close()


        if failed_count >= 3:

            return render_template(
                "login.html",
                error="This IP address is temporarily blocked for invalid login attempts. Try again after 5 minutes."
            )


        return render_template(
            "login.html",
            error="Invalid username or password"
        )


    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if not session.get("otp_pending"):

        return redirect("/login")


    username = session.get("otp_username")


    if request.method == "POST":

        otp = request.form["otp"].strip()


        if not otp.isdigit() or len(otp) != 6:

            return render_template(
                "otp.html",
                error="Enter a valid 6-digit OTP."
            )


        connection = get_connection()


        record = connection.execute(
            """
            SELECT id, otp_hash, expires_at,
                   attempts, used
            FROM otp_codes
            WHERE username = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (username,)
        ).fetchone()


        if record is None:

            connection.close()

            return render_template(
                "otp.html",
                error="OTP not found. Please request a new OTP."
            )


        otp_id = record[0]
        otp_hash = record[1]
        expires_at = record[2]
        attempts = record[3]
        used = record[4]


        # OTP already used.

        if used:

            connection.close()

            return render_template(
                "otp.html",
                error="This OTP is no longer valid. Please request a new OTP."
            )


        # OTP expired.

        if utc_now() > expires_at:

            connection.execute(
                """
                UPDATE otp_codes
                SET used = TRUE
                WHERE id = %s
                """,
                (otp_id,)
            )

            connection.commit()
            connection.close()

            return render_template(
                "otp.html",
                error="OTP has expired. Please request a new OTP."
            )


        # Maximum attempts.

        if attempts >= 3:

            connection.execute(
                """
                UPDATE otp_codes
                SET used = TRUE
                WHERE id = %s
                """,
                (otp_id,)
            )

            connection.commit()
            connection.close()

            return render_template(
                "otp.html",
                error="Maximum OTP attempts exceeded. Please request a new OTP."
            )


        entered_hash = hashlib.sha256(
            otp.encode()
        ).hexdigest()


        # Correct OTP.

        if secrets.compare_digest(
            entered_hash,
            otp_hash
        ):

            connection.execute(
                """
                UPDATE otp_codes
                SET used = TRUE
                WHERE id = %s
                """,
                (otp_id,)
            )


            connection.execute(
                """
                INSERT INTO login_attempts
                (username, ip_address, timestamp, status)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    username,
                    get_client_ip(),
                    utc_now(),
                    "SUCCESS"
                )
            )


            connection.commit()
            connection.close()


            role = session.get("otp_role")

            session.clear()

            session["username"] = username
            session["role"] = role


            return redirect("/dashboard")


        # Incorrect OTP.

        attempts += 1

        connection.execute(
            """
            UPDATE otp_codes
            SET attempts = %s
            WHERE id = %s
            """,
            (
                attempts,
                otp_id
            )
        )


        connection.commit()
        connection.close()


        if attempts >= 3:

            return render_template(
                "otp.html",
                error="Maximum OTP attempts exceeded. Please request a new OTP."
            )


        return render_template(
            "otp.html",
            error=f"Invalid OTP. {3 - attempts} attempts remaining."
        )


    return render_template("otp.html")


@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


@app.route("/encryption-flow")
def encryption_flow():

    if "username" not in session:
        return redirect("/login")

    return render_template(
        "encryption_flow.html"
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

        with open(
            decrypted_file,
            "r"
        ) as file:

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
                get_client_ip(),
                "secret.enc",
                utc_now()
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

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()

    logs = connection.execute(
        """
        SELECT username, ip_address,
               filename, timestamp
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

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()

    message = None
    error = None


    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]
        email = request.form["email"].strip()


        if (
            username == ""
            or password == ""
            or email == ""
        ):

            error = "Username, password and email are required."


        else:

            password_hash = generate_password_hash(
                password
            )

            try:

                connection.execute(
                    """
                    INSERT INTO users
                    (username, password, role, email)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        username,
                        password_hash,
                        "user",
                        email
                    )
                )

                connection.commit()

                message = "User created successfully."


            except psycopg.errors.UniqueViolation:

                connection.rollback()

                error = "Username or email already exists."


    user_list = connection.execute(
        """
        SELECT id, username, role, email
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


@app.route("/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()

    user = connection.execute(
        """
        SELECT username, role
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    ).fetchone()


    if user is None:

        connection.close()

        return "User not found.", 404


    username = user[0]
    role = user[1]


    if username == session["username"]:

        connection.close()

        return "You cannot delete the currently logged-in admin account.", 400


    if role == "admin":

        connection.close()

        return "Admin accounts cannot be deleted from this page.", 400


    connection.execute(
        """
        DELETE FROM stored_files
        WHERE username = %s
        """,
        (username,)
    )


    connection.execute(
        """
        DELETE FROM otp_codes
        WHERE username = %s
        """,
        (username,)
    )


    connection.execute(
        """
        DELETE FROM users
        WHERE id = %s
        """,
        (user_id,)
    )


    connection.commit()
    connection.close()


    return redirect("/users")


@app.route("/upload", methods=["GET", "POST"])
def upload():

    if "username" not in session:
        return redirect("/login")


    if request.method == "POST":

        file = request.files.get("file")


        if not file or file.filename == "":

            return render_template(
                "upload.html",
                error="Please select a file."
            )


        filename = secure_filename(
            file.filename
        )


        if filename == "":

            return render_template(
                "upload.html",
                error="Invalid filename."
            )


        data = file.read()


        if len(data) > 5 * 1024 * 1024:

            return render_template(
                "upload.html",
                error="File size must be 5 MB or less."
            )


        key = os.environ.get("FERNET_KEY")


        if not key:

            return "FERNET_KEY environment variable is not set.", 500


        cipher = Fernet(
            key.encode()
        )

        encrypted_data = cipher.encrypt(data)


        connection = get_connection()


        connection.execute(
            """
            INSERT INTO stored_files
            (username, filename, file_data,
             file_size, uploaded_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                session["username"],
                filename,
                encrypted_data,
                len(data),
                utc_now()
            )
        )


        connection.commit()
        connection.close()


        return redirect("/my-files")


    return render_template("upload.html")


@app.route("/my-files")
def my_files():

    if "username" not in session:
        return redirect("/login")


    connection = get_connection()


    files = connection.execute(
        """
        SELECT id, filename,
               file_size, uploaded_at
        FROM stored_files
        WHERE username = %s
        ORDER BY id DESC
        """,
        (session["username"],)
    ).fetchall()


    connection.close()


    return render_template(
        "my_files.html",
        files=files
    )


@app.route("/delete-file/<int:file_id>", methods=["POST"])
def delete_file(file_id):

    if "username" not in session:
        return redirect("/login")


    connection = get_connection()


    file = connection.execute(
        """
        SELECT filename
        FROM stored_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session["username"]
        )
    ).fetchone()


    if file is None:

        connection.close()

        return "File not found or access denied.", 404


    connection.execute(
        """
        DELETE FROM stored_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session["username"]
        )
    )


    connection.commit()
    connection.close()


    return redirect("/my-files")


@app.route("/download/<int:file_id>")
def download_file(file_id):

    if "username" not in session:
        return redirect("/login")


    connection = get_connection()


    file = connection.execute(
        """
        SELECT filename, file_data
        FROM stored_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session["username"]
        )
    ).fetchone()


    if file is None:

        connection.close()

        return "File not found or access denied.", 404


    filename = file[0]
    encrypted_data = file[1]


    try:

        key = os.environ.get("FERNET_KEY")


        if not key:

            raise RuntimeError(
                "FERNET_KEY environment variable is not set."
            )


        cipher = Fernet(
            key.encode()
        )

        decrypted_data = cipher.decrypt(
            encrypted_data
        )


        connection.execute(
            """
            INSERT INTO file_access_logs
            (username, ip_address,
             filename, timestamp)
            VALUES (%s, %s, %s, %s)
            """,
            (
                session["username"],
                get_client_ip(),
                filename,
                utc_now()
            )
        )


        connection.commit()
        connection.close()


        from flask import Response


        response = Response(
            decrypted_data,
            mimetype="application/octet-stream"
        )


        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )


        return response


    except Exception as e:

        connection.close()

        return f"Unable to download file: {e}", 500


@app.route("/admin-files")
def admin_files():

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()


    files = connection.execute(
        """
        SELECT id, username,
               filename, file_size,
               uploaded_at
        FROM stored_files
        ORDER BY id DESC
        """
    ).fetchall()


    connection.close()


    return render_template(
        "admin_files.html",
        files=files
    )


@app.route("/admin-download/<int:file_id>")
def admin_download(file_id):

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()


    file = connection.execute(
        """
        SELECT filename, file_data
        FROM stored_files
        WHERE id = %s
        """,
        (file_id,)
    ).fetchone()


    if file is None:

        connection.close()

        return "File not found.", 404


    filename = file[0]
    encrypted_data = file[1]


    try:

        key = os.environ.get("FERNET_KEY")


        if not key:

            raise RuntimeError(
                "FERNET_KEY environment variable is not set."
            )


        cipher = Fernet(
            key.encode()
        )

        decrypted_data = cipher.decrypt(
            encrypted_data
        )


        connection.execute(
            """
            INSERT INTO file_access_logs
            (username, ip_address,
             filename, timestamp)
            VALUES (%s, %s, %s, %s)
            """,
            (
                session["username"],
                get_client_ip(),
                filename,
                utc_now()
            )
        )


        connection.commit()
        connection.close()


        from flask import Response


        response = Response(
            decrypted_data,
            mimetype="application/octet-stream"
        )


        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )


        return response


    except Exception as e:

        connection.close()

        return f"Unable to download file: {e}", 500


@app.route("/admin-delete-file/<int:file_id>", methods=["POST"])
def admin_delete_file(file_id):

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()


    file = connection.execute(
        """
        SELECT filename
        FROM stored_files
        WHERE id = %s
        """,
        (file_id,)
    ).fetchone()


    if file is None:

        connection.close()

        return "File not found.", 404


    connection.execute(
        """
        DELETE FROM stored_files
        WHERE id = %s
        """,
        (file_id,)
    )


    connection.commit()
    connection.close()


    return redirect("/admin-files")


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


@app.route("/logs")
def logs():

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()


    attempts = connection.execute(
        """
        SELECT username, ip_address,
               timestamp, status
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

    if (
        "username" not in session
        or session["role"] != "admin"
    ):

        return "Access denied", 403


    connection = get_connection()


    alerts = connection.execute(
        """
        SELECT ip_address,
               message,
               timestamp
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
