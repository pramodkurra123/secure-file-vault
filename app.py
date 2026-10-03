from datetime import datetime, timedelta, timezone
import os
import psycopg
import secrets
import hashlib
import smtplib
from email.message import EmailMessage

from flask import Flask, render_template, request, redirect, session, send_file
from database import create_database, get_connection
from werkzeug.security import check_password_hash, generate_password_hash
from security import decrypt_file
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from zoneinfo import ZoneInfo
from io import BytesIO


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is not set."
    )


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_ist(value):

    if value is None:
        return ""

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        ZoneInfo("Asia/Kolkata")
    ).strftime(
        "%d-%m-%Y %I:%M:%S %p"
    )


app.jinja_env.filters["ist"] = to_ist


def get_client_ip():

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "Unknown"


def login_required():

    return "username" in session


def admin_required():

    return (
        "username" in session
        and session.get("role") == "admin"
    )


def send_otp_email(email, otp):

    smtp_host = os.environ.get(
        "BREVO_SMTP_HOST"
    )

    smtp_port = int(
        os.environ.get(
            "BREVO_SMTP_PORT",
            "2525"
        )
    )

    smtp_login = os.environ.get(
        "BREVO_SMTP_LOGIN"
    )

    smtp_password = os.environ.get(
        "BREVO_SMTP_PASSWORD"
    )

    sender_email = os.environ.get(
        "BREVO_SENDER_EMAIL"
    )

    sender_name = os.environ.get(
        "BREVO_SENDER_NAME",
        "Secure File Vault"
    )

    if not smtp_host:
        raise RuntimeError(
            "BREVO_SMTP_HOST environment variable is not set."
        )

    if not smtp_login:
        raise RuntimeError(
            "BREVO_SMTP_LOGIN environment variable is not set."
        )

    if not smtp_password:
        raise RuntimeError(
            "BREVO_SMTP_PASSWORD environment variable is not set."
        )

    if not sender_email:
        raise RuntimeError(
            "BREVO_SENDER_EMAIL environment variable is not set."
        )

    message = EmailMessage()

    message["Subject"] = (
        "Secure File Vault - Login OTP"
    )

    message["From"] = (
        f"{sender_name} <{sender_email}>"
    )

    message["To"] = email

    message.set_content(
        f"""
Secure File Vault

Your login verification code is:

{otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.

If you did not attempt to log in, you can safely ignore this email.
"""
    )

    try:

        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=15
        ) as server:

            server.starttls()

            server.login(
                smtp_login,
                smtp_password
            )

            server.send_message(
                message
            )

        print(
            f"BREVO SUCCESS: OTP email sent to {email}"
        )

    except smtplib.SMTPAuthenticationError as e:

        print(
            f"BREVO AUTH ERROR: {e}"
        )

        raise RuntimeError(
            "Brevo SMTP authentication failed."
        )

    except smtplib.SMTPException as e:

        print(
            f"BREVO SMTP ERROR: {e}"
        )

        raise RuntimeError(
            "Brevo SMTP email sending failed."
        )

    except Exception as e:

        print(
            f"BREVO UNKNOWN ERROR: "
            f"{type(e).__name__}: {e}"
        )

        raise


def send_security_alert_email(
    ip_address,
    message,
    timestamp
):

    smtp_host = os.environ.get(
        "BREVO_SMTP_HOST"
    )

    smtp_port = int(
        os.environ.get(
            "BREVO_SMTP_PORT",
            "2525"
        )
    )

    smtp_login = os.environ.get(
        "BREVO_SMTP_LOGIN"
    )

    smtp_password = os.environ.get(
        "BREVO_SMTP_PASSWORD"
    )

    sender_email = os.environ.get(
        "BREVO_SENDER_EMAIL"
    )

    sender_name = os.environ.get(
        "BREVO_SENDER_NAME",
        "Secure File Vault"
    )

    admin_email = os.environ.get(
        "ADMIN_EMAIL"
    )

    if not admin_email:
        raise RuntimeError(
            "ADMIN_EMAIL environment variable is not set."
        )

    if not smtp_host:
        raise RuntimeError(
            "BREVO_SMTP_HOST environment variable is not set."
        )

    if not smtp_login:
        raise RuntimeError(
            "BREVO_SMTP_LOGIN environment variable is not set."
        )

    if not smtp_password:
        raise RuntimeError(
            "BREVO_SMTP_PASSWORD environment variable is not set."
        )

    if not sender_email:
        raise RuntimeError(
            "BREVO_SENDER_EMAIL environment variable is not set."
        )

    ist_time = to_ist(timestamp)

    email = EmailMessage()

    email["Subject"] = (
        "Security Alert - Secure File Vault"
    )

    email["From"] = (
        f"{sender_name} <{sender_email}>"
    )

    email["To"] = admin_email

    email.set_content(
        f"""
Secure File Vault - Security Alert

A security event has been detected.

Event:
{message}

IP Address:
{ip_address}

Time:
{ist_time} IST

Action:
The IP address has been temporarily blocked
for 5 minutes according to the security policy.

Please review the Login Activity Logs if necessary.

Secure File Vault
"""
    )

    try:

        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=15
        ) as server:

            server.starttls()

            server.login(
                smtp_login,
                smtp_password
            )

            server.send_message(
                email
            )

        print(
            f"SECURITY ALERT EMAIL SENT TO "
            f"{admin_email}"
        )

    except smtplib.SMTPAuthenticationError as e:

        print(
            f"SECURITY ALERT SMTP AUTH ERROR: {e}"
        )

    except smtplib.SMTPException as e:

        print(
            f"SECURITY ALERT SMTP ERROR: {e}"
        )

    except Exception as e:

        print(
            f"SECURITY ALERT EMAIL ERROR: "
            f"{type(e).__name__}: {e}"
        )


def generate_and_send_otp(username, email):

    connection = get_connection()

    now = utc_now()

    fifteen_minutes_ago = (
        now - timedelta(minutes=15)
    )

    request_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM otp_codes
        WHERE username = %s
        AND created_at >= %s
        """,
        (
            username,
            fifteen_minutes_ago
        )
    ).fetchone()[0]

    if request_count >= 3:

        connection.close()

        return False, (
            "Maximum OTP requests reached. "
            "Please try again after 15 minutes."
        )

    latest = connection.execute(
        """
        SELECT created_at
        FROM otp_codes
        WHERE username = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (username,)
    ).fetchone()

    if latest:

        seconds_passed = (
            now - latest[0]
        ).total_seconds()

        if seconds_passed < 60:

            remaining = int(
                60 - seconds_passed
            )

            connection.close()

            return False, (
                f"Please wait {remaining} seconds "
                "before requesting another OTP."
            )

    otp = f"{secrets.randbelow(1000000):06d}"

    otp_hash = hashlib.sha256(
        otp.encode()
    ).hexdigest()

    connection.execute(
        """
        UPDATE otp_codes
        SET used = TRUE
        WHERE username = %s
        AND used = FALSE
        """,
        (username,)
    )

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

        return False, (
            "Unable to send OTP. Please try again."
        )

    return True, None


@app.route("/")
def home():

    if login_required():
        return redirect("/dashboard")

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

        if user and check_password_hash(
            user[1],
            password
        ):

            email = user[3]

            if not email:

                connection.close()

                return render_template(
                    "login.html",
                    error=(
                        "No email address is registered "
                        "for this account."
                    )
                )

            connection.close()

            success, error = generate_and_send_otp(
                username,
                email
            )

            if not success:

                return render_template(
                    "login.html",
                    error=error
                )

            session["otp_pending"] = True
            session["otp_username"] = username
            session["otp_role"] = user[2]

            return redirect("/verify-otp")

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

            connection.close()

            return render_template(
                "login.html",
                error=(
                    "This IP address is temporarily "
                    "blocked for invalid login attempts. "
                    "Try again after 5 minutes."
                )
            )

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

        if failed_count == 3:

            alert_message = (
                "Three failed login attempts detected. "
                "Further invalid login attempts from "
                "this IP are temporarily blocked for "
                "5 minutes."
            )

            connection.execute(
                """
                INSERT INTO alerts
                (ip_address, message, timestamp)
                VALUES (%s, %s, %s)
                """,
                (
                    ip_address,
                    alert_message,
                    now
                )
            )

            connection.commit()

            try:

                send_security_alert_email(
                    ip_address,
                    alert_message,
                    now
                )

            except Exception as e:

                print(
                    f"Security alert notification failed: {e}"
                )

        else:

            connection.commit()

        connection.close()

        if failed_count >= 3:

            return render_template(
                "login.html",
                error=(
                    "This IP address is temporarily "
                    "blocked for invalid login attempts. "
                    "Try again after 5 minutes."
                )
            )

                return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template(
        "login.html"
    )


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if not session.get("otp_pending"):

        return redirect("/login")

    username = session.get(
        "otp_username"
    )

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
                error=(
                    "OTP not found. "
                    "Please request a new OTP."
                )
            )

        otp_id = record[0]
        otp_hash = record[1]
        expires_at = record[2]
        attempts = record[3]
        used = record[4]

        if used:

            connection.close()

            return render_template(
                "otp.html",
                error=(
                    "This OTP is no longer valid. "
                    "Please request a new OTP."
                )
            )

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
                error=(
                    "OTP has expired. "
                    "Please request a new OTP."
                )
            )

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
                error=(
                    "Maximum OTP attempts exceeded. "
                    "Please request a new OTP."
                )
            )

        entered_hash = hashlib.sha256(
            otp.encode()
        ).hexdigest()

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

            role = session.get(
                "otp_role"
            )

            session.clear()

            session["username"] = username
            session["role"] = role

            return redirect("/dashboard")

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
                error=(
                    "Maximum OTP attempts exceeded. "
                    "Please request a new OTP."
                )
            )

        return render_template(
            "otp.html",
            error=(
                f"Invalid OTP. "
                f"{3 - attempts} attempts remaining."
            )
        )

    return render_template(
        "otp.html"
    )


@app.route("/resend-otp", methods=["POST"])
def resend_otp():

    if not session.get("otp_pending"):

        return redirect("/login")

    username = session.get(
        "otp_username"
    )

    connection = get_connection()

    user = connection.execute(
        """
        SELECT email
        FROM users
        WHERE username = %s
        """,
        (username,)
    ).fetchone()

    connection.close()

    if not user or not user[0]:

        session.clear()

        return render_template(
            "login.html",
            error=(
                "No email address is registered "
                "for this account."
            )
        )

    success, error = generate_and_send_otp(
        username,
        user[0]
    )

    if not success:

        return render_template(
            "otp.html",
            error=error
        )

    return render_template(
        "otp.html",
        error=(
            "A new OTP has been sent to "
            "your email address."
        )
    )


@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )


@app.route("/encryption-flow")
def encryption_flow():

    if not login_required():
        return redirect("/login")

    return render_template(
        "encryption_flow.html"
    )


@app.route("/protected-file")
def protected_file():

    if not login_required():
        return redirect("/login")

    file_path = os.path.join(
        "protected_files",
        "secret.enc"
    )

    if not os.path.exists(file_path):

        return render_template(
            "protected_file.html",
            content="Protected file not found."
        )

    temp_file = os.path.join(
        "protected_files",
        "temp_secret.txt"
    )

    try:

        decrypt_file(
            file_path,
            temp_file
        )

        with open(
            temp_file,
            "r",
            encoding="utf-8"
        ) as file:

            content = file.read()

    except Exception:

        content = (
            "Unable to decrypt protected file."
        )

    finally:

        if os.path.exists(temp_file):

            os.remove(temp_file)

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO file_access_logs
        (username, ip_address, filename, timestamp)
        VALUES (%s, %s, %s, %s)
        """,
        (
            session.get("username"),
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


@app.route("/file-logs")
def file_logs():

    if not admin_required():
        return redirect("/dashboard")

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

    if not admin_required():
        return redirect("/dashboard")

    error = None

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]
        email = request.form["email"].strip()
        role = request.form.get(
            "role",
            "user"
        )

        if not username or not password or not email:

            error = (
                "Username, password and email "
                "are required."
            )

        elif role not in ["admin", "user"]:

            error = "Invalid role."

        else:

            password_hash = generate_password_hash(
                password
            )

            connection = get_connection()

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
                        role,
                        email
                    )
                )

                connection.commit()

            except psycopg.errors.UniqueViolation:

                connection.rollback()

                error = (
                    "Username or email already exists."
                )

            finally:

                connection.close()

    connection = get_connection()

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
        error=error,
        current_username=session.get(
            "username"
        )
    )


@app.route("/delete-user/<int:user_id>")
def delete_user(user_id):

    if not admin_required():
        return redirect("/dashboard")

    connection = get_connection()

    user = connection.execute(
        """
        SELECT username, role
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    ).fetchone()

    if user:

        username = user[0]
        role = user[1]

        current_username = session.get(
            "username"
        )

        if (
            username != current_username
            and role != "admin"
        ):

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

    if not login_required():
        return redirect("/login")

    if request.method == "POST":

        file = request.files.get(
            "file"
        )

        if not file or file.filename == "":

            return render_template(
                "upload.html",
                error="Please select a file."
            )

        filename = secure_filename(
            file.filename
        )

        if not filename:

            return render_template(
                "upload.html",
                error="Invalid filename."
            )

        file_data = file.read()

        if len(file_data) > 5 * 1024 * 1024:

            return render_template(
                "upload.html",
                error="Maximum file size is 5 MB."
            )

        fernet_key = os.environ.get(
            "FERNET_KEY"
        )

        if not fernet_key:

            return render_template(
                "upload.html",
                error="Encryption key is not configured."
            )

        cipher = Fernet(
            fernet_key.encode()
        )

        encrypted_data = cipher.encrypt(
            file_data
        )

        connection = get_connection()

        connection.execute(
            """
            INSERT INTO stored_files
            (username, filename, file_data,
             file_size, uploaded_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                session.get("username"),
                filename,
                encrypted_data,
                len(file_data),
                utc_now()
            )
        )

        connection.commit()
        connection.close()

        return redirect("/my-files")

    return render_template(
        "upload.html"
    )


@app.route("/my-files")
def my_files():

    if not login_required():
        return redirect("/login")

    connection = get_connection()

    files = connection.execute(
        """
        SELECT id, filename, file_size,
               uploaded_at
        FROM stored_files
        WHERE username = %s
        ORDER BY id DESC
        """,
        (
            session.get("username"),
        )
    ).fetchall()

    connection.close()

    return render_template(
        "my_files.html",
        files=files
    )


@app.route("/delete-file/<int:file_id>")
def delete_file(file_id):

    if not login_required():
        return redirect("/login")

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM stored_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session.get("username")
        )
    )

    connection.commit()
    connection.close()

    return redirect("/my-files")


@app.route("/download/<int:file_id>")
def download(file_id):

    if not login_required():
        return redirect("/login")

    connection = get_connection()

    file_record = connection.execute(
        """
        SELECT filename, file_data
        FROM stored_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session.get("username")
        )
    ).fetchone()

    if not file_record:

        connection.close()

        return (
            "File not found or access denied.",
            404
        )

    filename = file_record[0]
    encrypted_data = file_record[1]

    connection.execute(
        """
        INSERT INTO file_access_logs
        (username, ip_address, filename, timestamp)
        VALUES (%s, %s, %s, %s)
        """,
        (
            session.get("username"),
            get_client_ip(),
            filename,
            utc_now()
        )
    )

    connection.commit()
    connection.close()

    try:

        cipher = Fernet(
            os.environ["FERNET_KEY"].encode()
        )

        decrypted_data = cipher.decrypt(
            bytes(encrypted_data)
        )

    except Exception:

        return (
            "Unable to decrypt file.",
            500
        )

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )


@app.route("/admin-files")
def admin_files():

    if not admin_required():
        return redirect("/dashboard")

    connection = get_connection()

    files = connection.execute(
        """
        SELECT id, username, filename,
               file_size, uploaded_at
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

    if not admin_required():
        return redirect("/dashboard")

    connection = get_connection()

    file_record = connection.execute(
        """
        SELECT username, filename, file_data
        FROM stored_files
        WHERE id = %s
        """,
        (file_id,)
    ).fetchone()

    if not file_record:

        connection.close()

        return "File not found.", 404

    filename = file_record[1]
    encrypted_data = file_record[2]

    connection.execute(
        """
        INSERT INTO file_access_logs
        (username, ip_address, filename, timestamp)
        VALUES (%s, %s, %s, %s)
        """,
        (
            session.get("username"),
            get_client_ip(),
            filename,
            utc_now()
        )
    )

    connection.commit()
    connection.close()

    try:

        cipher = Fernet(
            os.environ["FERNET_KEY"].encode()
        )

        decrypted_data = cipher.decrypt(
            bytes(encrypted_data)
        )

    except Exception:

        return (
            "Unable to decrypt file.",
            500
        )

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )


@app.route("/admin-delete-file/<int:file_id>")
def admin_delete_file(file_id):

    if not admin_required():
        return redirect("/dashboard")

    connection = get_connection()

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


@app.route("/logs")
def logs():

    if not admin_required():
        return redirect("/dashboard")

    connection = get_connection()

    login_logs = connection.execute(
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
        logs=login_logs
    )


@app.route("/alerts")
def alerts():

    if not admin_required():
        return redirect("/dashboard")

    connection = get_connection()

    alert_list = connection.execute(
        """
        SELECT ip_address, message, timestamp
        FROM alerts
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "alerts.html",
        alerts=alert_list
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


create_database()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
