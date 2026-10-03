import os
import io
import re
import smtplib
import hashlib
import secrets
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    flash,
    make_response
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from database import get_connection, create_database
from security import encrypt_file, decrypt_file


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is not set.")

app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

create_database()


# =========================================================
# TIME HELPERS
# =========================================================

def utc_now():
    return datetime.now(
        timezone.utc
    ).replace(
        tzinfo=None
    )


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


# =========================================================
# CLIENT IP
# =========================================================

def get_client_ip():

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:

        ip = forwarded_for.split(",")[0].strip()

        if ip:
            return ip

    real_ip = request.headers.get(
        "X-Real-IP"
    )

    if real_ip:

        ip = real_ip.strip()

        if ip:
            return ip

    return request.remote_addr or "UNKNOWN"


# =========================================================
# OTP EMAIL
# =========================================================

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

    if not all([
        smtp_host,
        smtp_login,
        smtp_password,
        sender_email
    ]):

        print(
            "BREVO SMTP SETTINGS ARE MISSING"
        )

        return False

    message = EmailMessage()

    message["Subject"] = (
        "Secure File Vault - OTP"
    )

    message["From"] = (
        f"{sender_name} <{sender_email}>"
    )

    message["To"] = email

    message.set_content(
        f"""
Secure File Vault

Your One-Time Password (OTP) is:

{otp}

This OTP is valid for 5 minutes.

You have a maximum of 3 verification attempts.

If you did not request this OTP, please ignore this email.

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
                message
            )

        print(
            f"OTP EMAIL SENT TO {email}"
        )

        return True

    except smtplib.SMTPAuthenticationError as e:

        print(
            f"OTP SMTP AUTH ERROR: {e}"
        )

    except smtplib.SMTPException as e:

        print(
            f"OTP SMTP ERROR: {e}"
        )

    except Exception as e:

        print(
            f"OTP EMAIL ERROR: "
            f"{type(e).__name__}: {e}"
        )

    return False


# =========================================================
# SECURITY ALERT EMAIL
# =========================================================

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

    if not all([
        smtp_host,
        smtp_login,
        smtp_password,
        sender_email,
        admin_email
    ]):

        print(
            "SECURITY ALERT SMTP SETTINGS ARE MISSING"
        )

        return False

    ist_time = to_ist(
        timestamp
    )

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

        return True

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

    return False


# =========================================================
# OTP GENERATION
# =========================================================

def generate_and_send_otp(
    username,
    email
):

    connection = get_connection()

    try:

        now = utc_now()

        recent_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM otp_codes
            WHERE username = %s
            AND created_at >= %s
            """,
            (
                username,
                now - timedelta(minutes=15)
            )
        ).fetchone()[0]

        if recent_count >= 3:

            return False, (
                "Too many OTP requests. "
                "Please try again later."
            )

        last_otp = connection.execute(
            """
            SELECT created_at
            FROM otp_codes
            WHERE username = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (username,)
        ).fetchone()

        if last_otp:

            if now - last_otp[0] < timedelta(
                seconds=60
            ):

                return False, (
                    "Please wait 60 seconds "
                    "before requesting another OTP."
                )

        connection.execute(
            """
            UPDATE otp_codes
            SET used = TRUE
            WHERE username = %s
            AND used = FALSE
            """,
            (username,)
        )

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_hash = hashlib.sha256(
            otp.encode()
        ).hexdigest()

        created_at = now

        expires_at = (
            now + timedelta(minutes=5)
        )

        connection.execute(
            """
            INSERT INTO otp_codes
            (
                username,
                otp_hash,
                created_at,
                expires_at,
                attempts,
                used
            )
            VALUES (%s, %s, %s, %s, 0, FALSE)
            """,
            (
                username,
                otp_hash,
                created_at,
                expires_at
            )
        )

        connection.commit()

    except Exception:

        connection.rollback()
        connection.close()
        raise

    connection.close()

    sent = send_otp_email(
        email,
        otp
    )

    if not sent:

        return False, (
            "Unable to send OTP email. "
            "Please try again."
        )

    return True, "OTP sent successfully."


# =========================================================
# PRO VAULT DATABASE SCHEMA
# =========================================================

def ensure_pro_vault_schema():

    connection = get_connection()

    try:

        connection.execute("""
            ALTER TABLE pro_vault_files
            ADD COLUMN IF NOT EXISTS
            encryption_version INTEGER
            NOT NULL DEFAULT 1
        """)

        connection.execute("""
            ALTER TABLE vault_keys
            ADD COLUMN IF NOT EXISTS
            password_hash TEXT
        """)

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


ensure_pro_vault_schema()


# =========================================================
# PRO VAULT RECOVERY KEY
# =========================================================

def get_recovery_key():

    key = os.environ.get(
        "VAULT_RECOVERY_KEY"
    )

    if not key:

        raise RuntimeError(
            "VAULT_RECOVERY_KEY is not set."
        )

    return key.encode()


def encrypt_recovery_data(data):

    cipher = Fernet(
        get_recovery_key()
    )

    return cipher.encrypt(data)


def decrypt_recovery_data(data):

    cipher = Fernet(
        get_recovery_key()
    )

    return cipher.decrypt(data)


# =========================================================
# VAULT KEY DATABASE HELPERS
# =========================================================

def get_vault_record(username):

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT
                recovery_data,
                password_hash
            FROM vault_keys
            WHERE username = %s
            """,
            (username,)
        ).fetchone()

    finally:

        connection.close()

    if not row:

        return None, None

    try:

        vault_key = decrypt_recovery_data(
            bytes(row[0])
        )

        return vault_key, row[1]

    except Exception as e:

        print(
            f"VAULT KEY DECRYPT ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return None, row[1]


def get_vault_key(username):

    vault_key, _ = get_vault_record(
        username
    )

    return vault_key


def create_vault_key(username):

    existing_key = get_vault_key(
        username
    )

    if existing_key:

        return existing_key

    vault_key = secrets.token_bytes(
        32
    )

    encrypted_key = encrypt_recovery_data(
        vault_key
    )

    now = utc_now()

    connection = get_connection()

    try:

        connection.execute(
            """
            INSERT INTO vault_keys
            (
                username,
                recovery_data,
                created_at,
                updated_at
            )
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (username)
            DO NOTHING
            """,
            (
                username,
                encrypted_key,
                now,
                now
            )
        )

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()

    existing_key = get_vault_key(
        username
    )

    return existing_key or vault_key


def get_vault_password_hash(username):

    _, password_hash = get_vault_record(
        username
    )

    return password_hash


def set_vault_password(
    username,
    password
):

    password_hash = generate_password_hash(
        password
    )

    create_vault_key(
        username
    )

    connection = get_connection()

    try:

        connection.execute(
            """
            UPDATE vault_keys
            SET
                password_hash = %s,
                updated_at = %s
            WHERE username = %s
            """,
            (
                password_hash,
                utc_now(),
                username
            )
        )

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


def verify_vault_password(
    username,
    password
):

    password_hash = get_vault_password_hash(
        username
    )

    if not password_hash:

        return False

    return check_password_hash(
        password_hash,
        password
    )


def vault_password_is_set(username):

    return bool(
        get_vault_password_hash(
            username
        )
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return redirect(
        url_for("login")
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        ip_address = get_client_ip()

        now = utc_now()

        print(
            f"LOGIN REQUEST | "
            f"Username: {username} | "
            f"IP: {ip_address}"
        )

        connection = get_connection()

        user = connection.execute(
            """
            SELECT
                id,
                username,
                password,
                role,
                email
            FROM users
            WHERE username = %s
            """,
            (username,)
        ).fetchone()

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
                now - timedelta(minutes=5)
            )
        ).fetchone()[0]

        print(
            f"FAILED LOGIN COUNT | "
            f"IP: {ip_address} | "
            f"Count: {failed_count}"
        )

        if failed_count >= 3:

            if user is not None and user[3] == "admin":

                print(
                    f"ADMIN ATTEMPT AFTER ALERT | "
                    f"IP: {ip_address}"
                )

            else:

                connection.close()

                return render_template(
                    "login.html",
                    error=(
                        "This IP address is temporarily "
                        "blocked for 5 minutes because "
                        "of multiple failed login attempts."
                    )
                )

        if user is None:

            connection.execute(
                """
                INSERT INTO login_attempts
                (
                    username,
                    ip_address,
                    timestamp,
                    status
                )
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

            connection.commit()

            if failed_count == 3:

                alert_message = (
                    "Three failed login attempts "
                    "detected from the same IP address."
                )

                existing_alert = connection.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE ip_address = %s
                    AND timestamp >= %s
                    LIMIT 1
                    """,
                    (
                        ip_address,
                        now - timedelta(minutes=5)
                    )
                ).fetchone()

                if existing_alert is None:

                    connection.execute(
                        """
                        INSERT INTO alerts
                        (
                            ip_address,
                            message,
                            timestamp
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            ip_address,
                            alert_message,
                            now
                        )
                    )

                    connection.commit()

                    connection.close()

                    send_security_alert_email(
                        ip_address,
                        alert_message,
                        now
                    )

                else:

                    connection.close()

                return render_template(
                    "login.html",
                    error=(
                        "Too many failed attempts. "
                        "This IP address is blocked "
                        "for 5 minutes."
                    )
                )

            connection.close()

            return render_template(
                "login.html",
                error="Invalid username or password"
            )

        db_username = user[1]
        password_hash = user[2]
        role = user[3]
        email = user[4]

        password_valid = check_password_hash(
            password_hash,
            password
        )

        if not password_valid:

            connection.execute(
                """
                INSERT INTO login_attempts
                (
                    username,
                    ip_address,
                    timestamp,
                    status
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    db_username,
                    ip_address,
                    now,
                    "FAILED"
                )
            )

            failed_count += 1

            connection.commit()

            if failed_count == 3:

                alert_message = (
                    "Three failed login attempts "
                    "detected from the same IP address."
                )

                existing_alert = connection.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE ip_address = %s
                    AND timestamp >= %s
                    LIMIT 1
                    """,
                    (
                        ip_address,
                        now - timedelta(minutes=5)
                    )
                ).fetchone()

                if existing_alert is None:

                    connection.execute(
                        """
                        INSERT INTO alerts
                        (
                            ip_address,
                            message,
                            timestamp
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            ip_address,
                            alert_message,
                            now
                        )
                    )

                    connection.commit()

                    connection.close()

                    send_security_alert_email(
                        ip_address,
                        alert_message,
                        now
                    )

                else:

                    connection.close()

                if role == "admin":

                    return render_template(
                        "login.html",
                        error=(
                            "Multiple failed login "
                            "attempts detected. "
                            "A security alert has been "
                            "sent to the administrator."
                        )
                    )

                return render_template(
                    "login.html",
                    error=(
                        "Too many failed attempts. "
                        "This IP address is blocked "
                        "for 5 minutes."
                    )
                )

            connection.close()

            return render_template(
                "login.html",
                error="Invalid username or password"
            )

        if not email:

            connection.close()

            return render_template(
                "login.html",
                error=(
                    "No email address is registered "
                    "for this account. "
                    "Please contact the administrator."
                )
            )

        connection.execute(
            """
            INSERT INTO login_attempts
            (
                username,
                ip_address,
                timestamp,
                status
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                db_username,
                ip_address,
                now,
                "OTP_PENDING"
            )
        )

        connection.commit()
        connection.close()

        sent, message = generate_and_send_otp(
            db_username,
            email
        )

        if not sent:

            return render_template(
                "login.html",
                error=message
            )

        session["pending_username"] = (
            db_username
        )

        session["pending_ip"] = (
            ip_address
        )

        return redirect(
            url_for("verify_otp")
        )

    return render_template(
        "login.html"
    )


# =========================================================
# VERIFY LOGIN OTP
# =========================================================

@app.route(
    "/verify-otp",
    methods=["GET", "POST"]
)
def verify_otp():

    username = session.get(
        "pending_username"
    )

    if not username:

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        if not re.fullmatch(
            r"\d{6}",
            entered_otp
        ):

            return render_template(
                "otp.html",
                error="Enter a valid 6-digit OTP."
            )

        connection = get_connection()

        try:

            otp_row = connection.execute(
                """
                SELECT
                    id,
                    otp_hash,
                    created_at,
                    expires_at,
                    attempts,
                    used
                FROM otp_codes
                WHERE username = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (username,)
            ).fetchone()

            if otp_row is None:

                return render_template(
                    "otp.html",
                    error=(
                        "No OTP found. "
                        "Please request a new OTP."
                    )
                )

            otp_id = otp_row[0]
            otp_hash = otp_row[1]
            expires_at = otp_row[3]
            attempts = otp_row[4]
            used = otp_row[5]

            if used:

                return render_template(
                    "otp.html",
                    error=(
                        "This OTP has already been used. "
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

                return render_template(
                    "otp.html",
                    error=(
                        "OTP expired. "
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

                return render_template(
                    "otp.html",
                    error=(
                        "Maximum OTP attempts exceeded. "
                        "Please request a new OTP."
                    )
                )

            entered_hash = hashlib.sha256(
                entered_otp.encode()
            ).hexdigest()

            if not secrets.compare_digest(
                entered_hash,
                otp_hash
            ):

                connection.execute(
                    """
                    UPDATE otp_codes
                    SET attempts = attempts + 1
                    WHERE id = %s
                    """,
                    (otp_id,)
                )

                connection.commit()

                return render_template(
                    "otp.html",
                    error="Invalid OTP."
                )

            user = connection.execute(
                """
                SELECT
                    username,
                    role
                FROM users
                WHERE username = %s
                """,
                (username,)
            ).fetchone()

            if user is None:

                connection.rollback()

                return render_template(
                    "otp.html",
                    error="User account was not found."
                )

            connection.execute(
                """
                UPDATE otp_codes
                SET used = TRUE
                WHERE id = %s
                """,
                (otp_id,)
            )

            ip_address = session.get(
                "pending_ip",
                request.remote_addr
            )

            connection.execute(
                """
                UPDATE login_attempts
                SET status = 'SUCCESS'
                WHERE id = (
                    SELECT id
                    FROM login_attempts
                    WHERE username = %s
                    AND ip_address = %s
                    AND status = 'OTP_PENDING'
                    ORDER BY timestamp DESC
                    LIMIT 1
                )
                """,
                (
                    username,
                    ip_address
                )
            )

            connection.commit()

        except Exception as e:

            connection.rollback()

            print(
                f"OTP VERIFICATION ERROR: "
                f"{type(e).__name__}: {e}"
            )

            return render_template(
                "otp.html",
                error=(
                    "An internal error occurred. "
                    "Please try again."
                )
            )

        finally:

            connection.close()

        session.clear()

        session["username"] = user[0]
        session["role"] = user[1]

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "otp.html"
    )


# =========================================================
# RESEND LOGIN OTP
# =========================================================

@app.route(
    "/resend-otp",
    methods=["POST"]
)
def resend_otp():

    username = session.get(
        "pending_username"
    )

    if not username:

        return redirect(
            url_for("login")
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

        return render_template(
            "otp.html",
            error=(
                "No email address is registered "
                "for this account."
            )
        )

    sent, message = generate_and_send_otp(
        username,
        user[0]
    )

    if not sent:

        return render_template(
            "otp.html",
            error=message
        )

    return render_template(
        "otp.html",
        message=message
    )


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required():

    return "username" in session


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )


# =========================================================
# PRO VAULT
# =========================================================

@app.route("/pro-vault")
def pro_vault():

    if not login_required():

        return redirect(
            url_for("login")
        )

    username = session.get(
        "username"
    )

    connection = get_connection()

    files = connection.execute(
        """
        SELECT
            id,
            original_name,
            file_size,
            uploaded_at,
            encryption_version
        FROM pro_vault_files
        WHERE username = %s
        ORDER BY uploaded_at DESC
        """,
        (username,)
    ).fetchall()

    connection.close()

    vault_key = create_vault_key(
        username
    )

    password_set = vault_password_is_set(
        username
    )

    return render_template(
        "pro_vault.html",
        files=files,
        vault_initialized=bool(vault_key),
        vault_password_set=password_set,
        vault_unlocked=session.get(
            "vault_unlocked",
            False
        )
    )


# =========================================================
# UNLOCK PRO VAULT
# =========================================================

@app.route("/pro-vault-unlock", methods=["POST"])
def pro_vault_unlock():

    if not login_required():
        return {
            "message": "Authentication required."
        }, 401

    username = session.get("username")
    password = request.form.get("vault_password", "")

    if not password:
        return {
            "message": "Vault password is required."
        }, 400

    try:
        # Make sure a vault key exists.
        vault_key = create_vault_key(username)

        if not vault_key:
            return {
                "message": "Unable to initialize Pro Vault."
            }, 500

        password_hash = get_vault_password_hash(username)

        # First-time vault setup.
        if not password_hash:

            if len(password) < 8:
                return {
                    "message": "Vault password must contain at least 8 characters."
                }, 400

            set_vault_password(
                username,
                password
            )

            # Read the newly stored password hash again.
            if not verify_vault_password(
                username,
                password
            ):
                return {
                    "message": "Unable to create vault password."
                }, 500

            session["vault_unlocked"] = True

            return {
                "message": "Vault password created.",
                "vault_key": vault_key.hex()
            }, 200

        # Verify the current/new vault password.
        if not verify_vault_password(
            username,
            password
        ):
            return {
                "message": "Incorrect vault password."
            }, 401

        session["vault_unlocked"] = True

        # Get the same existing vault key.
        vault_key = get_vault_key(username)

        if not vault_key:
            return {
                "message": "Unable to retrieve Pro Vault key."
            }, 500

        return {
            "message": "Vault unlocked.",
            "vault_key": vault_key.hex()
        }, 200

    except Exception as e:

        print(
            f"PRO VAULT UNLOCK ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return {
            "message": "Unable to unlock Pro Vault."
        }, 500


# =========================================================
# GET PRO VAULT KEY
# =========================================================

@app.route(
    "/pro-vault-key",
    methods=["GET"]
)
def pro_vault_key():

    if not login_required():

        return {
            "message": "Authentication required."
        }, 401

    if not session.get(
        "vault_unlocked"
    ):

        return {
            "message": "Unlock the Pro Vault first."
        }, 403

    username = session.get(
        "username"
    )

    try:

        vault_key = create_vault_key(
            username
        )

        if not vault_key:

            return {
                "message": "Unable to create vault key."
            }, 500

        return {
            "vault_key": vault_key.hex()
        }, 200

    except Exception as e:

        print(
            f"PRO VAULT KEY ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return {
            "message": "Unable to access vault key."
        }, 500


# =========================================================
# PRO VAULT ENCRYPTED UPLOAD
# =========================================================

@app.route(
    "/pro-vault-upload",
    methods=["POST"]
)
def pro_vault_upload():

    if not login_required():

        return {
            "message": "Authentication required."
        }, 401

    encrypted_file = request.files.get(
        "encrypted_file"
    )

    original_name = request.form.get(
        "original_name",
        ""
    ).strip()

    original_size = request.form.get(
        "original_size",
        "0"
    )

    encryption_version = request.form.get(
        "encryption_version",
        "1"
    )

    if not encrypted_file:

        return {
            "message": "Encrypted file is missing."
        }, 400

    if not original_name:

        return {
            "message": "Original filename is missing."
        }, 400

    try:

        original_size = int(
            original_size
        )

        encryption_version = int(
            encryption_version
        )

    except ValueError:

        return {
            "message": "Invalid file information."
        }, 400

    if original_size <= 0:

        return {
            "message": "Invalid file."
        }, 400

    if original_size > 5 * 1024 * 1024:

        return {
            "message": "File size must be 5 MB or less."
        }, 400

    if encryption_version not in (1, 2):

        return {
            "message": "Unsupported encryption version."
        }, 400

    if encryption_version == 2:

        if not session.get(
            "vault_unlocked"
        ):

            return {
                "message": "Unlock the Pro Vault first."
            }, 403

        if not get_vault_key(
            session.get("username")
        ):

            return {
                "message": "Vault key is unavailable."
            }, 500

    encrypted_data = encrypted_file.read()

    if not encrypted_data:

        return {
            "message": "Encrypted file is empty."
        }, 400

    if len(encrypted_data) > (
        5 * 1024 * 1024 + 4096
    ):

        return {
            "message": "Encrypted file is too large."
        }, 400

    stored_name = (
        secrets.token_hex(16)
        + ".vault"
    )

    connection = get_connection()

    try:

        connection.execute(
            """
            INSERT INTO pro_vault_files
            (
                username,
                stored_name,
                original_name,
                file_data,
                file_size,
                uploaded_at,
                encryption_version
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                session.get("username"),
                stored_name,
                original_name,
                encrypted_data,
                original_size,
                utc_now(),
                encryption_version
            )
        )

        connection.commit()

    except Exception as e:

        connection.rollback()

        print(
            f"PRO VAULT UPLOAD ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return {
            "message": "Unable to store encrypted file."
        }, 500

    finally:

        connection.close()

    print(
        f"PRO VAULT ENCRYPTED FILE STORED | "
        f"Username: {session.get('username')} | "
        f"File: {stored_name} | "
        f"Encryption Version: {encryption_version}"
    )

    return {
        "message": "Encrypted file uploaded successfully."
    }, 200


# =========================================================
# MIGRATE OLD PRO VAULT FILE
# =========================================================

@app.route(
    "/pro-vault-migrate/<int:file_id>",
    methods=["POST"]
)
def pro_vault_migrate(file_id):

    if not login_required():

        return {
            "message": "Authentication required."
        }, 401

    if not session.get(
        "vault_unlocked"
    ):

        return {
            "message": "Unlock the Pro Vault first."
        }, 403

    encrypted_file = request.files.get(
        "encrypted_file"
    )

    if not encrypted_file:

        return {
            "message": "Migrated encrypted file is missing."
        }, 400

    encrypted_data = encrypted_file.read()

    if not encrypted_data:

        return {
            "message": "Migrated encrypted file is empty."
        }, 400

    if len(encrypted_data) > (
        5 * 1024 * 1024 + 4096
    ):

        return {
            "message": "Migrated encrypted file is too large."
        }, 400

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT
                original_name,
                encryption_version
            FROM pro_vault_files
            WHERE id = %s
            AND username = %s
            """,
            (
                file_id,
                session.get("username")
            )
        ).fetchone()

        if not row:

            return {
                "message": "File not found."
            }, 404

        if row[1] == 2:

            return {
                "message": "File is already migrated."
            }, 400

        new_stored_name = (
            secrets.token_hex(16)
            + ".vault"
        )

        connection.execute(
            """
            UPDATE pro_vault_files
            SET
                file_data = %s,
                encryption_version = 2,
                stored_name = %s
            WHERE id = %s
            AND username = %s
            """,
            (
                encrypted_data,
                new_stored_name,
                file_id,
                session.get("username")
            )
        )

        connection.commit()

    except Exception as e:

        connection.rollback()

        print(
            f"PRO VAULT MIGRATION ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return {
            "message": "Unable to migrate file."
        }, 500

    finally:

        connection.close()

    return {
        "message": "File migrated successfully.",
        "filename": row[0]
    }, 200


# =========================================================
# FORGOT VAULT PASSWORD
# =========================================================

@app.route(
    "/pro-vault-forgot",
    methods=["GET", "POST"]
)
def pro_vault_forgot():

    if not login_required():

        return redirect(
            url_for("login")
        )

    username = session.get(
        "username"
    )

    if request.method == "POST":

        entered_email = request.form.get(
            "email",
            ""
        ).strip().lower()

        if not entered_email:

            return render_template(
                "pro_vault_forgot.html",
                error="Enter your registered email address."
            )

        connection = get_connection()

        try:

            user = connection.execute(
                """
                SELECT email
                FROM users
                WHERE username = %s
                """,
                (username,)
            ).fetchone()

        finally:

            connection.close()

        if not user or not user[0]:

            return render_template(
                "pro_vault_forgot.html",
                error=(
                    "No email address is registered "
                    "for this account."
                )
            )

        registered_email = (
            user[0].strip().lower()
        )

        if entered_email != registered_email:

            return render_template(
                "pro_vault_forgot.html",
                error=(
                    "The email address does not match "
                    "the registered account email."
                )
            )

        sent, message = generate_and_send_otp(
            username,
            registered_email
        )

        if not sent:

            return render_template(
                "pro_vault_forgot.html",
                error=message
            )

        session["vault_reset_pending"] = True

        return redirect(
            url_for(
                "pro_vault_forgot_otp"
            )
        )

    return render_template(
        "pro_vault_forgot.html"
    )


# =========================================================
# VERIFY VAULT RESET OTP
# =========================================================

@app.route(
    "/pro-vault-forgot-otp",
    methods=["GET", "POST"]
)
def pro_vault_forgot_otp():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not session.get(
        "vault_reset_pending"
    ):

        return redirect(
            url_for("pro_vault")
        )

    username = session.get(
        "username"
    )

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        if not re.fullmatch(
            r"\d{6}",
            entered_otp
        ):

            return render_template(
                "pro_vault_forgot_otp.html",
                error="Enter a valid 6-digit OTP."
            )

        connection = get_connection()

        try:

            otp_row = connection.execute(
                """
                SELECT
                    id,
                    otp_hash,
                    expires_at,
                    attempts,
                    used
                FROM otp_codes
                WHERE username = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (username,)
            ).fetchone()

            if otp_row is None:

                return render_template(
                    "pro_vault_forgot_otp.html",
                    error=(
                        "No OTP found. "
                        "Please request a new OTP."
                    )
                )

            otp_id = otp_row[0]
            otp_hash = otp_row[1]
            expires_at = otp_row[2]
            attempts = otp_row[3]
            used = otp_row[4]

            if used:

                return render_template(
                    "pro_vault_forgot_otp.html",
                    error=(
                        "This OTP has already been used. "
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

                return render_template(
                    "pro_vault_forgot_otp.html",
                    error=(
                        "OTP expired. "
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

                return render_template(
                    "pro_vault_forgot_otp.html",
                    error=(
                        "Maximum OTP attempts exceeded. "
                        "Please request a new OTP."
                    )
                )

            entered_hash = hashlib.sha256(
                entered_otp.encode()
            ).hexdigest()

            if not secrets.compare_digest(
                entered_hash,
                otp_hash
            ):

                connection.execute(
                    """
                    UPDATE otp_codes
                    SET attempts = attempts + 1
                    WHERE id = %s
                    """,
                    (otp_id,)
                )

                connection.commit()

                return render_template(
                    "pro_vault_forgot_otp.html",
                    error="Invalid OTP."
                )

            connection.execute(
                """
                UPDATE otp_codes
                SET used = TRUE
                WHERE id = %s
                """,
                (otp_id,)
            )

            connection.commit()

        except Exception as e:

            connection.rollback()

            print(
                f"VAULT RESET OTP ERROR: "
                f"{type(e).__name__}: {e}"
            )

            return render_template(
                "pro_vault_forgot_otp.html",
                error=(
                    "An internal error occurred. "
                    "Please try again."
                )
            )

        finally:

            connection.close()

        session["vault_reset_verified"] = True

        session.pop(
            "vault_reset_pending",
            None
        )

        return redirect(
            url_for("pro_vault_reset")
        )

    return render_template(
        "pro_vault_forgot_otp.html"
    )


# =========================================================
# RESET VAULT PASSWORD
# =========================================================

@app.route(
    "/pro-vault-reset",
    methods=["GET", "POST"]
)
def pro_vault_reset():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not session.get(
        "vault_reset_verified"
    ):

        return redirect(
            url_for("pro_vault")
        )

    username = session.get(
        "username"
    )

    if request.method == "POST":

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(new_password) < 8:

            return render_template(
                "pro_vault_reset.html",
                error=(
                    "Password must contain "
                    "at least 8 characters."
                )
            )

        if new_password != confirm_password:

            return render_template(
                "pro_vault_reset.html",
                error="Passwords do not match."
            )

        try:

            # IMPORTANT:
            # This changes only the password hash.
            # recovery_data and the vault key remain unchanged.
            set_vault_password(
                username,
                new_password
            )

            session["vault_unlocked"] = True

            session.pop(
                "vault_reset_verified",
                None
            )

            return redirect(
                url_for("pro_vault")
            )

        except Exception as e:

            print(
                f"VAULT PASSWORD RESET ERROR: "
                f"{type(e).__name__}: {e}"
            )

            return render_template(
                "pro_vault_reset.html",
                error=(
                    "Unable to reset the vault password."
                )
            )

    return render_template(
        "pro_vault_reset.html"
    )


# =========================================================
# PRO VAULT ENCRYPTED DOWNLOAD
# =========================================================

@app.route(
    "/pro-vault-download/<int:file_id>"
)
def pro_vault_download(file_id):

    if not login_required():

        return {
            "message": "Authentication required."
        }, 401

    connection = get_connection()

    file_data = connection.execute(
        """
        SELECT
            original_name,
            file_data,
            encryption_version
        FROM pro_vault_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session.get("username")
        )
    ).fetchone()

    connection.close()

    if not file_data:

        return {
            "message": "File not found."
        }, 404

    original_name = file_data[0]

    encrypted_data = bytes(
        file_data[1]
    )

    encryption_version = (
        file_data[2] or 1
    )

    response = make_response(
        encrypted_data
    )

    response.headers[
        "Content-Type"
    ] = "application/octet-stream"

    response.headers[
        "Content-Disposition"
    ] = (
        'attachment; filename="'
        + original_name
        + '.encrypted"'
    )

    response.headers[
        "X-Encryption-Version"
    ] = str(
        encryption_version
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


# =========================================================
# DELETE PRO VAULT FILE
# =========================================================

@app.route(
    "/pro-vault-delete/<int:file_id>",
    methods=["POST"]
)
def pro_vault_delete(file_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM pro_vault_files
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

    flash(
        "Pro Vault file deleted successfully."
    )

    return redirect(
        url_for("pro_vault")
    )


# =========================================================
# ENCRYPTION FLOW
# =========================================================

@app.route(
    "/encryption-flow"
)
def encryption_flow():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "encryption_flow.html"
    )


# =========================================================
# PROTECTED FILE
# =========================================================

@app.route(
    "/protected-file"
)
def protected_file():

    if not login_required():

        return redirect(
            url_for("login")
        )

    os.makedirs(
        "protected_files",
        exist_ok=True
    )

    if not os.path.exists(
        "protected_files/secret.enc"
    ):

        return render_template(
            "protected_file.html",
            error="Protected file not found."
        )

    temp_file = (
        "protected_files/temp_secret.txt"
    )

    try:

        decrypt_file(
            "protected_files/secret.enc",
            temp_file
        )

        with open(
            temp_file,
            "r",
            encoding="utf-8"
        ) as file:

            content = file.read()

        connection = get_connection()

        try:

            connection.execute(
                """
                INSERT INTO file_access_logs
                (
                    username,
                    ip_address,
                    filename,
                    timestamp
                )
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

        finally:

            connection.close()

        return render_template(
            "protected_file.html",
            content=content
        )

    except Exception as e:

        return render_template(
            "protected_file.html",
            error=str(e)
        )

    finally:

        if os.path.exists(
            temp_file
        ):

            os.remove(
                temp_file
            )


# =========================================================
# UPLOAD PAGE
# =========================================================

@app.route(
    "/upload"
)
def upload():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "upload.html"
    )


# =========================================================
# UPLOAD FILE
# =========================================================

@app.route(
    "/upload-file",
    methods=["POST"]
)
def upload_file():

    if not login_required():

        return redirect(
            url_for("login")
        )

    file = request.files.get(
        "file"
    )

    if not file or not file.filename:

        flash(
            "Please select a file."
        )

        return redirect(
            url_for("upload")
        )

    filename = os.path.basename(
        file.filename
    )

    data = file.read()

    if len(data) > 5 * 1024 * 1024:

        flash(
            "File size must be 5 MB or less."
        )

        return redirect(
            url_for("upload")
        )

    os.makedirs(
        "protected_files",
        exist_ok=True
    )

    temp_input = (
        "protected_files/temp_upload_input"
    )

    temp_output = (
        "protected_files/temp_upload_encrypted"
    )

    try:

        with open(
            temp_input,
            "wb"
        ) as file_object:

            file_object.write(data)

        encrypt_file(
            temp_input,
            temp_output
        )

        with open(
            temp_output,
            "rb"
        ) as file_object:

            encrypted_data = file_object.read()

        if os.path.exists(
            temp_input
        ):

            os.remove(
                temp_input
            )

        if os.path.exists(
            temp_output
        ):

            os.remove(
                temp_output
            )

        connection = get_connection()

        try:

            connection.execute(
                """
                INSERT INTO stored_files
                (
                    username,
                    filename,
                    file_data,
                    file_size,
                    uploaded_at
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    session.get("username"),
                    filename,
                    encrypted_data,
                    len(data),
                    utc_now()
                )
            )

            connection.commit()

        finally:

            connection.close()

        flash(
            "File uploaded and encrypted successfully."
        )

        return redirect(
            url_for("my_files")
        )

    except Exception as e:

        if os.path.exists(
            temp_input
        ):

            os.remove(
                temp_input
            )

        if os.path.exists(
            temp_output
        ):

            os.remove(
                temp_output
            )

        flash(
            f"Upload failed: {e}"
        )

        return redirect(
            url_for("upload")
        )


# =========================================================
# MY FILES
# =========================================================

@app.route(
    "/my-files"
)
def my_files():

    if not login_required():

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    files = connection.execute(
        """
        SELECT
            id,
            filename,
            file_size,
            uploaded_at
        FROM stored_files
        WHERE username = %s
        ORDER BY uploaded_at DESC
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


# =========================================================
# DOWNLOAD USER FILE
# =========================================================

@app.route(
    "/download-file/<int:file_id>"
)
def download_file(file_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            filename,
            file_data
        FROM stored_files
        WHERE id = %s
        AND username = %s
        """,
        (
            file_id,
            session.get("username")
        )
    ).fetchone()

    if row is None:

        connection.close()

        return "File not found.", 404

    filename = row[0]
    encrypted_data = row[1]

    connection.execute(
        """
        INSERT INTO file_access_logs
        (
            username,
            ip_address,
            filename,
            timestamp
        )
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

    os.makedirs(
        "protected_files",
        exist_ok=True
    )

    temp_encrypted = (
        "protected_files/temp_download.enc"
    )

    temp_decrypted = (
        "protected_files/temp_download"
    )

    try:

        with open(
            temp_encrypted,
            "wb"
        ) as file_object:

            file_object.write(
                encrypted_data
            )

        decrypt_file(
            temp_encrypted,
            temp_decrypted
        )

        with open(
            temp_decrypted,
            "rb"
        ) as file_object:

            data = file_object.read()

        if os.path.exists(
            temp_encrypted
        ):

            os.remove(
                temp_encrypted
            )

        if os.path.exists(
            temp_decrypted
        ):

            os.remove(
                temp_decrypted
            )

        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:

        if os.path.exists(
            temp_encrypted
        ):

            os.remove(
                temp_encrypted
            )

        if os.path.exists(
            temp_decrypted
        ):

            os.remove(
                temp_decrypted
            )

        return (
            f"Download failed: {e}",
            500
        )


# =========================================================
# DELETE USER FILE
# =========================================================

@app.route(
    "/delete-file/<int:file_id>",
    methods=["POST"]
)
def delete_file(file_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

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

    flash(
        "File deleted successfully."
    )

    return redirect(
        url_for("my_files")
    )


# =========================================================
# FILE ACCESS LOGS
# =========================================================

@app.route(
    "/file-logs"
)
def file_logs():

    if not login_required():

        return redirect(
            url_for("login")
        )

    connection = get_connection()

    logs = connection.execute(
        """
        SELECT
            username,
            ip_address,
            filename,
            timestamp
        FROM file_access_logs
        WHERE username = %s
        ORDER BY timestamp DESC
        """,
        (
            session.get("username"),
        )
    ).fetchall()

    connection.close()

    return render_template(
        "file_logs.html",
        logs=logs
    )


# =========================================================
# USERS
# =========================================================

@app.route(
    "/users",
    methods=["GET", "POST"]
)
def users():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        email = request.form.get(
            "email",
            ""
        ).strip()

        if not username or not password or not email:

            connection.close()

            return render_template(
                "users.html",
                error=(
                    "Username, password and "
                    "email are required."
                )
            )

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = %s
            """,
            (username,)
        ).fetchone()

        if existing:

            connection.close()

            return render_template(
                "users.html",
                error="Username already exists."
            )

        password_hash = generate_password_hash(
            password
        )

        try:

            connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    password,
                    role,
                    email
                )
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

        except Exception as e:

            connection.rollback()
            connection.close()

            return render_template(
                "users.html",
                error=f"Unable to create user: {e}"
            )

    users_list = connection.execute(
        """
        SELECT
            id,
            username,
            email,
            role
        FROM users
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    return render_template(
        "users.html",
        users=users_list
    )


# =========================================================
# DELETE USER
# =========================================================

@app.route(
    "/delete-user/<int:user_id>"
)
def delete_user(user_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    user = connection.execute(
        """
        SELECT
            username,
            role
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    ).fetchone()

    if user:

        if user[1] != "admin":

            connection.execute(
                """
                DELETE FROM users
                WHERE id = %s
                """,
                (user_id,)
            )

            connection.commit()

    connection.close()

    return redirect(
        url_for("users")
    )


# =========================================================
# ADMIN FILES
# =========================================================

@app.route(
    "/admin-files"
)
def admin_files():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    files = connection.execute(
        """
        SELECT
            id,
            username,
            filename,
            file_size,
            uploaded_at
        FROM stored_files
        ORDER BY uploaded_at DESC
        """
    ).fetchall()

    connection.close()

    return render_template(
        "admin_files.html",
        files=files
    )


# =========================================================
# ADMIN DOWNLOAD
# =========================================================

@app.route(
    "/admin-download-file/<int:file_id>"
)
def admin_download_file(file_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            username,
            filename,
            file_data
        FROM stored_files
        WHERE id = %s
        """,
        (file_id,)
    ).fetchone()

    if row is None:

        connection.close()

        return "File not found.", 404

    filename = row[1]
    encrypted_data = row[2]

    connection.execute(
        """
        INSERT INTO file_access_logs
        (
            username,
            ip_address,
            filename,
            timestamp
        )
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

    os.makedirs(
        "protected_files",
        exist_ok=True
    )

    temp_encrypted = (
        "protected_files/admin_temp.enc"
    )

    temp_decrypted = (
        "protected_files/admin_temp"
    )

    try:

        with open(
            temp_encrypted,
            "wb"
        ) as file_object:

            file_object.write(
                encrypted_data
            )

        decrypt_file(
            temp_encrypted,
            temp_decrypted
        )

        with open(
            temp_decrypted,
            "rb"
        ) as file_object:

            data = file_object.read()

        if os.path.exists(
            temp_encrypted
        ):

            os.remove(
                temp_encrypted
            )

        if os.path.exists(
            temp_decrypted
        ):

            os.remove(
                temp_decrypted
            )

        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:

        if os.path.exists(
            temp_encrypted
        ):

            os.remove(
                temp_encrypted
            )

        if os.path.exists(
            temp_decrypted
        ):

            os.remove(
                temp_decrypted
            )

        return (
            f"Download failed: {e}",
            500
        )


# =========================================================
# ADMIN DELETE FILE
# =========================================================

@app.route(
    "/admin-delete-file/<int:file_id>"
)
def admin_delete_file(file_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

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

    return redirect(
        url_for("admin_files")
    )


# =========================================================
# LOGIN LOGS
# =========================================================

@app.route(
    "/logs"
)
def logs():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    logs = connection.execute(
        """
        SELECT
            id,
            username,
            ip_address,
            timestamp,
            status
        FROM login_attempts
        ORDER BY timestamp DESC
        LIMIT 200
        """
    ).fetchall()

    connection.close()

    return render_template(
        "logs.html",
        logs=logs
    )


# =========================================================
# DELETE LOGIN LOG
# =========================================================

@app.route(
    "/delete-log/<int:log_id>",
    methods=["POST"]
)
def delete_log(log_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM login_attempts
        WHERE id = %s
        """,
        (log_id,)
    )

    connection.commit()
    connection.close()

    flash(
        "Login log deleted successfully."
    )

    return redirect(
        url_for("logs")
    )


# =========================================================
# SECURITY ALERTS
# =========================================================

@app.route(
    "/alerts"
)
def alerts():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if session.get("role") != "admin":

        return "Access denied.", 403

    connection = get_connection()

    alerts_list = connection.execute(
        """
        SELECT
            ip_address,
            message,
            timestamp
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 100
        """
    ).fetchall()

    connection.close()

    return render_template(
        "alerts.html",
        alerts=alerts_list
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        )
    )
